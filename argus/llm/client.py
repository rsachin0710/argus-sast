"""LLMClient: the single gateway every agent uses to call a model.

Responsibilities (in the order a call flows through them):

    1. Build a cache key from (prompt version, provider, model, system prompt,
       messages, schema, temperature, seed, vote index).
    2. Cache hit  -> return the stored, already-validated answer. This is what
       makes re-scans of unchanged code byte-identical.
    3. Budget     -> refuse once `max_llm_calls` is reached (cost control).
    4. Concurrency-> an asyncio semaphore caps parallel requests.
    5. Call       -> provider.complete(); 429/5xx/network errors are retried
                     with exponential backoff.
    6. Validate   -> the JSON must parse into the agent's Pydantic model. If not,
                     ONE repair round-trip tells the model what was wrong.
    7. Store      -> only valid answers are cached.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from .. import PROMPT_VERSION
from .base import LLMError, LLMProvider, inline_schema

T = TypeVar("T", bound=BaseModel)


class BudgetExceeded(RuntimeError):
    pass


class ResponseCache:
    """Content-addressed SQLite cache of validated LLM answers."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, created REAL)"
        )
        self._db.commit()

    def get(self, key: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM cache WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO cache (key, value, created) VALUES (?, ?, ?)",
                (key, json.dumps(value, sort_keys=True), time.time()),
            )
            self._db.commit()

    def clear(self) -> int:
        with self._lock:
            n = self._db.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            self._db.execute("DELETE FROM cache")
            self._db.commit()
        return n

    def close(self) -> None:
        with self._lock:
            self._db.close()


@dataclass
class LLMStats:
    calls: int = 0
    cache_hits: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    failures: int = 0
    repairs: int = 0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class LLMClient:
    def __init__(
        self,
        provider: LLMProvider,
        cache: ResponseCache | None = None,
        max_calls: int = 2000,
        max_concurrency: int = 4,
    ):
        self.provider = provider
        self.cache = cache
        self.max_calls = max_calls
        self.stats = LLMStats()
        self._sem = asyncio.Semaphore(max_concurrency)
        self._count_lock = asyncio.Lock()

    @property
    def model_label(self) -> str:
        return f"{self.provider.name.value}:{self.provider.settings.model}"

    def _cache_key(self, system: str, messages: list[dict], schema: dict, vote: int) -> str:
        s = self.provider.settings
        payload = {
            "pv": PROMPT_VERSION,
            "provider": self.provider.name.value,
            "model": s.model,
            "temperature": s.temperature,
            "seed": s.seed,
            "system": system,
            "messages": messages,
            "schema": schema,
            "vote": vote,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    async def structured(
        self,
        *,
        system: str,
        user: str,
        model_cls: type[T],
        vote: int = 0,
        history: list[dict] | None = None,
    ) -> T:
        """Ask for a JSON answer that validates as ``model_cls``.

        ``vote`` distinguishes self-consistency runs of the same prompt so each
        vote is cached separately (otherwise all votes would hit one entry).
        Raises LLMError when no valid answer could be obtained.
        """
        schema = inline_schema(model_cls.model_json_schema())
        messages = [*(history or []), {"role": "user", "content": user}]
        key = self._cache_key(system, messages, schema, vote)

        if self.cache is not None:
            hit = self.cache.get(key)
            if hit is not None:
                try:
                    self.stats.cache_hits += 1
                    return model_cls.model_validate(hit)
                except ValidationError:
                    pass  # schema changed since it was cached: fall through and re-ask

        result = await self._call(system, messages, schema)
        try:
            parsed = model_cls.model_validate(result.data or {})
        except ValidationError as exc:
            # One repair attempt: show the model its own output and the error.
            self.stats.repairs += 1
            repair = [
                *messages,
                {"role": "assistant", "content": result.text[:6000] or "{}"},
                {
                    "role": "user",
                    "content": "Your previous reply did not match the required JSON schema. "
                    f"Validation errors:\n{_short_errors(exc)}\n"
                    "Reply again with ONE corrected JSON object only.",
                },
            ]
            result = await self._call(system, repair, schema)
            try:
                parsed = model_cls.model_validate(result.data or {})
            except ValidationError as exc2:
                self.stats.failures += 1
                raise LLMError(f"model output failed validation twice: {_short_errors(exc2)}") from exc2

        if self.cache is not None:
            self.cache.put(key, parsed.model_dump(mode="json"))
        return parsed

    async def _call(self, system: str, messages: list[dict], schema: dict):
        async with self._count_lock:
            if self.stats.calls >= self.max_calls:
                raise BudgetExceeded(
                    f"LLM call budget of {self.max_calls} reached (raise scan.max_llm_calls)"
                )
            self.stats.calls += 1
        delay = 2.0
        async with self._sem:
            for attempt in range(4):
                try:
                    res = await self.provider.complete(system, messages, schema)
                    self.stats.input_tokens += res.input_tokens
                    self.stats.output_tokens += res.output_tokens
                    return res
                except LLMError as err:
                    if not err.retryable or attempt == 3:
                        self.stats.failures += 1
                        raise
                    await asyncio.sleep(delay)
                    delay *= 2
        raise LLMError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        await self.provider.aclose()


def _short_errors(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:8]
    )
