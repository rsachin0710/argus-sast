"""Provider-neutral LLM interface.

Every agent talks to an ``LLMProvider`` through ``LLMClient`` (see client.py).
A provider adapter only has to do one thing: send (system prompt, messages,
optional JSON schema) to its API and hand back text + parsed JSON + token
counts. Everything else — caching, retries, budgets, schema validation and
repair — lives in one place in ``LLMClient`` so behaviour is identical across
Anthropic, OpenAI, xAI Grok and Ollama.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import DEFAULT_BASE_URLS, LLMSettings, ProviderName


class LLMError(RuntimeError):
    """A provider call failed. ``retryable`` marks 429 / 5xx / network errors."""

    def __init__(self, message: str, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


@dataclass
class LLMResult:
    text: str
    data: dict | None = None  # parsed JSON object, when one was requested
    input_tokens: int = 0
    output_tokens: int = 0
    cached: bool = False
    raw: dict = field(default_factory=dict, repr=False)


class LLMProvider:
    """Base class for the four adapters."""

    name: ProviderName

    def __init__(self, settings: LLMSettings, api_key: str | None, http: httpx.AsyncClient | None = None):
        self.settings = settings
        self.api_key = api_key
        self.base_url = (settings.base_url or DEFAULT_BASE_URLS[self.name]).rstrip("/")
        self._http = http
        # Parameters a model rejected once (e.g. `temperature` on reasoning
        # models). We drop them for the rest of the run instead of failing.
        self._dropped_params: set[str] = set()

    # -- HTTP helpers ------------------------------------------------------ #
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.settings.timeout_seconds)
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _post(self, url: str, body: dict, headers: dict) -> dict:
        try:
            resp = await self.http.post(url, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise LLMError(f"{self.name.value}: request timed out", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"{self.name.value}: network error: {exc}", retryable=True) from exc
        if resp.status_code >= 400:
            detail = resp.text[:500]
            retryable = resp.status_code == 429 or resp.status_code >= 500
            raise LLMError(
                f"{self.name.value}: HTTP {resp.status_code}: {detail}", resp.status_code, retryable
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise LLMError(f"{self.name.value}: invalid JSON response") from exc

    def _maybe_drop_param(self, err: LLMError, body: dict, params: tuple[str, ...]) -> bool:
        """If a 400 error names a parameter we sent, drop it and allow a retry."""
        if err.status != 400:
            return False
        msg = str(err).lower()
        for p in params:
            if p in body and p.replace("_", " ") in msg.replace("_", " "):
                self._dropped_params.add(p)
                body.pop(p, None)
                return True
        return False

    # -- interface ----------------------------------------------------------- #
    async def complete(
        self, system: str, messages: list[dict], schema: dict | None = None
    ) -> LLMResult:  # pragma: no cover - implemented by adapters
        raise NotImplementedError

    async def list_models(self) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def supports_seed(self) -> bool:
        return False


# --------------------------------------------------------------------------- #
# JSON helpers shared by adapters and the client
# --------------------------------------------------------------------------- #
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def extract_json_object(text: str) -> dict | None:
    """Pull the first JSON object out of a model reply.

    Handles bare JSON, ```json fenced blocks and prose around the object by
    scanning for the first balanced {...} while respecting string literals.
    """
    if not text:
        return None
    stripped = _FENCE.sub("", text.strip())
    try:
        val = json.loads(stripped)
        return val if isinstance(val, dict) else None
    except ValueError:
        pass
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        val = json.loads(text[start : i + 1])
                        if isinstance(val, dict):
                            return val
                    except ValueError:
                        break
                    break
        start = text.find("{", start + 1)
    return None


def inline_schema(schema: dict) -> dict:
    """Resolve local $ref/$defs so every provider gets a flat JSON schema."""
    defs = schema.get("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node and node["$ref"].startswith("#/$defs/"):
                name = node["$ref"].split("/")[-1]
                resolved = walk(defs.get(name, {}))
                extra = {k: walk(v) for k, v in node.items() if k != "$ref"}
                return {**resolved, **extra}
            return {k: walk(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(schema)
