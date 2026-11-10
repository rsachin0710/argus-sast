"""The four supported provider adapters: Anthropic, OpenAI, xAI (Grok), Ollama.

Each adapter maps Argus's neutral request (system prompt + messages + JSON
schema) onto its vendor's API and normalises the reply into ``LLMResult``.
No vendor SDKs are required: plain HTTPS keeps behaviour uniform and the
dependency tree small.

How structured output is obtained per provider
---------------------------------------------
* Anthropic : tries, in order, and remembers per model what works:
                1. output_config.format = json_schema  (structured outputs; the
                   JSON comes back as text). Required by newer models, which
                   reject a forced tool_choice.
                2. a single forced tool ("submit_result") whose input_schema is
                   the schema (older models without output_config).
                3. plain JSON requested in the system prompt (last resort).
              Parameters a model rejects (e.g. `temperature` on Claude 5.5
              models) are dropped automatically.
* OpenAI    : response_format = json_object (+ schema described in the prompt).
* xAI Grok  : same as OpenAI (OpenAI-compatible API).
* Ollama    : `format` = the JSON schema (constrained decoding).
All replies are validated again with Pydantic in ``LLMClient``.
"""

from __future__ import annotations

import json

from ..config import LLMSettings, ProviderName
from .base import LLMError, LLMProvider, LLMResult, extract_json_object


# Keywords Anthropic structured outputs may reject. They are removed from the
# schema sent to the API only; Pydantic still enforces them on the reply.
_UNSUPPORTED_SCHEMA_KEYS = {
    "$schema", "default", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "minLength", "maxLength", "pattern", "format", "maxItems", "uniqueItems", "minProperties", "maxProperties",
}

# Minimum output budget: on newer models thinking tokens count against max_tokens,
# and a small budget ends the reply before the JSON is complete.
MIN_OUTPUT_TOKENS = 16000


def anthropic_schema(schema: dict) -> dict:
    """Normalise a JSON schema for Anthropic structured outputs: every object
    gets additionalProperties: false, and unsupported keywords are removed."""

    def walk(node):
        if isinstance(node, list):
            return [walk(x) for x in node]
        if not isinstance(node, dict):
            return node
        out = {}
        for k, v in node.items():
            if k in _UNSUPPORTED_SCHEMA_KEYS:
                continue
            if k == "minItems" and isinstance(v, int) and v > 1:
                continue
            if k == "properties" and isinstance(v, dict):
                out[k] = {name: walk(sub) for name, sub in v.items()}  # property names are not keywords
            else:
                out[k] = walk(v)
        if out.get("type") == "object" or "properties" in out:
            out["additionalProperties"] = False
        return out

    return walk(schema)


class AnthropicProvider(LLMProvider):
    name = ProviderName.ANTHROPIC
    MODES = ("output_config", "tool", "prompt")
    # What each model accepted, shared by every scan in this process:
    # model -> {"mode": ..., "dropped": {...}}. First scan learns, later scans reuse.
    _learned: dict[str, dict] = {}

    def _headers(self) -> dict:
        if not self.api_key:
            raise LLMError("anthropic: no API key (set ANTHROPIC_API_KEY or run `argus init`)")
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def _body(self, mode: str, system: str, messages: list[dict], schema: dict | None) -> dict:
        body: dict = {
            "model": self.settings.model,
            "max_tokens": max(self.settings.max_tokens, MIN_OUTPUT_TOKENS),
            "system": system,
            "messages": messages,
            "temperature": self.settings.temperature,
        }
        if schema is None:
            return body
        if mode == "output_config":
            body["output_config"] = {"format": {"type": "json_schema", "schema": anthropic_schema(schema)}}
        elif mode == "tool":
            body["tools"] = [{
                "name": "submit_result",
                "description": "Submit the final structured result.",
                "input_schema": schema,
            }]
            body["tool_choice"] = {"type": "tool", "name": "submit_result"}
        else:  # prompt
            body["system"] = (system + "\n\nRespond with a single JSON object only, no prose, matching this "
                              "JSON schema:\n" + json.dumps(schema))
        return body

    @staticmethod
    def _mode_rejected(err: LLMError, mode: str) -> bool:
        """Did a 400 say this structured-output mechanism is unsupported?"""
        if err.status != 400:
            return False
        msg = str(err).lower()
        if mode == "output_config":
            return "output_config" in msg or "output_format" in msg or ("format" in msg and "not supported" in msg)
        if mode == "tool":
            return "tool_choice" in msg or "tool use" in msg or "tools" in msg
        return False

    async def complete(self, system: str, messages: list[dict], schema: dict | None = None) -> LLMResult:
        learned = self._learned.setdefault(self.settings.model, {"mode": None, "dropped": set()})
        start = self.MODES.index(learned["mode"]) if learned["mode"] in self.MODES else 0
        modes = self.MODES[start:] if schema is not None else ("plain",)
        last_err: LLMError | None = None

        for mode in modes:
            body = self._body(mode, system, messages, schema)
            for p in learned["dropped"]:
                body.pop(p, None)
            try:
                raw = await self._post_dropping(body, learned)
            except LLMError as err:
                if schema is not None and self._mode_rejected(err, mode):
                    last_err = err
                    continue  # try the next structured-output mechanism
                raise
            if schema is not None:
                learned["mode"] = mode
            return self._parse(raw, schema)
        raise last_err or LLMError("anthropic: no structured-output mode was accepted")

    async def _post_dropping(self, body: dict, learned: dict) -> dict:
        """POST, dropping parameters the model rejects (and remembering them)."""
        for _ in range(4):
            try:
                return await self._post(f"{self.base_url}/v1/messages", body, self._headers())
            except LLMError as err:
                if not self._maybe_drop_param(err, body, ("temperature", "top_p", "top_k")):
                    raise
                learned["dropped"] |= self._dropped_params
        raise LLMError("anthropic: request kept failing")  # pragma: no cover

    def _parse(self, raw: dict, schema: dict | None) -> LLMResult:
        stop = raw.get("stop_reason")
        if stop == "refusal":
            raise LLMError("anthropic: the model declined to answer this request")
        text_parts, data = [], None
        for block in raw.get("content", []):
            if block.get("type") == "tool_use":
                data = block.get("input")
            elif block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            # thinking / redacted_thinking blocks are ignored
        text = "\n".join(text_parts)
        if data is None and schema is not None:
            data = extract_json_object(text)
            if data is None and stop == "max_tokens":
                raise LLMError("anthropic: the reply hit max_tokens before the JSON was complete; "
                               "raise llm.max_tokens")
        usage = raw.get("usage", {})
        return LLMResult(
            text=text or json.dumps(data or {}),
            data=data,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            raw=raw,
        )

    async def list_models(self) -> list[str]:
        resp = await self.http.get(f"{self.base_url}/v1/models?limit=100", headers=self._headers())
        resp.raise_for_status()
        return sorted(m["id"] for m in resp.json().get("data", []))


class OpenAICompatibleProvider(LLMProvider):
    """Shared implementation for OpenAI and xAI (Grok), whose chat APIs match."""

    max_tokens_field = "max_completion_tokens"
    env_hint = "OPENAI_API_KEY"

    def _headers(self) -> dict:
        if not self.api_key:
            raise LLMError(f"{self.name.value}: no API key (set {self.env_hint} or run `argus init`)")
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def supports_seed(self) -> bool:
        return "seed" not in self._dropped_params

    async def complete(self, system: str, messages: list[dict], schema: dict | None = None) -> LLMResult:
        sys_msg = system
        if schema is not None:
            # JSON mode guarantees valid JSON; the schema in the prompt guides shape.
            sys_msg += (
                "\n\nRespond with a single JSON object only, matching this JSON schema:\n"
                + json.dumps(schema)
            )
        body: dict = {
            "model": self.settings.model,
            "messages": [{"role": "system", "content": sys_msg}, *messages],
            "temperature": self.settings.temperature,
            "seed": self.settings.seed,
            # reasoning models count reasoning tokens against this limit
            self.max_tokens_field: max(self.settings.max_tokens, MIN_OUTPUT_TOKENS),
        }
        if schema is not None:
            body["response_format"] = {"type": "json_object"}
        for p in self._dropped_params:
            body.pop(p, None)

        for _ in range(4):
            try:
                raw = await self._post(f"{self.base_url}/chat/completions", body, self._headers())
                break
            except LLMError as err:
                if not self._maybe_drop_param(err, body, ("temperature", "seed", "response_format")):
                    raise
        else:  # pragma: no cover
            raise LLMError(f"{self.name.value}: request kept failing")

        choice = (raw.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content") or ""
        usage = raw.get("usage", {})
        return LLMResult(
            text=text,
            data=extract_json_object(text) if schema is not None else None,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            raw=raw,
        )

    async def list_models(self) -> list[str]:
        resp = await self.http.get(f"{self.base_url}/models", headers=self._headers())
        resp.raise_for_status()
        return sorted(m["id"] for m in resp.json().get("data", []))


class OpenAIProvider(OpenAICompatibleProvider):
    name = ProviderName.OPENAI
    max_tokens_field = "max_completion_tokens"
    env_hint = "OPENAI_API_KEY"


class XAIProvider(OpenAICompatibleProvider):
    name = ProviderName.XAI
    max_tokens_field = "max_tokens"
    env_hint = "XAI_API_KEY"


class OllamaProvider(LLMProvider):
    """Local models via Ollama: code never leaves the machine."""

    name = ProviderName.OLLAMA
    num_ctx = 16384

    def supports_seed(self) -> bool:
        return True

    async def complete(self, system: str, messages: list[dict], schema: dict | None = None) -> LLMResult:
        body: dict = {
            "model": self.settings.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
            "options": {
                "temperature": self.settings.temperature,
                "seed": self.settings.seed,
                "num_ctx": self.num_ctx,
                "num_predict": self.settings.max_tokens,
            },
        }
        if schema is not None:
            body["format"] = schema  # constrained decoding to the schema
        raw = await self._post(f"{self.base_url}/api/chat", body, {"Content-Type": "application/json"})
        text = (raw.get("message") or {}).get("content", "")
        return LLMResult(
            text=text,
            data=extract_json_object(text) if schema is not None else None,
            input_tokens=raw.get("prompt_eval_count", 0),
            output_tokens=raw.get("eval_count", 0),
            raw=raw,
        )

    async def list_models(self) -> list[str]:
        resp = await self.http.get(f"{self.base_url}/api/tags")
        resp.raise_for_status()
        return sorted(m["name"] for m in resp.json().get("models", []))


_ADAPTERS: dict[ProviderName, type[LLMProvider]] = {
    ProviderName.ANTHROPIC: AnthropicProvider,
    ProviderName.OPENAI: OpenAIProvider,
    ProviderName.XAI: XAIProvider,
    ProviderName.OLLAMA: OllamaProvider,
}


def create_provider(settings: LLMSettings, api_key: str | None = None) -> LLMProvider:
    """Factory. ``settings.provider`` is a closed enum, so only the four
    supported vendors can ever be constructed."""
    from ..credentials import get_api_key

    provider = ProviderName(settings.provider)
    key = api_key if api_key is not None else get_api_key(provider)
    return _ADAPTERS[provider](settings, key)
