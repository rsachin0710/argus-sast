"""Provider adapters: request shape and response parsing, via a mocked HTTP
transport (no network, no keys)."""

import asyncio
import json

import httpx
import pytest
from pydantic import BaseModel

from argus.config import LLMSettings
from argus.llm import LLMClient
from argus.llm.base import LLMError
from argus.llm.providers import OllamaProvider, OpenAIProvider, XAIProvider


class Out(BaseModel):
    verdict: str
    score: int


def _run(coro):
    return asyncio.run(coro)


TOOL_CHOICE_REJECTED = ('{"type":"error","error":{"type":"invalid_request_error","message":'
                        '"tool_choice: type \\"tool\\" and \\"any\\" are not supported for this model."}}')


def _anthropic(handler, model):
    from argus.llm.providers import AnthropicProvider as AP

    AP._learned.pop(model, None)  # fresh per test
    return AP(LLMSettings(provider="anthropic", model=model), "k",
              httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def test_anthropic_uses_structured_outputs_first():
    """Newer Claude models: output_config json_schema, JSON returned as text."""
    seen = []

    def handler(req: httpx.Request):
        seen.append((str(req.url), req.headers, json.loads(req.content)))
        return httpx.Response(200, json={"content": [{"type": "thinking", "thinking": "..."},
                                                     {"type": "text", "text": '{"verdict": "ok", "score": 3}'}],
                                         "stop_reason": "end_turn", "usage": {"input_tokens": 11, "output_tokens": 5}})

    p = _anthropic(handler, "claude-new-a")
    out = _run(LLMClient(p).structured(system="s", user="u", model_cls=Out))
    assert out == Out(verdict="ok", score=3)
    url, headers, body = seen[0]
    assert url.endswith("/v1/messages") and headers["x-api-key"] == "k" and headers["anthropic-version"]
    fmt = body["output_config"]["format"]
    assert fmt["type"] == "json_schema" and fmt["schema"]["additionalProperties"] is False
    assert "tool_choice" not in body and "tools" not in body
    assert body["max_tokens"] >= 16000


def test_anthropic_drops_temperature_the_model_rejects():
    bodies = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        bodies.append(body)
        if "temperature" in body:
            return httpx.Response(400, json={"type": "error", "error": {"type": "invalid_request_error",
                                             "message": "temperature: Extra inputs are not permitted"}})
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"verdict":"ok","score":1}'}]})

    p = _anthropic(handler, "claude-new-b")
    client = LLMClient(p)
    _run(client.structured(system="s", user="a", model_cls=Out))
    _run(client.structured(system="s", user="b", model_cls=Out))
    assert len(bodies) == 3  # rejected once, then remembered: no temperature on the second call
    assert "temperature" not in bodies[-1]


def test_anthropic_falls_back_to_forced_tool_for_older_models():
    modes = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        if "output_config" in body:
            modes.append("output_config")
            return httpx.Response(400, json={"type": "error", "error": {"type": "invalid_request_error",
                                             "message": "output_config: Extra inputs are not permitted"}})
        modes.append("tool")
        assert body["tool_choice"] == {"type": "tool", "name": "submit_result"}
        return httpx.Response(200, json={"content": [{"type": "tool_use", "name": "submit_result",
                                                      "input": {"verdict": "ok", "score": 2}}]})

    p = _anthropic(handler, "claude-old")
    client = LLMClient(p)
    assert _run(client.structured(system="s", user="a", model_cls=Out)).score == 2
    assert _run(client.structured(system="s", user="b", model_cls=Out)).score == 2
    assert modes == ["output_config", "tool", "tool"]  # learned after the first call


def test_anthropic_last_resort_prompt_json_and_the_reported_error():
    """The exact error from the field (forced tool_choice rejected) never stops a scan."""
    calls = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        if "output_config" in body:
            calls.append("output_config")
            return httpx.Response(400, json={"type": "error", "error": {"type": "invalid_request_error",
                                             "message": "output_config.format: not supported for this model"}})
        if "tool_choice" in body:
            calls.append("tool")
            return httpx.Response(400, text=TOOL_CHOICE_REJECTED)
        calls.append("prompt")
        assert "JSON schema" in body["system"]
        return httpx.Response(200, json={"content": [{"type": "text", "text": 'Here: {"verdict":"ok","score":4}'}]})

    p = _anthropic(handler, "claude-odd")
    assert _run(LLMClient(p).structured(system="s", user="u", model_cls=Out)).score == 4
    assert calls == ["output_config", "tool", "prompt"]


def test_anthropic_refusal_and_truncation_are_clear_errors():
    def refuse(req):
        return httpx.Response(200, json={"content": [], "stop_reason": "refusal"})

    with pytest.raises(LLMError, match="declined"):
        _run(_anthropic(refuse, "claude-r").complete("s", [{"role": "user", "content": "u"}], {"type": "object"}))

    def cut(req):
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"verdict": "o'}],
                                         "stop_reason": "max_tokens"})

    with pytest.raises(LLMError, match="max_tokens"):
        _run(_anthropic(cut, "claude-t").complete("s", [{"role": "user", "content": "u"}], {"type": "object"}))


def test_anthropic_schema_normalisation():
    from argus.agents.schemas import TracerAction, VerifierOutput
    from argus.llm.base import inline_schema
    from argus.llm.providers import anthropic_schema

    for model in (VerifierOutput, TracerAction):
        s = anthropic_schema(inline_schema(model.model_json_schema()))
        text = json.dumps(s)
        assert '"minimum"' not in text and '"maximum"' not in text and '"default"' not in text

        def objects(node):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    yield node
                for v in node.values():
                    yield from objects(v)
            elif isinstance(node, list):
                for v in node:
                    yield from objects(v)

        assert all(o.get("additionalProperties") is False for o in objects(s))
        # property names that collide with keywords are kept
    assert "pattern" in anthropic_schema(inline_schema(TracerAction.model_json_schema()))["properties"]["args"]["properties"]


@pytest.mark.parametrize("cls,url,tok_field", [
    (OpenAIProvider, "https://api.openai.com/v1/chat/completions", "max_completion_tokens"),
    (XAIProvider, "https://api.x.ai/v1/chat/completions", "max_tokens"),
])
def test_openai_compatible_json_mode_and_param_drop(cls, url, tok_field):
    bodies = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        bodies.append(body)
        if "temperature" in body:  # simulate a reasoning model rejecting temperature
            return httpx.Response(400, json={"error": {"message": "Unsupported parameter: 'temperature'"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"verdict":"ok","score":1}'}}],
                                         "usage": {"prompt_tokens": 3, "completion_tokens": 2}})

    p = cls(LLMSettings(provider=cls.name.value, model="m"), "k",
            httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    client = LLMClient(p)
    assert _run(client.structured(system="s", user="u", model_cls=Out)).score == 1
    assert bodies[0]["response_format"] == {"type": "json_object"}
    assert tok_field in bodies[0] and bodies[0]["seed"] == 1337
    assert "temperature" not in bodies[-1]
    assert client.stats.input_tokens == 3


def test_ollama_sends_schema_and_seed():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"message": {"content": '{"verdict":"ok","score":2}'},
                                         "prompt_eval_count": 7, "eval_count": 3})

    p = OllamaProvider(LLMSettings(provider="ollama", model="qwen"), None,
                       httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert _run(LLMClient(p).structured(system="s", user="u", model_cls=Out)).score == 2
    assert seen["url"] == "http://localhost:11434/api/chat"
    assert seen["body"]["format"]["properties"]["score"]["type"] == "integer"
    assert seen["body"]["options"]["seed"] == 1337 and seen["body"]["stream"] is False


def test_invalid_output_gets_one_repair_then_fails():
    calls = []

    def handler(req: httpx.Request):
        calls.append(1)
        return httpx.Response(200, json={"message": {"content": '{"verdict": 5}'}})

    p = OllamaProvider(LLMSettings(provider="ollama", model="q"), None,
                       httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(LLMError, match="validation"):
        _run(LLMClient(p).structured(system="s", user="u", model_cls=Out))
    assert len(calls) == 2


def test_budget_is_enforced():
    from argus.llm import BudgetExceeded

    def handler(req):
        return httpx.Response(200, json={"message": {"content": '{"verdict":"ok","score":1}'}})

    p = OllamaProvider(LLMSettings(provider="ollama", model="q"), None,
                       httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    c = LLMClient(p, max_calls=1)
    _run(c.structured(system="s", user="a", model_cls=Out))
    with pytest.raises(BudgetExceeded):
        _run(c.structured(system="s", user="b", model_cls=Out))


def test_missing_key_is_a_clear_error():
    p = OpenAIProvider(LLMSettings(provider="openai", model="m"), None)
    with pytest.raises(LLMError, match="no API key"):
        _run(p.complete("s", [{"role": "user", "content": "u"}], {}))
