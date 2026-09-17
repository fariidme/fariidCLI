"""AI provider tests using httpx MockTransport (no network)."""

from __future__ import annotations

import httpx
import pytest
from fariid_sec.ai import (
    AuthenticationError,
    DeepSeekProvider,
    InvalidRequestError,
    Message,
    OpenAICompatibleProvider,
    ProviderConfig,
    RateLimitError,
    Role,
)


def _provider(handler, *, name: str = "deepseek", **cfg):
    transport = httpx.MockTransport(handler)
    config = ProviderConfig(
        api_key="sk-test", base_url="https://api.deepseek.com", model="deepseek-chat", **cfg
    )
    if name == "deepseek":
        return DeepSeekProvider(config, transport=transport)
    return OpenAICompatibleProvider(config, transport=transport)


def test_chat_parses_content_tool_calls_usage() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": "ok",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "run_nmap", "arguments": '{"target": "127.0.0.1"}'},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    provider = _provider(lambda request: httpx.Response(200, json=payload))
    out = provider.chat([Message(role=Role.USER, content="scan")])
    assert out.content == "ok"
    assert out.tool_calls[0].name == "run_nmap"
    assert out.tool_calls[0].arguments == {"target": "127.0.0.1"}
    assert out.usage is not None and out.usage.total_tokens == 15


def test_auth_error_raised() -> None:
    provider = _provider(lambda request: httpx.Response(401, text="bad key"))
    with pytest.raises(AuthenticationError):
        provider.chat([Message(role=Role.USER, content="hi")])


def test_rate_limit_raised() -> None:
    provider = _provider(lambda request: httpx.Response(429, text="slow down"))
    with pytest.raises(RateLimitError):
        provider.chat([Message(role=Role.USER, content="hi")])


def test_invalid_request_raised() -> None:
    provider = _provider(lambda request: httpx.Response(400, text="bad model"))
    with pytest.raises(InvalidRequestError):
        provider.chat([Message(role=Role.USER, content="hi")])


def test_streaming_accumulates_content() -> None:
    sse = (
        b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    provider = _provider(
        lambda request: httpx.Response(
            200, content=sse, headers={"content-type": "text/event-stream"}
        )
    )
    chunks = list(provider.chat_stream([Message(role=Role.USER, content="hi")]))
    text = "".join(c.content or "" for c in chunks)
    assert text == "hello world"


def test_streaming_reasoning_captured() -> None:
    sse = (
        b'data: {"choices":[{"delta":{"reasoning_content":"thinking..."}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"answer"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    provider = _provider(
        lambda request: httpx.Response(
            200, content=sse, headers={"content-type": "text/event-stream"}
        )
    )
    reasoning = "".join(c.reasoning_content or "" for c in provider.chat_stream([]))
    assert "thinking" in reasoning
