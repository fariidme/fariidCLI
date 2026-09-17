"""Ollama provider (local models).

Speaks Ollama's native ``/api/chat`` endpoint, which supports streaming,
function/tool calling, and a model list endpoint for health checks. Supports
any locally pulled model such as ``llama3``, ``qwen``, or ``deepseek-coder``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx

from .base import (
    AIProvider,
    ChatChunk,
    Message,
    ProviderConfig,
    ProviderConnectionError,
    ToolCall,
    ToolDefinition,
    Usage,
    _parse_json_args,
)


class OllamaProvider(AIProvider):
    name = "ollama"

    def __init__(
        self, config: ProviderConfig, transport: httpx.BaseTransport | None = None
    ) -> None:
        super().__init__(config)
        timeout = httpx.Timeout(self.config.timeout, connect=10.0)
        self._client = httpx.Client(
            timeout=timeout, base_url=self.config.base_url.rstrip("/"), transport=transport
        )

    # --- helpers -----------------------------------------------------------
    def _to_ollama_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            item: dict[str, Any] = {"role": m.role, "content": m.content or ""}
            if m.tool_calls:
                item["tool_calls"] = [
                    {"function": {"name": tc.name, "arguments": tc.arguments}} for tc in m.tool_calls
                ]
            if m.name:
                item["name"] = m.name
            out.append(item)
        return out

    def _payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        json_mode: bool,
        stream: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": self._to_ollama_messages(messages),
            "stream": stream,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
        if json_mode:
            payload["format"] = "json"
        return payload

    def _parse_message(self, msg: dict[str, Any] | None, done: bool) -> ChatChunk:
        msg = msg or {}
        tool_calls = [
            ToolCall(
                id=f"call_{i}",
                name=(tc.get("function") or {}).get("name", ""),
                arguments=_parse_json_args((tc.get("function") or {}).get("arguments")),
            )
            for i, tc in enumerate(msg.get("tool_calls") or [])
        ]
        finish = "stop" if done and not tool_calls else ("tool_calls" if tool_calls else None)
        return ChatChunk(
            content=msg.get("content"),
            reasoning_content=msg.get("reasoning_content"),
            tool_calls=tool_calls,
            finish_reason=finish,
            usage=Usage(
                prompt_tokens=int(msg.get("prompt_eval_count") or 0),
                completion_tokens=int(msg.get("eval_count") or 0),
            )
            if done
            else None,
        )

    # --- chat --------------------------------------------------------------
    def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        *,
        stream: bool = False,
        json_mode: bool = False,
    ) -> ChatChunk:
        if stream:
            return self._chat_via_stream(messages, tools, json_mode)
        payload = self._payload(messages, tools, json_mode, stream=False)
        resp = self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return self._parse_message(data.get("message"), data.get("done", True))

    def _chat_via_stream(
        self, messages: list[Message], tools: list[ToolDefinition] | None, json_mode: bool
    ) -> ChatChunk:
        content: list[str] = []
        tool_calls: list[ToolCall] = []
        usage: Usage | None = None
        for chunk in self.chat_stream(messages, tools, json_mode=json_mode):
            if chunk.content:
                content.append(chunk.content)
            if chunk.tool_calls:
                tool_calls = chunk.tool_calls
            if chunk.usage:
                usage = chunk.usage
        return ChatChunk(
            content="".join(content) or None,
            tool_calls=tool_calls,
            finish_reason="tool_calls" if tool_calls else "stop",
            usage=usage,
        )

    def chat_stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        *,
        json_mode: bool = False,
    ) -> Iterator[ChatChunk]:
        payload = self._payload(messages, tools, json_mode, stream=True)
        with self._client.stream("POST", "/api/chat", json=payload) as resp:
            if resp.status_code != 200:
                raise ProviderConnectionError(
                    f"ollama error {resp.status_code}: {resp.read().decode(errors='replace')[:300]}"
                )
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                done = bool(obj.get("done"))
                yield self._parse_message(obj.get("message"), done)
                if done:
                    break

    # --- health ------------------------------------------------------------
    def check_health(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "provider": self.name,
            "base_url": self.config.base_url,
            "model": self.config.model,
        }
        try:
            resp = self._client.get("/api/tags", timeout=8.0)
            if resp.status_code == 200:
                names = [m.get("name") for m in resp.json().get("models", [])]
                result["status"] = "ok"
                result["models"] = names[:20]
                result["model_installed"] = any(
                    self.config.model.split(":")[0] in (n or "") for n in names
                )
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            result["status"] = "timeout"
        except httpx.HTTPError as exc:
            result["status"] = "unreachable"
            result["detail"] = str(exc)
        return result

    def close(self) -> None:
        self._client.close()
