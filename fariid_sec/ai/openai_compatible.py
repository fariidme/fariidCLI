"""OpenAI-compatible Chat Completions provider.

Implements the shared protocol used by DeepSeek and any other OpenAI-style
endpoint (streaming, tool/function calling, JSON output, usage reporting,
typed error mapping, and retry/backoff).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import httpx

from .base import (
    AIProvider,
    AITimeoutError,
    AuthenticationError,
    ChatChunk,
    InvalidRequestError,
    Message,
    ProviderConfig,
    ProviderConnectionError,
    RateLimitError,
    ToolCall,
    ToolDefinition,
    Usage,
    _parse_json_args,
)


class OpenAICompatibleProvider(AIProvider):
    name = "openai-compatible"

    def __init__(
        self, config: ProviderConfig, transport: httpx.BaseTransport | None = None
    ) -> None:
        super().__init__(config)
        timeout = httpx.Timeout(self.config.timeout, connect=10.0)
        self._client = httpx.Client(timeout=timeout, headers=self._headers(), transport=transport)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers.update(self.config.extra_headers)
        return headers

    @property
    def endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    @property
    def models_endpoint(self) -> str:
        return f"{self.config.base_url.rstrip('/')}/models"

    # --- payload -----------------------------------------------------------
    def _payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        json_mode: bool,
        stream: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        payload.update(self.config.extra_params)
        return payload

    # --- non-streaming -----------------------------------------------------
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
        return self._request(messages, tools, json_mode)

    def _chat_via_stream(
        self, messages: list[Message], tools: list[ToolDefinition] | None, json_mode: bool
    ) -> ChatChunk:
        content: list[str] = []
        reasoning: list[str] = []
        tool_calls: list[ToolCall] = []
        usage: Usage | None = None
        finish_reason: str | None = None
        raw: dict[str, Any] | None = None
        for chunk in self.chat_stream(messages, tools, json_mode=json_mode):
            if chunk.content:
                content.append(chunk.content)
            if chunk.reasoning_content:
                reasoning.append(chunk.reasoning_content)
            if chunk.tool_calls:
                tool_calls = chunk.tool_calls
            if chunk.usage:
                usage = chunk.usage
            if chunk.finish_reason:
                finish_reason = chunk.finish_reason
            raw = chunk.raw or raw
        return ChatChunk(
            content="".join(content) or None,
            reasoning_content="".join(reasoning) or None,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage=usage,
            raw=raw,
        )

    def _request(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        json_mode: bool,
    ) -> ChatChunk:
        payload = self._payload(messages, tools, json_mode, stream=False)
        last_exc: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self._client.post(self.endpoint, json=payload)
                return self._handle_response(resp)
            except httpx.TimeoutException:
                last_exc = AITimeoutError(f"request timed out after {self.config.timeout}s")
            except httpx.ConnectError as exc:
                last_exc = ProviderConnectionError(f"could not reach {self.endpoint}: {exc}")
            except (RateLimitError, AuthenticationError, InvalidRequestError):
                raise
            if attempt < self.config.max_retries:
                time.sleep(min(2 ** attempt, 8.0))
        raise last_exc  # type: ignore[misc]

    # --- streaming ---------------------------------------------------------
    def chat_stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        *,
        json_mode: bool = False,
    ) -> Iterator[ChatChunk]:
        payload = self._payload(messages, tools, json_mode, stream=True)
        with self._client.stream("POST", self.endpoint, json=payload) as resp:
            if resp.status_code != 200:
                body = resp.read().decode("utf-8", errors="replace")
                self._raise_for_status(resp.status_code, body)

            tool_acc: dict[int, dict[str, str]] = {}
            for line in resp.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue

                choice = (obj.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                for tc in delta.get("tool_calls") or []:
                    idx = int(tc.get("index", 0))
                    slot = tool_acc.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["arguments"] += fn["arguments"]

                finish = choice.get("finish_reason")
                calls: list[ToolCall] = []
                if finish and tool_acc:
                    calls = [
                        ToolCall(
                            id=s["id"] or f"call_{i}",
                            name=s["name"],
                            arguments=_parse_json_args(s["arguments"]),
                        )
                        for i, s in sorted(tool_acc.items())
                    ]

                yield ChatChunk(
                    content=delta.get("content"),
                    reasoning_content=delta.get("reasoning_content") or delta.get("reasoning"),
                    tool_calls=calls,
                    finish_reason=finish,
                    usage=self._parse_usage(obj.get("usage")) if obj.get("usage") else None,
                    raw=obj,
                )

    # --- response handling -------------------------------------------------
    def _handle_response(self, resp: httpx.Response) -> ChatChunk:
        if resp.status_code != 200:
            self._raise_for_status(resp.status_code, resp.text)
        return self._parse(resp.json())

    def _parse(self, data: dict[str, Any]) -> ChatChunk:
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = [
            ToolCall(
                id=tc.get("id", ""),
                name=(tc.get("function") or {}).get("name", ""),
                arguments=_parse_json_args((tc.get("function") or {}).get("arguments")),
            )
            for tc in msg.get("tool_calls") or []
        ]
        return ChatChunk(
            content=msg.get("content"),
            reasoning_content=msg.get("reasoning_content") or msg.get("reasoning"),
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
            usage=self._parse_usage(data.get("usage")),
            raw=data,
        )

    @staticmethod
    def _parse_usage(raw: dict[str, Any] | None) -> Usage | None:
        if not raw:
            return None
        return Usage(
            prompt_tokens=int(raw.get("prompt_tokens") or 0),
            completion_tokens=int(raw.get("completion_tokens") or 0),
            total_tokens=int(raw.get("total_tokens") or 0),
        )

    @staticmethod
    def _raise_for_status(status: int, body: str) -> None:
        snippet = body[:500]
        if status == 401:
            raise AuthenticationError("invalid API key (401 Unauthorized). Check your key.")
        if status == 429:
            raise RateLimitError("rate limited (429). Try again shortly.", retry_after=None)
        if status >= 500:
            raise ProviderConnectionError(f"provider server error ({status}): {snippet}")
        raise InvalidRequestError(f"request rejected ({status}): {snippet}")

    # --- health ------------------------------------------------------------
    def check_health(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "provider": self.name,
            "base_url": self.config.base_url,
            "model": self.config.model,
            "api_key_set": bool(self.config.api_key),
        }
        if not self.config.api_key:
            result["status"] = "no_api_key"
            return result
        try:
            r = self._client.get(self.models_endpoint, timeout=8.0)
            if r.status_code == 401:
                result["status"] = "unauthorized"
            elif r.status_code in (200, 201, 204):
                result["status"] = "ok"
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {r.status_code}"
        except httpx.TimeoutException:
            result["status"] = "timeout"
        except httpx.HTTPError as exc:
            result["status"] = "unreachable"
            result["detail"] = str(exc)
        return result

    def close(self) -> None:
        self._client.close()
