"""AI provider abstraction.

Defines the provider-agnostic types (messages, tools, responses) and the
:class:`AIProvider` interface implemented by DeepSeek, Ollama, and any
OpenAI-compatible endpoint. Providers raise typed exceptions so the CLI can
recover gracefully from auth failures, rate limits, and timeouts.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]

    def to_openai(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": json.dumps(self.arguments)},
        }


@dataclass
class Message:
    role: str
    content: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None
    name: str | None = None
    reasoning_content: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = [tc.to_openai() for tc in self.tool_calls]
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            d["name"] = self.name
        return d


@dataclass
class ToolDefinition:
    """A tool the model may call, described as an OpenAI JSON schema."""

    name: str
    description: str
    parameters: dict[str, Any]
    risk: str = "low"  # low | medium | high | critical
    requires_auth: bool = False
    timeout: float = 300.0

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class ChatChunk:
    content: str | None = None
    reasoning_content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: Usage | None = None
    raw: dict[str, Any] | None = None

    @property
    def text(self) -> str:
        return self.content or ""


@dataclass
class ProviderConfig:
    api_key: str | None = None
    base_url: str = ""
    model: str = ""
    timeout: float = 60.0
    max_retries: int = 3
    temperature: float = 0.7
    max_tokens: int = 4096
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra_params: dict[str, Any] = field(default_factory=dict)


# --- typed errors ----------------------------------------------------------
class AIError(Exception):
    """Base class for all provider errors."""


class AuthenticationError(AIError):
    """401 — invalid or missing API key."""


class RateLimitError(AIError):
    """429 — provider rate limit; carries an optional retry-after hint."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class AITimeoutError(AIError):
    """The request exceeded the configured timeout."""


class ProviderConnectionError(AIError):
    """Network / server-side error (connect refused, 5xx, etc.)."""


class InvalidRequestError(AIError):
    """400 — malformed request (bad model name, invalid JSON schema, etc.)."""


def _parse_json_args(raw: str | dict | None) -> dict[str, Any]:
    """Parse tool-call arguments that may arrive as JSON string or dict."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except (json.JSONDecodeError, TypeError):
        return {"value": raw}


class AIProvider(ABC):
    """Interface every provider implements."""

    name = "base"

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    @abstractmethod
    def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        *,
        stream: bool = False,
        json_mode: bool = False,
    ) -> ChatChunk:
        """Return a single complete assistant response."""

    @abstractmethod
    def chat_stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        *,
        json_mode: bool = False,
    ) -> Iterator[ChatChunk]:
        """Yield incremental assistant response chunks."""

    @abstractmethod
    def check_health(self) -> dict[str, Any]:
        """Report provider reachability/auth status for ``fariid-sec doctor``."""

    def count_tokens(self, text: str) -> int:
        """A rough, dependency-free token estimate (4 chars/token)."""
        return max(1, len(text) // 4)

    def close(self) -> None:  # noqa: B027
        """Release any underlying HTTP client."""
