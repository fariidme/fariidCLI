"""The AI security agent.

Implements a real tool-calling loop:

    request -> understand -> select tools -> execute -> collect output
             -> parse -> send results back -> analyze -> (repeat) -> report

The agent only invokes the structured tools in :mod:`fariid_sec.tools.actions`;
it never shells out to arbitrary commands on its own.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..ai.base import AIProvider, ChatChunk, Message, Role, ToolCall, Usage
from ..runners.command import CommandRunner
from ..runners.normalizer import ResultNormalizer
from ..security.redact import redact_text
from ..tools.actions import ExecutionContext, get_tool, tool_definitions_for_mode
from ..tools.registry import ToolRegistry
from .prompts import build_system_prompt


@dataclass
class AgentResult:
    content: str
    reasoning: str = ""
    messages: list[Message] = field(default_factory=list)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    usage: Usage | None = None


class SecurityAgent:
    def __init__(
        self,
        provider: AIProvider,
        registry: ToolRegistry,
        runner: CommandRunner,
        normalize: ResultNormalizer,
        mode: str = "passive",
        target: str | None = None,
        platform: Any = None,
        confirm: Callable[[str], bool] | None = None,
        max_iterations: int = 12,
    ) -> None:
        self.provider = provider
        self.registry = registry
        self.runner = runner
        self.normalize = normalize
        self.mode = mode
        self.target = target
        self.platform = platform
        self._confirm = confirm or (lambda _msg: False)
        self.max_iterations = max_iterations

    def _ctx(self) -> ExecutionContext:
        return ExecutionContext(
            runner=self.runner,
            registry=self.registry,
            normalize=self.normalize,
            mode=self.mode,
            target=self.target,
            confirm=self._confirm,
        )

    def run(self, request: str, system_extra: str | None = None) -> AgentResult:
        safe_request, _ = redact_text(request)
        system = build_system_prompt(self.mode, self.target, self.platform)
        if system_extra:
            system = f"{system}\n\n{system_extra}"

        messages: list[Message] = [
            Message(role=Role.SYSTEM, content=system),
            Message(role=Role.USER, content=safe_request),
        ]
        tools = tool_definitions_for_mode(self.mode)
        tool_history: list[dict[str, Any]] = []
        reasoning: list[str] = []
        last_usage: Usage | None = None

        for _ in range(self.max_iterations):
            resp: ChatChunk = self.provider.chat(messages, tools=tools)
            if resp.reasoning_content:
                reasoning.append(resp.reasoning_content)
            if resp.usage:
                last_usage = resp.usage

            if not resp.tool_calls:
                return AgentResult(
                    content=resp.content or "",
                    reasoning="\n".join(reasoning),
                    messages=messages,
                    tool_history=tool_history,
                    usage=last_usage,
                )

            # Append the assistant tool-call turn.
            messages.append(
                Message(role=Role.ASSISTANT, content=resp.content, tool_calls=resp.tool_calls)
            )

            for call in resp.tool_calls:
                outcome = self._dispatch(call)
                tool_history.append(outcome)
                messages.append(
                    Message(
                        role=Role.TOOL,
                        content=json.dumps(outcome, default=str),
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )

        return AgentResult(
            content="(reached the maximum number of tool iterations)",
            reasoning="\n".join(reasoning),
            messages=messages,
            tool_history=tool_history,
            usage=last_usage,
        )

    def _dispatch(self, call: ToolCall) -> dict[str, Any]:
        tool = get_tool(call.name)
        if tool is None:
            return {"ok": False, "tool": call.name, "error": "unknown tool"}

        needs_confirm = tool.definition.requires_auth or tool.definition.risk in ("high", "critical")
        if needs_confirm:
            approved = self._confirm(
                f"Run {call.name} (risk: {tool.definition.risk}) against {self.target or 'target'}?"
            )
            if not approved:
                return {
                    "ok": False,
                    "tool": call.name,
                    "error": "denied: operator did not authorize this action",
                }

        entry = {
            "tool": call.name,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "arguments": call.arguments,
            "risk": tool.definition.risk,
        }
        try:
            result = tool.handler(call.arguments, self._ctx())
        except Exception as exc:  # noqa: BLE001 — a tool failure must not kill the loop
            result = {"ok": False, "tool": call.name, "error": f"execution error: {exc}"}
        binary_name = result.pop("tool", None)
        entry.update(result)
        entry["tool"] = call.name
        if binary_name:
            entry["binary"] = binary_name
        return entry
