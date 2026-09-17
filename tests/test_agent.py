"""Security agent tests with a fake provider (no network, no tools)."""

from __future__ import annotations

from typing import Any

from fariid_sec.agent import SecurityAgent
from fariid_sec.ai import ChatChunk, ToolCall
from fariid_sec.runners.command import CommandRunner
from fariid_sec.runners.normalizer import ResultNormalizer
from fariid_sec.tools.registry import ToolRegistry


class FakeProvider:
    name = "fake"

    def __init__(self, responses: list[ChatChunk]) -> None:
        self._responses = list(responses)
        self.calls: list[Any] = []

    def chat(self, messages, tools=None, *, stream=False, json_mode=False):
        self.calls.append(list(messages))
        return self._responses.pop(0)

    def chat_stream(self, *a, **k):
        yield ChatChunk(content="streamed")

    def check_health(self):
        return {"status": "ok"}


def test_agent_tool_loop() -> None:
    provider = FakeProvider(
        [
            ChatChunk(tool_calls=[ToolCall(id="c1", name="run_nmap", arguments={"target": "127.0.0.1"})]),
            ChatChunk(content="Scan complete, 2 ports open."),
        ]
    )
    agent = SecurityAgent(
        provider,
        ToolRegistry(),
        CommandRunner(),
        ResultNormalizer(),
        mode="lab",
        target="127.0.0.1",
        confirm=lambda _m: True,
    )
    result = agent.run("scan this")
    assert result.content == "Scan complete, 2 ports open."
    assert len(result.tool_history) == 1
    assert result.tool_history[0]["tool"] == "run_nmap"


def test_agent_denies_unauthorized_tool() -> None:
    provider = FakeProvider(
        [
            ChatChunk(tool_calls=[ToolCall(id="c1", name="run_sqlmap", arguments={"url": "http://x"})]),
            ChatChunk(content="I cannot run sqlmap without authorization."),
        ]
    )
    agent = SecurityAgent(
        provider,
        ToolRegistry(),
        CommandRunner(),
        ResultNormalizer(),
        mode="lab",
        confirm=lambda _m: False,
    )
    result = agent.run("test sqlmap")
    assert result.tool_history[0]["error"] == "denied: operator did not authorize this action"


def test_agent_plain_answer_no_tools() -> None:
    provider = FakeProvider([ChatChunk(content="Use nmap -sV.")])
    agent = SecurityAgent(provider, ToolRegistry(), CommandRunner(), ResultNormalizer())
    result = agent.run("how do I scan?")
    assert result.content == "Use nmap -sV."
    assert result.tool_history == []
