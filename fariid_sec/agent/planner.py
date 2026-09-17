"""Natural-language -> structured execution plan."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from ..ai.base import AIProvider, Message, Role
from ..security.redact import redact_text
from .prompts import PLANNER_SYSTEM, plan_user_prompt


class Plan(BaseModel):
    target: str = ""
    objective: str = ""
    tools: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    risk: str = "low"

    def to_dict(self) -> dict:
        return self.model_dump()


class Planner:
    def __init__(self, provider: AIProvider) -> None:
        self.provider = provider

    def plan(self, request: str, mode: str = "passive", target: str | None = None) -> Plan:
        safe_request, _ = redact_text(request)
        messages = [
            Message(role=Role.SYSTEM, content=PLANNER_SYSTEM),
            Message(role=Role.USER, content=plan_user_prompt(safe_request, mode, target)),
        ]
        resp = self.provider.chat(messages, json_mode=True)
        raw = (resp.content or "{}").strip()
        # tolerate a leading/trailing code fence
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return Plan(objective="failed-to-parse-plan", actions=[], risk="low")
        return Plan(**data)
