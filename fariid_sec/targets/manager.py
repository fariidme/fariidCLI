"""Authorized target profile management.

Targets the operator has explicitly authorized are stored here. The ``--yes``
flag only applies to targets present in this list, so a stored profile is the
operator's durable record of authorization.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..security.validate import classify_target
from ..utils.fs import atomic_write_text, ensure_dir


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Target:
    name: str
    value: str
    description: str = ""
    kind: str = ""
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Target:
        return cls(
            name=str(data.get("name", "")),
            value=str(data.get("value", "")),
            description=str(data.get("description", "")),
            kind=str(data.get("kind", "")),
            created_at=str(data.get("created_at", _now())),
        )


class TargetManager:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _load(self) -> list[Target]:
        if not self.path.exists():
            return []
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or []
        except yaml.YAMLError:
            return []
        if isinstance(raw, list):
            return [Target.from_dict(t) for t in raw if isinstance(t, dict)]
        return []

    def _save(self, targets: list[Target]) -> None:
        ensure_dir(self.path.parent)
        payload = [t.to_dict() for t in targets]
        atomic_write_text(self.path, yaml.safe_dump(payload, sort_keys=False))

    def add(self, name: str, value: str, description: str = "") -> Target:
        kind = classify_target(value) or ""
        target = Target(name=name, value=value, description=description, kind=kind)
        targets = self._load()
        targets = [t for t in targets if t.name != name and t.value != value]
        targets.append(target)
        self._save(targets)
        return target

    def remove(self, name: str) -> bool:
        targets = self._load()
        remaining = [t for t in targets if t.name != name]
        if len(remaining) == len(targets):
            return False
        self._save(remaining)
        return True

    def get(self, name: str) -> Target | None:
        for t in self._load():
            if t.name == name:
                return t
        return None

    def list(self) -> list[Target]:
        return self._load()

    def is_authorized(self, value: str) -> bool:
        """True if ``value`` matches an explicitly stored authorized target."""
        for t in self._load():
            if t.value == value:
                return True
        return False

    def find_by_value(self, value: str) -> Target | None:
        for t in self._load():
            if t.value == value:
                return t
        return None


def new_session_id() -> str:
    return uuid.uuid4().hex[:12]
