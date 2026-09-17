"""Persistent conversation sessions for ``fariid-sec chat``.

Sessions live as JSON files in the user's config directory (0600). Only
conversation text is stored — API keys are never written into session files.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils.fs import atomic_write_text, ensure_dir


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Session:
    id: str
    title: str
    provider: str
    model: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "provider": self.provider,
            "model": self.model,
            "messages": self.messages,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            id=str(data.get("id", _new_id())),
            title=str(data.get("title", "untitled")),
            provider=str(data.get("provider", "")),
            model=str(data.get("model", "")),
            messages=list(data.get("messages", [])),
            created_at=str(data.get("created_at", _now())),
            updated_at=str(data.get("updated_at", _now())),
        )

    @property
    def message_count(self) -> int:
        return len(self.messages)


class SessionManager:
    def __init__(self, sessions_dir: Path) -> None:
        self.dir = sessions_dir

    def _path(self, session_id: str) -> Path:
        return self.dir / f"{session_id}.json"

    def create(self, title: str = "", provider: str = "", model: str = "") -> Session:
        session = Session(
            id=_new_id(),
            title=title or "new session",
            provider=provider,
            model=model,
        )
        self.save(session)
        return session

    def list(self) -> list[Session]:
        if not self.dir.exists():
            return []
        sessions: list[Session] = []
        for path in sorted(self.dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                sessions.append(Session.from_dict(data))
            except (json.JSONDecodeError, OSError):
                continue
        return sorted(sessions, key=lambda s: s.updated_at, reverse=True)

    def get(self, session_id: str) -> Session | None:
        path = self._path(session_id)
        if not path.exists():
            # allow prefix matching
            matches = [s for s in self.list() if s.id.startswith(session_id)]
            if len(matches) == 1:
                return matches[0]
            return None
        try:
            return Session.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            return None

    def save(self, session: Session) -> None:
        session.updated_at = _now()
        if not session.title or session.title == "new session":
            # derive a title from the first user message
            for m in session.messages:
                if m.get("role") == "user" and m.get("content"):
                    session.title = m["content"][:40]
                    break
        ensure_dir(self.dir)
        atomic_write_text(self._path(session.id), json.dumps(session.to_dict(), indent=2))

    def delete(self, session_id: str) -> bool:
        path = self._path(session_id)
        if path.exists():
            path.unlink()
            return True
        session = self.get(session_id)
        if session:
            self._path(session.id).unlink(missing_ok=True)
            return True
        return False

    def add_message(self, session_id: str, role: str, content: str) -> Session | None:
        session = self.get(session_id)
        if session is None:
            return None
        session.messages.append({"role": role, "content": content})
        self.save(session)
        return session
