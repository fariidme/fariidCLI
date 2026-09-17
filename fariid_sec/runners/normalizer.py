"""Result normalization: strip ANSI, truncate, and redact secrets.

Tool output is often huge, colorful, and may contain incidental secrets. Before
it is shown to the user or sent to an AI provider, it is normalized.
"""

from __future__ import annotations

import re

from ..security.redact import redact_text
from .command import CommandResult

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class ResultNormalizer:
    def __init__(self, max_chars: int = 20000, redact: bool = True) -> None:
        self.max_chars = max_chars
        self.redact = redact

    @staticmethod
    def strip_ansi(text: str) -> str:
        return _ANSI_RE.sub("", text)

    @staticmethod
    def strip_control(text: str) -> str:
        return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")

    def truncate(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.max_chars:
            return text, False
        return text[: self.max_chars] + "\n…[truncated]", True

    def normalize_text(self, text: str) -> dict:
        cleaned = self.strip_control(self.strip_ansi(text))
        if self.redact:
            cleaned, secrets = redact_text(cleaned)
        else:
            secrets = []
        truncated_text, was_truncated = self.truncate(cleaned)
        return {
            "text": truncated_text,
            "truncated": was_truncated,
            "redacted": bool(secrets),
            "secrets": secrets,
        }

    def normalize(self, result: CommandResult) -> dict:
        return {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration": round(result.duration, 3),
            "stdout": self.normalize_text(result.stdout),
            "stderr": self.normalize_text(result.stderr),
        }
