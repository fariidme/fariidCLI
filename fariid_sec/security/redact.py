"""Secret detection and redaction.

Before any project file, tool output, or configuration value is sent to an AI
provider, it must pass through :func:`redact_text`. We detect and mask common
secret shapes so credentials never leave the machine.

Nothing here *transmits* data; it only rewrites local strings. All patterns
are conservative: a false positive is a missed convenience, a false negative
is a leaked secret, so we prefer the former.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    repl: str = REDACTED


_SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("api key (sk-)", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")),
    SecretPattern("anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b")),
    SecretPattern("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    SecretPattern("github pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    SecretPattern(
        "aws access key id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"),
    ),
    SecretPattern("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretPattern("slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    SecretPattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    SecretPattern(
        "private key block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
    ),
    SecretPattern(
        "authorization header",
        re.compile(r"(?i)(Authorization\s*:\s*(?:Bearer\s+)?)\S+"),
        r"\1" + REDACTED,
    ),
    SecretPattern(
        "password assignment",
        re.compile(r"(?i)\b(password|passwd|pwd)\s*([=:])\s*\S+"),
        r"\1\2 " + REDACTED,
    ),
    SecretPattern(
        "key assignment",
        re.compile(r"(?i)\b(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*([=:])\s*\S+"),
        r"\1\2 " + REDACTED,
    ),
]


def mask_secret(value: str | None) -> str:
    """Return a masked representation of a single secret for display."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def find_secrets(text: str) -> list[str]:
    """Return the names of any detected secret shapes in ``text``."""
    if not text:
        return []
    found: list[str] = []
    for sp in _SECRET_PATTERNS:
        if sp.pattern.search(text):
            found.append(sp.name)
    return found


def redact_text(text: str) -> tuple[str, list[str]]:
    """Return ``text`` with secrets masked, plus the list of detected kinds."""
    if not text:
        return text, []
    found = find_secrets(text)
    out = text
    for sp in _SECRET_PATTERNS:
        out = sp.pattern.sub(sp.repl, out)
    return out, found


def redact_mapping(data: dict) -> tuple[dict, list[str]]:
    """Redact all string values in a (possibly nested) mapping."""
    found: list[str] = []
    out: dict = {}
    for key, value in data.items():
        if isinstance(value, str):
            new_text, hits = redact_text(value)
            found.extend(hits)
            out[key] = new_text
        elif isinstance(value, dict):
            new_dict, hits = redact_mapping(value)
            found.extend(hits)
            out[key] = new_dict
        elif isinstance(value, list):
            new_list, hits = redact_list(value)
            found.extend(hits)
            out[key] = new_list
        else:
            out[key] = value
    return out, found


def redact_list(items: list) -> tuple[list, list[str]]:
    found: list[str] = []
    out: list = []
    for item in items:
        if isinstance(item, str):
            new_text, hits = redact_text(item)
            found.extend(hits)
            out.append(new_text)
        elif isinstance(item, dict):
            new_dict, hits = redact_mapping(item)
            found.extend(hits)
            out.append(new_dict)
        elif isinstance(item, list):
            new_list, hits = redact_list(item)
            found.extend(hits)
            out.append(new_list)
        else:
            out.append(item)
    return out, found
