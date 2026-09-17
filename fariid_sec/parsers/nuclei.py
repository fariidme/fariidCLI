"""Parse nuclei JSONL output (``nuclei -jsonl -silent``)."""

from __future__ import annotations

import json

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def parse_jsonl(text: str) -> list[dict]:
    """Parse newline-delimited nuclei JSON into a list of finding dicts."""
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        findings.append(
            {
                "id": obj.get("template-id") or obj.get("templateID") or "",
                "name": info.get("name") or obj.get("template-id") or "",
                "severity": (info.get("severity") or "unknown").lower(),
                "tags": info.get("tags") or [],
                "host": obj.get("host") or obj.get("matched-at") or "",
                "url": obj.get("matched-at") or obj.get("matched") or "",
                "type": obj.get("type") or "",
                "description": (info.get("description") or "").strip(),
                "matcher": obj.get("matcher-name") or "",
            }
        )
    return findings


def severity_key(finding: dict) -> int:
    return _SEVERITY_ORDER.get(str(finding.get("severity", "unknown")).lower(), 5)
