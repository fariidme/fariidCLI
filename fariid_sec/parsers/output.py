"""Generic output parser: dispatch to a tool-specific parser."""

from __future__ import annotations

from .nmap import parse_greppable, parse_xml
from .nuclei import parse_jsonl


class OutputParser:
    """Parse raw tool output into structured findings."""

    @staticmethod
    def parse(tool: str, text: str) -> dict:
        name = (tool or "").lower()
        if "nmap" in name:
            if "<nmaprun" in text:
                return {"findings": parse_xml(text), "format": "xml"}
            return {"findings": parse_greppable(text), "format": "greppable"}
        if "nuclei" in name:
            return {"findings": parse_jsonl(text), "format": "jsonl"}
        return {"findings": [], "format": "text", "raw": text}
