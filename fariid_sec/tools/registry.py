"""Tool registry and automatic detection.

:class:`ToolRegistry` wraps the built-in catalog plus any user overrides and
answers questions like "is nmap installed?" and "which vulnerability scanners
do I have?". :class:`ToolDetector` checks the PATH for each binary.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path

from .catalog import BUILTIN_CATALOG, Tool


class MissingToolError(Exception):
    def __init__(self, tool: Tool) -> None:
        self.tool = tool
        hint = f" Install with: {tool.install_hint}" if tool.install_hint else ""
        super().__init__(f"{tool.binary!r} is not installed.{hint}")


class ToolDetector:
    """Checks whether binaries exist on the PATH."""

    def is_installed(self, tool: Tool) -> bool:
        return self.path(tool) is not None

    def path(self, tool: Tool) -> str | None:
        return shutil.which(tool.binary)


class ToolRegistry:
    def __init__(
        self,
        catalog: dict[str, Tool] | None = None,
        detector: ToolDetector | None = None,
        extra_paths: Iterable[str] = (),
    ) -> None:
        self._catalog = dict(catalog) if catalog is not None else dict(BUILTIN_CATALOG)
        self.detector = detector or ToolDetector()
        # Prepend any extra search paths to PATH for detection only.
        if extra_paths:
            self.detector = _PathAugmentedDetector(list(extra_paths))

    # --- lookups -----------------------------------------------------------
    def all(self) -> list[Tool]:
        return sorted(self._catalog.values(), key=lambda t: (t.category, t.name))

    def get(self, name: str) -> Tool | None:
        key = name.strip()
        for tool in self._catalog.values():
            if tool.name == key or tool.binary == key or key in tool.aliases:
                return tool
        return None

    def categories(self) -> list[str]:
        seen: list[str] = []
        for tool in self.all():
            if tool.category not in seen:
                seen.append(tool.category)
        return seen

    def by_category(self, category: str) -> list[Tool]:
        return [t for t in self.all() if t.category == category]

    # --- install state -----------------------------------------------------
    def is_installed(self, name: str) -> bool:
        tool = self.get(name)
        if tool is None:
            return False
        return self.detector.is_installed(tool)

    def installed(self) -> list[Tool]:
        return [t for t in self.all() if self.detector.is_installed(t)]

    def missing(self) -> list[Tool]:
        return [t for t in self.all() if not self.detector.is_installed(t)]

    def require(self, name: str) -> Tool:
        tool = self.get(name)
        if tool is None:
            raise MissingToolError(
                Tool(name, name, "unknown", "low", "unknown tool", "", ())
            )
        if not self.detector.is_installed(tool):
            raise MissingToolError(tool)
        return tool

    def status(self) -> list[dict]:
        rows: list[dict] = []
        for tool in self.all():
            path = self.detector.path(tool)
            rows.append(
                {
                    "name": tool.name,
                    "binary": tool.binary,
                    "category": tool.category,
                    "risk": tool.risk,
                    "installed": path is not None,
                    "path": path,
                    "install_hint": tool.install_hint,
                }
            )
        return rows


class _PathAugmentedDetector(ToolDetector):
    def __init__(self, extra_paths: list[str]) -> None:
        self._extra = [Path(p) for p in extra_paths]

    def path(self, tool: Tool) -> str | None:
        for directory in self._extra:
            candidate = directory / tool.binary
            if candidate.is_file() and candidate.stat().st_mode & 0o111:
                return str(candidate)
        return super().path(tool)
