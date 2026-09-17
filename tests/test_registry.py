"""Tool registry and detection tests."""

from __future__ import annotations

import pytest
from fariid_sec.tools.catalog import BUILTIN_CATALOG
from fariid_sec.tools.registry import MissingToolError, ToolDetector, ToolRegistry


class _FakeDetector(ToolDetector):
    def __init__(self, installed: set[str]) -> None:
        self._installed = installed

    def path(self, tool) -> str | None:
        return f"/usr/bin/{tool.binary}" if tool.name in self._installed else None


def test_builtin_catalog_populated() -> None:
    assert "nmap" in BUILTIN_CATALOG
    assert "nuclei" in BUILTIN_CATALOG
    assert "sqlmap" in BUILTIN_CATALOG
    assert BUILTIN_CATALOG["sqlmap"].risk == "high"


def test_registry_installed_and_missing() -> None:
    cat = {"nmap": BUILTIN_CATALOG["nmap"], "nuclei": BUILTIN_CATALOG["nuclei"]}
    reg = ToolRegistry(cat, detector=_FakeDetector({"nmap"}))
    assert reg.is_installed("nmap")
    assert not reg.is_installed("nuclei")
    assert [t.name for t in reg.installed()] == ["nmap"]
    assert [t.name for t in reg.missing()] == ["nuclei"]


def test_get_by_alias() -> None:
    reg = ToolRegistry()
    assert reg.get("nc") is not None
    assert reg.get("nc").name == "netcat"


def test_require_missing_raises() -> None:
    reg = ToolRegistry(detector=_FakeDetector(set()))
    with pytest.raises(MissingToolError):
        reg.require("nuclei")
