"""Authorized target manager tests."""

from __future__ import annotations

from fariid_sec.targets import TargetManager


def test_add_list_authorize_remove(tmp_path) -> None:
    m = TargetManager(tmp_path / "targets.yaml")
    m.add("lab", "192.168.1.10", "my lab box")
    assert m.is_authorized("192.168.1.10")
    assert not m.is_authorized("8.8.8.8")
    assert m.get("lab").value == "192.168.1.10"
    assert len(m.list()) == 1
    assert m.remove("lab")
    assert not m.is_authorized("192.168.1.10")


def test_add_duplicate_replaces(tmp_path) -> None:
    m = TargetManager(tmp_path / "targets.yaml")
    m.add("lab", "192.168.1.10")
    m.add("lab", "192.168.1.11")
    assert len(m.list()) == 1
    assert m.get("lab").value == "192.168.1.11"


def test_remove_missing(tmp_path) -> None:
    m = TargetManager(tmp_path / "targets.yaml")
    assert not m.remove("nope")
