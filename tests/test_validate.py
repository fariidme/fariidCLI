"""Target classification and validation tests."""

from __future__ import annotations

from fariid_sec.security.validate import (
    classify_target,
    is_special_address,
    target_in_scope,
    validate_target,
)


def test_classify_ip() -> None:
    assert classify_target("192.168.1.10") == "ip"


def test_classify_cidr() -> None:
    assert classify_target("192.168.1.0/24") == "cidr"


def test_classify_hostname() -> None:
    assert classify_target("example.com") == "hostname"


def test_classify_localhost() -> None:
    assert classify_target("localhost") == "hostname"


def test_classify_url() -> None:
    assert classify_target("https://example.com/path") == "url"


def test_classify_invalid() -> None:
    assert classify_target("not a real target !!") is None
    assert classify_target("") is None


def test_validate_target() -> None:
    ok, kind = validate_target("10.0.0.1")
    assert ok and kind == "ip"
    ok, kind = validate_target("garbage!!")
    assert not ok


def test_is_special_address() -> None:
    assert is_special_address("127.0.0.1")
    assert is_special_address("10.1.2.3")
    assert not is_special_address("8.8.8.8")


def test_target_in_scope() -> None:
    assert target_in_scope("192.168.1.50", ["192.168.1.0/24"])
    assert not target_in_scope("10.0.0.5", ["192.168.1.0/24"])
    assert target_in_scope("anything", [])  # no scope = unrestricted
