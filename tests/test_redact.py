"""Secret detection and redaction tests."""

from __future__ import annotations

from fariid_sec.security.redact import find_secrets, mask_secret, redact_mapping, redact_text


def test_redacts_sk_key() -> None:
    text = "Authorization: Bearer sk-abc1234567890123456789abcdef"
    out, found = redact_text(text)
    assert "sk-abc1234567890123456789abcdef" not in out
    assert "api key (sk-)" in found


def test_redacts_password_assignment() -> None:
    out, _ = redact_text("db password=correct-horse-battery")
    assert "correct-horse-battery" not in out
    assert "password" in out  # label preserved


def test_redacts_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34Gxk\n-----END RSA PRIVATE KEY-----"
    out, found = redact_text(text)
    assert "MIIBOgIBAAJBAKj34Gxk" not in out
    assert "private key block" in found


def test_find_secrets_empty() -> None:
    assert find_secrets("nothing sensitive here") == []


def test_mask_secret() -> None:
    masked = mask_secret("sk-1234567890abcdef")
    assert masked != "sk-1234567890abcdef"
    assert masked.startswith("sk-1")
    assert masked.endswith("cdef")


def test_redact_mapping_recursive() -> None:
    data = {"a": "ok", "nested": {"token": "Bearer sk-xxxxyyyyzzzz00001111"}, "list": ["sk-abcdef1234567890"]}
    out, found = redact_mapping(data)
    assert "sk-xxxxyyyyzzzz00001111" not in json_str(out)
    assert "sk-abcdef1234567890" not in json_str(out)
    assert found


def json_str(obj) -> str:
    import json

    return json.dumps(obj)
