"""Configuration manager tests."""

from __future__ import annotations

import json

import pytest
from fariid_sec.config.manager import AppConfig, ConfigManager


def test_defaults() -> None:
    cfg = AppConfig()
    assert cfg.provider == "deepseek"
    assert cfg.mode == "passive"
    assert cfg.effective_model == "deepseek-chat"


def test_rejects_unknown_provider() -> None:
    with pytest.raises(ValueError):
        AppConfig(provider="bogus")


def test_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError):
        AppConfig(mode="destructive")


def test_set_and_persist(tmp_path) -> None:
    m = ConfigManager(tmp_path)
    m.set("provider", "ollama")
    m.set("model", "qwen2.5-coder")
    assert m.get("provider") == "ollama"
    # a fresh manager reads the same persisted config
    assert ConfigManager(tmp_path).load().provider == "ollama"


def test_api_key_masked_in_public_view(tmp_path) -> None:
    m = ConfigManager(tmp_path)
    m.set_api_key("sk-super-secret-1234567890", "deepseek")
    view = ConfigManager.public_view(m.load())
    assert "sk-super-secret-1234567890" not in json.dumps(view)
    assert "*" in view["deepseek_api_key"]


def test_get_unknown_key(tmp_path) -> None:
    with pytest.raises(KeyError):
        ConfigManager(tmp_path).get("does_not_exist")
