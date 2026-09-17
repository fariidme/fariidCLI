"""Shared pytest fixtures: isolate config/state and scrub secrets from env."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("FARIID_SEC_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    for var in (
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_MODEL",
        "OPENAI_API_KEY",
        "OLLAMA_BASE_URL",
        "FARIID_SEC_PROVIDER",
        "FARIID_SEC_MODE",
    ):
        monkeypatch.delenv(var, raising=False)
