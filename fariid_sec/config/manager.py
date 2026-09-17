"""Configuration manager.

Loads and persists the typed :class:`AppConfig`, resolves the config/state
directories, and provides a thin ``get``/``set`` API for the ``config`` CLI.

Environment variables take precedence over the config file, which takes
precedence over defaults. API keys are stored with ``0600`` permissions and are
never printed in full.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from ..security.redact import mask_secret
from ..utils.fs import atomic_write_text, config_home, ensure_dir, state_home
from . import defaults


class AppConfig(BaseModel):
    """Typed application configuration."""

    model_config = {"extra": "ignore"}

    provider: str = Field(default=defaults.PROVIDER_DEEPSEEK)
    model: str = Field(default="", description="Empty means use the provider default")
    mode: str = Field(default=defaults.MODE_PASSIVE)
    timeout: float = Field(default=defaults.DEFAULT_TIMEOUT, gt=0)
    max_retries: int = Field(default=defaults.DEFAULT_MAX_RETRIES, ge=0, le=10)
    temperature: float = Field(default=defaults.DEFAULT_TEMPERATURE, ge=0, le=2)
    max_tokens: int = Field(default=defaults.DEFAULT_MAX_TOKENS, ge=1)
    stream: bool = Field(default=True)

    # DeepSeek (primary provider)
    deepseek_api_key: str = Field(default="")
    deepseek_base_url: str = Field(default=defaults.DEEPSEEK_BASE_URL)
    deepseek_model: str = Field(default=defaults.DEEPSEEK_MODEL)

    # Ollama (local)
    ollama_api_key: str = Field(default="")
    ollama_base_url: str = Field(default=defaults.OLLAMA_BASE_URL)
    ollama_model: str = Field(default=defaults.OLLAMA_MODEL)

    # OpenAI-compatible
    openai_api_key: str = Field(default="")
    openai_base_url: str = Field(default=defaults.OPENAI_BASE_URL)
    openai_model: str = Field(default=defaults.OPENAI_MODEL)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        if v not in defaults.VALID_PROVIDERS:
            raise ValueError(f"unknown provider {v!r}; use one of {defaults.VALID_PROVIDERS}")
        return v

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        if v not in defaults.VALID_MODES:
            raise ValueError(f"unknown mode {v!r}; use one of {defaults.VALID_MODES}")
        return v

    # --- derived accessors -------------------------------------------------
    @property
    def effective_model(self) -> str:
        """The model for the active provider, honouring any explicit override."""
        return self.model or getattr(self, f"{self.provider}_model")

    @property
    def effective_base_url(self) -> str:
        return getattr(self, f"{self.provider}_base_url")

    def api_key_for(self, provider: str | None = None) -> str:
        return getattr(self, f"{provider or self.provider}_api_key", "")

    def set_api_key(self, key: str, provider: str | None = None) -> None:
        setattr(self, f"{provider or self.provider}_api_key", key.strip())

    @property
    def secret_fields(self) -> set[str]:
        return {name for name in type(self).model_fields if "api_key" in name}


class ConfigManager:
    """Owns the on-disk location of config, targets, sessions and reports."""

    def __init__(self, config_dir: Path | None = None) -> None:
        self.config_dir = config_dir or config_home()
        self.config_path = self.config_dir / defaults.CONFIG_FILE
        self.targets_path = self.config_dir / defaults.TARGETS_FILE
        self.sessions_dir = self.config_dir / defaults.SESSIONS_DIR
        self.reports_dir = state_home() / defaults.REPORTS_DIR

    # --- load / save -------------------------------------------------------
    def load(self) -> AppConfig:
        """Load config from disk, merged over defaults, then env overrides."""
        ensure_dir(self.config_dir)
        cfg = AppConfig()
        if self.config_path.exists():
            try:
                raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
                if isinstance(raw, dict):
                    cfg = AppConfig(**raw)
            except (yaml.YAMLError, ValueError) as exc:
                # A corrupt config should not brick the CLI.
                raise RuntimeError(f"invalid config at {self.config_path}: {exc}") from exc

        if env_provider := os.environ.get("FARIID_SEC_PROVIDER"):
            cfg.provider = env_provider
        if env_mode := os.environ.get(defaults.ENV_MODE):
            cfg.mode = env_mode
        return cfg

    def save(self, cfg: AppConfig) -> None:
        ensure_dir(self.config_dir)
        data = json.loads(cfg.model_dump_json())
        atomic_write_text(self.config_path, yaml.safe_dump(data, sort_keys=False))

    # --- typed get / set ---------------------------------------------------
    def get(self, key: str) -> Any:
        cfg = self.load()
        if key not in type(cfg).model_fields:
            raise KeyError(f"unknown config key: {key}")
        return getattr(cfg, key)

    def set(self, key: str, value: Any) -> AppConfig:
        cfg = self.load()
        if key not in type(cfg).model_fields:
            raise KeyError(f"unknown config key: {key}")
        updated = cfg.model_copy(update={key: value})
        self.save(updated)
        return updated

    # --- api key convenience ----------------------------------------------
    def set_api_key(self, value: str, provider: str | None = None) -> AppConfig:
        cfg = self.load()
        cfg.set_api_key(value, provider)
        self.save(cfg)
        return cfg

    def api_key_for(self, provider: str | None = None) -> str:
        return self.load().api_key_for(provider)

    # --- display helpers ---------------------------------------------------
    @staticmethod
    def public_view(cfg: AppConfig) -> dict[str, Any]:
        """A dict safe to print, with secrets masked."""
        data = json.loads(cfg.model_dump_json())
        for field in cfg.secret_fields:
            data[field] = mask_secret(data.get(field) or "")
        return data
