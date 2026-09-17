"""Provider factory: build the active :class:`AIProvider` from config + env."""

from __future__ import annotations

import os
from typing import Any

from ..config import defaults
from ..config.manager import AppConfig
from .base import AIProvider, ProviderConfig
from .deepseek import DeepSeekProvider
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider


def resolve_provider_config(
    cfg: AppConfig, provider: str | None = None, model: str | None = None
) -> ProviderConfig:
    """Resolve a :class:`ProviderConfig` for the given (or active) provider."""
    name = provider or cfg.provider
    common: dict[str, Any] = {
        "timeout": cfg.timeout,
        "max_retries": cfg.max_retries,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
    }

    if name == defaults.PROVIDER_DEEPSEEK:
        return ProviderConfig(
            api_key=os.environ.get(defaults.ENV_DEEPSEEK_API_KEY) or cfg.deepseek_api_key or None,
            base_url=os.environ.get(defaults.ENV_DEEPSEEK_BASE_URL) or cfg.deepseek_base_url,
            model=model
            or os.environ.get(defaults.ENV_DEEPSEEK_MODEL)
            or cfg.effective_model
            or cfg.deepseek_model,
            **common,
        )
    if name == defaults.PROVIDER_OLLAMA:
        return ProviderConfig(
            api_key=cfg.ollama_api_key or None,
            base_url=os.environ.get(defaults.ENV_OLLAMA_BASE_URL) or cfg.ollama_base_url,
            model=model
            or os.environ.get(defaults.ENV_OLLAMA_MODEL)
            or cfg.effective_model
            or cfg.ollama_model,
            **common,
        )
    if name == defaults.PROVIDER_OPENAI:
        return ProviderConfig(
            api_key=os.environ.get(defaults.ENV_OPENAI_API_KEY) or cfg.openai_api_key or None,
            base_url=os.environ.get(defaults.ENV_OPENAI_BASE_URL) or cfg.openai_base_url,
            model=model
            or os.environ.get(defaults.ENV_OPENAI_MODEL)
            or cfg.effective_model
            or cfg.openai_model,
            **common,
        )
    raise ValueError(f"unknown provider {name!r}")


def create_provider(
    cfg: AppConfig, provider: str | None = None, model: str | None = None
) -> AIProvider:
    """Instantiate the active provider."""
    name = provider or cfg.provider
    pcfg = resolve_provider_config(cfg, provider, model)
    if name == defaults.PROVIDER_DEEPSEEK:
        return DeepSeekProvider(pcfg)
    if name == defaults.PROVIDER_OLLAMA:
        return OllamaProvider(pcfg)
    if name == defaults.PROVIDER_OPENAI:
        return OpenAICompatibleProvider(pcfg)
    raise ValueError(f"unknown provider {name!r}")
