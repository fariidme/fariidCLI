"""Default configuration values and environment variable names."""

from __future__ import annotations

# Providers
PROVIDER_DEEPSEEK = "deepseek"
PROVIDER_OLLAMA = "ollama"
PROVIDER_OPENAI = "openai"
VALID_PROVIDERS = (PROVIDER_DEEPSEEK, PROVIDER_OLLAMA, PROVIDER_OPENAI)

# DeepSeek (primary)
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3"

# OpenAI-compatible
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_MODEL = "gpt-4o-mini"

# Execution modes
MODE_PASSIVE = "passive"
MODE_ACTIVE = "active"
MODE_LAB = "lab"
VALID_MODES = (MODE_PASSIVE, MODE_ACTIVE, MODE_LAB)

# Network defaults
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_TEMPERATURE = 0.7
DEFAULT_MAX_TOKENS = 4096

# Environment variables
ENV_DEEPSEEK_API_KEY = "DEEPSEEK_API_KEY"
ENV_DEEPSEEK_BASE_URL = "DEEPSEEK_BASE_URL"
ENV_DEEPSEEK_MODEL = "DEEPSEEK_MODEL"
ENV_OLLAMA_BASE_URL = "OLLAMA_BASE_URL"
ENV_OLLAMA_MODEL = "OLLAMA_MODEL"
ENV_OPENAI_API_KEY = "OPENAI_API_KEY"
ENV_OPENAI_BASE_URL = "OPENAI_BASE_URL"
ENV_OPENAI_MODEL = "OPENAI_MODEL"
ENV_MODE = "FARIID_SEC_MODE"

# File names
CONFIG_FILE = "config.yaml"
TARGETS_FILE = "targets.yaml"
SESSIONS_DIR = "sessions"
REPORTS_DIR = "reports"
TOOL_CATALOG_FILE = "catalog.yaml"
