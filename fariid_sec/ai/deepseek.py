"""DeepSeek provider.

DeepSeek's Chat Completions API is OpenAI-compatible and additionally returns
``reasoning_content`` for reasoning models (``deepseek-reasoner``). The base
:class:`OpenAICompatibleProvider` already captures that field, so DeepSeek only
fixes its identity and defaults.
"""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider


class DeepSeekProvider(OpenAICompatibleProvider):
    name = "deepseek"
