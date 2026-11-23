"""Builds the configured provider and explainer limits from Settings."""

from __future__ import annotations

from ai.adapters.null_adapter import NullProvider
from ai.adapters.openai_compatible import OpenAICompatibleProvider
from ai.explainer import ExplainerLimits
from ai.protocols import LLMProvider
from core.config import Settings


def build_provider(settings: Settings) -> LLMProvider:
    """
    The provider named by AI_PROVIDER. "null" (the default) makes no network
    calls. "openai" requires OPENAI_API_KEY (enforced by Settings, AS-09).
    """
    if settings.ai_provider == "ollama":
        return OpenAICompatibleProvider(
            name="ollama",
            base_url=settings.ollama_base_url.rstrip("/") + "/v1",
            model=settings.ollama_model,
            timeout_seconds=settings.ai_explanation_timeout_seconds,
        )
    if settings.ai_provider == "openai":
        return OpenAICompatibleProvider(
            name="openai",
            base_url=settings.openai_base_url,
            model=settings.openai_model,
            timeout_seconds=settings.ai_explanation_timeout_seconds,
            api_key=settings.openai_api_key,
        )
    return NullProvider()


def explainer_limits(settings: Settings) -> ExplainerLimits:
    return ExplainerLimits(
        timeout_seconds=settings.ai_explanation_timeout_seconds,
        max_attempts=settings.ai_max_attempts,
        max_output_tokens=settings.ai_max_output_tokens,
        max_raw_chars=settings.ai_max_raw_response_chars,
        max_field_chars=settings.ai_max_response_chars,
        max_context_chars=settings.ai_max_context_chars,
    )
