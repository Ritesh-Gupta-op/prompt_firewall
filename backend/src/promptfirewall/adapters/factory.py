"""Configuration-driven model adapter selection."""

from __future__ import annotations

from typing import Final

import httpx

from promptfirewall.config import Settings

from .anthropic import AnthropicAdapter
from .base import AdapterConfigurationError, ModelAdapter
from .mock import MockAdapter
from .openai_compatible import OpenAICompatibleAdapter

DEFAULT_BASE_URLS: Final[dict[str, str]] = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "github": "https://models.inference.ai.azure.com",
    "github-models": "https://models.inference.ai.azure.com",
    "together": "https://api.together.xyz/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "anthropic": "https://api.anthropic.com",
}

DEFAULT_MODEL_NAMES: Final[dict[str, str]] = {
    "openai": "gpt-4o-mini",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "openai/gpt-4o-mini",
    "github": "gpt-4o-mini",
    "github-models": "gpt-4o-mini",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "gemini": "gemini-2.0-flash",
    "anthropic": "claude-3-5-sonnet-20241022",
}

_OPENAI_COMPATIBLE_PROVIDERS = frozenset(DEFAULT_BASE_URLS) - {"anthropic"}


def create_model_adapter(
    settings: Settings | None = None,
    *,
    client: httpx.AsyncClient | None = None,
) -> ModelAdapter:
    """Build the configured adapter without making a network request."""

    effective_settings = settings or Settings()
    provider = effective_settings.model_provider.strip().casefold()
    provider = {"github_models": "github-models", "openai_compatible": "openai-compatible"}.get(
        provider, provider
    )
    if provider in {"mock", "deterministic"}:
        return MockAdapter(model_name=effective_settings.model_name)

    api_key = (
        effective_settings.model_api_key.get_secret_value()
        if effective_settings.model_api_key is not None
        else None
    )
    base_url = effective_settings.model_base_url or DEFAULT_BASE_URLS.get(provider)
    model_name = effective_settings.model_name
    if model_name == "promptfirewall-mock-1":
        model_name = DEFAULT_MODEL_NAMES.get(provider, model_name)
    common = {
        "api_key": api_key,
        "model": model_name,
        "client": client,
        "timeout_seconds": effective_settings.model_timeout_seconds,
        "max_retries": effective_settings.model_max_retries,
        "retry_backoff_seconds": effective_settings.model_retry_backoff_seconds,
    }
    if provider in _OPENAI_COMPATIBLE_PROVIDERS or provider == "openai-compatible":
        if base_url is None:
            raise AdapterConfigurationError(
                "model base URL is required for the selected provider",
                provider=provider,
            )
        return OpenAICompatibleAdapter(base_url=base_url, provider=provider, **common)
    if provider == "anthropic":
        return AnthropicAdapter(base_url=base_url or DEFAULT_BASE_URLS["anthropic"], **common)
    raise AdapterConfigurationError(
        f"unsupported model provider: {provider}",
        provider=provider or "unknown",
    )


get_model_adapter = create_model_adapter


__all__ = [
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODEL_NAMES",
    "create_model_adapter",
    "get_model_adapter",
]
