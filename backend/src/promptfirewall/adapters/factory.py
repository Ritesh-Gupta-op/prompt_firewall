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

    effective_settings = resolve_model_settings(settings or Settings())
    provider = effective_settings.model_provider
    if provider == "mock":
        return MockAdapter(model_name=effective_settings.model_name)

    api_key = (
        effective_settings.model_api_key.get_secret_value()
        if effective_settings.model_api_key is not None
        else None
    )
    base_url = effective_settings.model_base_url
    assert base_url is not None  # Validated without constructing a client below.
    if provider == "anthropic":
        return AnthropicAdapter(
            base_url=base_url,
            api_key=api_key,
            model=effective_settings.model_name,
            client=client,
            timeout_seconds=effective_settings.model_timeout_seconds,
            max_retries=effective_settings.model_max_retries,
            retry_backoff_seconds=effective_settings.model_retry_backoff_seconds,
        )
    return OpenAICompatibleAdapter(
        base_url=base_url,
        provider=provider,
        api_key=api_key,
        model=effective_settings.model_name,
        client=client,
        timeout_seconds=effective_settings.model_timeout_seconds,
        max_retries=effective_settings.model_max_retries,
        retry_backoff_seconds=effective_settings.model_retry_backoff_seconds,
    )


def resolve_model_settings(settings: Settings) -> Settings:
    """Resolve and validate selection without allocating loop-bound HTTP resources."""

    provider = settings.model_provider.strip().casefold()
    provider = {
        "deterministic": "mock",
        "github_models": "github-models",
        "openai_compatible": "openai-compatible",
    }.get(provider, provider)
    if provider not in {*_OPENAI_COMPATIBLE_PROVIDERS, "anthropic", "openai-compatible", "mock"}:
        raise AdapterConfigurationError("unsupported model provider", provider="unknown")
    model_name = settings.model_name
    if provider != "mock" and model_name == "promptfirewall-mock-1":
        model_name = DEFAULT_MODEL_NAMES.get(provider, "")
    if not model_name.strip():
        raise AdapterConfigurationError("model name is required", provider=provider)
    base_url = settings.model_base_url
    if provider != "mock":
        base_url = base_url if base_url is not None else DEFAULT_BASE_URLS.get(provider)
        try:
            url = httpx.URL(base_url or "")
            valid_url = url.scheme in {"http", "https"} and bool(url.host)
        except httpx.InvalidURL:
            valid_url = False
        if not valid_url:
            raise AdapterConfigurationError("valid model base URL is required", provider=provider)
        if settings.model_api_key is None or not settings.model_api_key.get_secret_value().strip():
            raise AdapterConfigurationError("model API key is required", provider=provider)
    return settings.model_copy(
        deep=True,
        update={"model_provider": provider, "model_name": model_name, "model_base_url": base_url},
    )


get_model_adapter = create_model_adapter


__all__ = [
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODEL_NAMES",
    "create_model_adapter",
    "get_model_adapter",
]
