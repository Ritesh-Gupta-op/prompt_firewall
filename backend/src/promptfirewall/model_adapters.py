"""Compatibility facade for PromptFirewall's model adapter layer."""

from promptfirewall.adapters import (
    AdapterAuthenticationError,
    AdapterConfigurationError,
    AdapterError,
    AdapterRateLimitError,
    AdapterResponseError,
    AdapterTimeoutError,
    AdapterTransportError,
    AdapterUnavailableError,
    AnthropicAdapter,
    MockAdapter,
    ModelAdapter,
    OpenAICompatibleAdapter,
    classify_adapter_error,
    create_model_adapter,
    get_model_adapter,
)

__all__ = [
    "AdapterAuthenticationError",
    "AdapterConfigurationError",
    "AdapterError",
    "AdapterRateLimitError",
    "AdapterResponseError",
    "AdapterTimeoutError",
    "AdapterTransportError",
    "AdapterUnavailableError",
    "AnthropicAdapter",
    "MockAdapter",
    "ModelAdapter",
    "OpenAICompatibleAdapter",
    "classify_adapter_error",
    "create_model_adapter",
    "get_model_adapter",
]
