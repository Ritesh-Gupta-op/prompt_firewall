"""Provider-neutral asynchronous model adapters."""

from .anthropic import AnthropicAdapter
from .base import (
    AdapterAuthenticationError,
    AdapterConfigurationError,
    AdapterError,
    AdapterRateLimitError,
    AdapterResponseError,
    AdapterTimeoutError,
    AdapterTransportError,
    AdapterUnavailableError,
    ModelAdapter,
    classify_adapter_error,
)
from .factory import DEFAULT_BASE_URLS, DEFAULT_MODEL_NAMES, create_model_adapter, get_model_adapter
from .mock import MockAdapter
from .openai_compatible import OpenAICompatibleAdapter

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
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODEL_NAMES",
    "MockAdapter",
    "ModelAdapter",
    "OpenAICompatibleAdapter",
    "classify_adapter_error",
    "create_model_adapter",
    "get_model_adapter",
]
