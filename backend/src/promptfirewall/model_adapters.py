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
    ProviderSyncModel,
    classify_adapter_error,
    create_model_adapter,
    create_sync_model,
    get_model_adapter,
)
from promptfirewall.contracts.models import SyncModel

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
    "ProviderSyncModel",
    "SyncModel",
    "classify_adapter_error",
    "create_model_adapter",
    "create_sync_model",
    "get_model_adapter",
]
