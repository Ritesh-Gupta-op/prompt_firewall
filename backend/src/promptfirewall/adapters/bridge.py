"""Synchronous provider entry point for threaded victim and runner callers."""

from __future__ import annotations

import asyncio

from promptfirewall.config import Settings
from promptfirewall.contracts.models import ModelMessage, ModelRequest, ModelResponse, SyncModel
from promptfirewall.victim_app.model import DeterministicMockModel

from .base import AdapterConfigurationError, classify_adapter_error, validate_generation_parameters
from .factory import create_model_adapter, resolve_model_settings


class ProviderSyncModel:
    """Share configuration across threads, never an adapter, event loop, or client.

    Each completion creates, uses, and closes its async adapter on one fresh loop.
    Async callers must use ``asyncio.to_thread(model.complete, request)``. Explicit
    request timeouts override settings and bound generation including retries.
    Temperature/seed default to settings/factory values unless present in parameters.
    """

    def __init__(self, settings: Settings, *, seed: int = 7) -> None:
        self._settings = resolve_model_settings(settings)
        self.model_name = self._settings.model_name
        self._seed = seed

    def complete(self, request: ModelRequest) -> ModelResponse:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise AdapterConfigurationError(
                "synchronous provider calls require a worker thread; use asyncio.to_thread",
                provider=self._settings.model_provider,
            )
        try:
            return asyncio.run(self._complete(request))
        except Exception as error:
            raise classify_adapter_error(error, provider=self._settings.model_provider) from None

    async def _complete(self, request: ModelRequest) -> ModelResponse:
        temperature = request.parameters.get("temperature", self._settings.model_temperature)
        seed = request.parameters.get("seed", self._seed)
        validate_generation_parameters(
            temperature=temperature,
            seed=seed,
            max_tokens=request.max_tokens,
            provider=self._settings.model_provider,
        )
        timeout = (
            request.timeout_seconds
            if "timeout_seconds" in request.model_fields_set
            else self._settings.model_timeout_seconds
        )
        settings = self._settings.model_copy(update={"model_timeout_seconds": timeout})
        messages = [
            ModelMessage(role="system", content=request.system_instructions),
            *request.messages,
        ]
        adapter = create_model_adapter(settings)
        try:
            async with asyncio.timeout(timeout):
                response = await adapter.generate(
                    messages=messages,
                    tools=request.tools,
                    temperature=temperature,
                    seed=seed,
                    max_tokens=request.max_tokens,
                )
        except BaseException:
            # A shutdown failure must not mask the original classified provider
            # error (or cancellation). Still attempt cleanup on this same loop.
            try:
                await adapter.aclose()
            except Exception:
                pass
            raise
        else:
            await adapter.aclose()
            return response


def create_sync_model(
    settings: Settings | None = None,
    *,
    provider: str | None = None,
    model_name: str | None = None,
    seed: int = 7,
) -> SyncModel:
    """Select a model explicitly; the default mock is entirely offline.

    Overrides take precedence over settings. Invalid/missing provider configuration
    raises a safe ``AdapterConfigurationError`` and never falls back to mock.
    Construction does not allocate an HTTP client or contact a provider.
    """

    effective = (settings or Settings()).model_copy(deep=True)
    if provider is not None:
        effective.model_provider = provider
    if model_name is not None:
        effective.model_name = model_name
    effective = resolve_model_settings(effective)
    if effective.model_provider == "mock":
        return DeterministicMockModel(seed=seed, model_name=effective.model_name)
    return ProviderSyncModel(effective, seed=seed)


__all__ = ["ProviderSyncModel", "create_sync_model"]
