"""Offline adapter wrapping PromptFirewall's deterministic mock model."""

from __future__ import annotations

from collections.abc import Sequence

from promptfirewall.contracts.models import ModelRequest, ModelResponse
from promptfirewall.victim_app.model import DeterministicMockModel

from .base import (
    MessageInput,
    ModelAdapter,
    ToolInput,
    coerce_messages,
    coerce_tools,
    validate_generation_parameters,
)


class MockAdapter:
    """Async ``ModelAdapter`` facade for deterministic unit and CI execution.

    It never performs network calls.  The wrapped model remains available via
    ``model`` for callers that still use the established synchronous API.
    """

    provider = "mock"
    is_mock = True

    def __init__(
        self,
        model: DeterministicMockModel | None = None,
        *,
        seed: int | None = None,
        model_name: str | None = None,
    ) -> None:
        self.model = model or DeterministicMockModel(
            seed=7 if seed is None else seed,
            model_name=model_name or "promptfirewall-mock-1",
        )
        self.seed = self.model.seed if seed is None else seed
        self.model_name = self.model.model_name if model_name is None else model_name

    async def generate(
        self,
        messages: Sequence[MessageInput],
        tools: Sequence[ToolInput],
        temperature: float,
        seed: int,
        max_tokens: int,
    ) -> ModelResponse:
        validate_generation_parameters(
            temperature=temperature, seed=seed, max_tokens=max_tokens, provider=self.provider
        )
        request = ModelRequest(
            system_instructions="",
            messages=coerce_messages(messages),
            tools=coerce_tools(tools, provider=self.provider),
            parameters={"temperature": temperature, "seed": seed},
            correlation_id="mock-adapter",
            max_tokens=max_tokens,
        )
        model = self.model
        if model.seed != seed or model.model_name != self.model_name:
            model = DeterministicMockModel(seed=seed, model_name=self.model_name)
        return model.complete(request)

    async def aclose(self) -> None:
        """The offline model has no external resources."""


assert isinstance(MockAdapter(), ModelAdapter)


__all__ = ["MockAdapter"]
