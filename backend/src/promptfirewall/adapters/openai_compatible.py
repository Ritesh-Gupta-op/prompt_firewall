"""Chat Completions adapter for OpenAI-compatible providers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from promptfirewall.contracts.models import (
    ModelMessage,
    ModelResponse,
    ProposedToolCall,
    ToolDefinition,
)

from .base import (
    AdapterConfigurationError,
    AdapterResponseError,
    HTTPAdapterMixin,
    MessageInput,
    ToolInput,
    coerce_messages,
    coerce_tools,
    content_to_text,
    elapsed_ms,
    endpoint_url,
    generation_started,
    optional_int,
    parse_structured_tool_fallback,
    parse_tool_arguments,
    validate_generation_parameters,
)


class OpenAICompatibleAdapter(HTTPAdapterMixin):
    """Adapter for OpenAI-style ``/chat/completions`` APIs.

    The same implementation covers OpenAI, Groq, OpenRouter, GitHub Models,
    Together, and Google's OpenAI-compatible Gemini endpoint.  Provider-specific
    behavior is limited to the configured base URL and response metadata.
    """

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        *,
        provider: str = "openai-compatible",
        client: httpx.AsyncClient | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.2,
        structured_json_tool_fallback: bool = True,
    ) -> None:
        self.provider = provider
        self.base_url = base_url.strip().rstrip("/")
        self.model = model
        self.structured_json_tool_fallback = structured_json_tool_fallback
        if not self.base_url:
            raise AdapterConfigurationError(
                "model base URL is required",
                provider=self.provider,
            )
        if not api_key or not api_key.strip():
            raise AdapterConfigurationError(
                "model API key is required",
                provider=self.provider,
            )
        if not model.strip():
            raise AdapterConfigurationError(
                "model name is required",
                provider=self.provider,
            )
        if client is not None and http_client is not None:
            raise AdapterConfigurationError(
                "provide only one HTTP client",
                provider=self.provider,
            )
        self.api_key = api_key
        self._init_http(
            client=client or http_client,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    async def generate(
        self,
        messages: Sequence[MessageInput],
        tools: Sequence[ToolInput],
        temperature: float,
        seed: int,
        max_tokens: int,
    ) -> ModelResponse:
        validate_generation_parameters(
            temperature=temperature,
            seed=seed,
            max_tokens=max_tokens,
            provider=self.provider,
        )
        normalized_messages = coerce_messages(messages)
        normalized_tools = coerce_tools(tools, provider=self.provider)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [self._message_payload(message) for message in normalized_messages],
            "temperature": temperature,
            "seed": seed,
            "max_tokens": max_tokens,
        }
        if normalized_tools:
            payload["tools"] = [self._tool_payload(tool) for tool in normalized_tools]
            payload["tool_choice"] = "auto"

        started = generation_started()
        result = await self._post_json(
            url=endpoint_url(self.base_url, "chat/completions"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            payload=payload,
        )
        return self._response(result, elapsed_ms(started))

    def _response(self, result: Mapping[str, Any], latency_ms: float) -> ModelResponse:
        choices = result.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
            raise AdapterResponseError(
                f"{self.provider} returned no choices",
                provider=self.provider,
            )
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, Mapping):
            raise AdapterResponseError(
                f"{self.provider} returned an invalid message",
                provider=self.provider,
            )
        text = content_to_text(message.get("content"))
        tool_calls: list[ProposedToolCall] = []
        native_calls = message.get("tool_calls")
        if native_calls is not None:
            if not isinstance(native_calls, list):
                raise AdapterResponseError(
                    f"{self.provider} returned invalid tool calls",
                    provider=self.provider,
                )
            for index, raw_call in enumerate(native_calls):
                tool_calls.append(self._native_tool_call(raw_call, index))
        if not tool_calls and self.structured_json_tool_fallback and text:
            fallback = parse_structured_tool_fallback(text, provider=self.provider)
            if fallback is not None:
                text, tool_calls = fallback

        usage = result.get("usage")
        usage_data = usage if isinstance(usage, Mapping) else {}
        finish_reason = choice.get("finish_reason")
        if not isinstance(finish_reason, str) or not finish_reason:
            finish_reason = "tool_calls" if tool_calls else "stop"
        response_id = result.get("id")
        return ModelResponse(
            text=text,
            tool_calls=tool_calls,
            provider=self.provider,
            model=self.model,
            input_tokens=optional_int(usage_data.get("prompt_tokens")),
            output_tokens=optional_int(usage_data.get("completion_tokens")),
            finish_reason=finish_reason,
            latency_ms=latency_ms,
            provider_request_id=response_id if isinstance(response_id, str) else None,
        )

    def _native_tool_call(self, raw_call: Any, index: int) -> ProposedToolCall:
        if not isinstance(raw_call, Mapping):
            raise AdapterResponseError(
                f"{self.provider} returned an invalid tool call",
                provider=self.provider,
            )
        function = raw_call.get("function")
        if not isinstance(function, Mapping):
            raise AdapterResponseError(
                f"{self.provider} returned an invalid tool call",
                provider=self.provider,
            )
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AdapterResponseError(
                f"{self.provider} returned an invalid tool call",
                provider=self.provider,
            )
        call_id = raw_call.get("id")
        return ProposedToolCall(
            name=name,
            arguments=parse_tool_arguments(function.get("arguments"), provider=self.provider),
            call_id=(
                call_id if isinstance(call_id, str) and call_id else f"provider-call-{index + 1}"
            ),
        )

    @staticmethod
    def _message_payload(message: ModelMessage) -> dict[str, str]:
        # ModelMessage has no native tool_call_id or matching assistant tool call.
        # Treat synthetic tool-output/context/memory deliveries as untrusted user
        # data instead of emitting an invalid provider protocol message.
        if message.role in {"system", "user", "assistant"}:
            return {"role": message.role, "content": message.content}
        return {"role": "user", "content": f"[{message.role} data]\n{message.content}"}

    @staticmethod
    def _tool_payload(tool: ToolDefinition) -> dict[str, Any]:
        parameters = tool.parameters or {"type": "object", "properties": {}}
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": parameters,
            },
        }


__all__ = ["OpenAICompatibleAdapter"]
