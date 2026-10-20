"""Anthropic Messages API model adapter."""

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


class AnthropicAdapter(HTTPAdapterMixin):
    """Adapter for Anthropic's ``POST /v1/messages`` endpoint."""

    provider = "anthropic"

    def __init__(
        self,
        base_url: str = "https://api.anthropic.com",
        api_key: str | None = None,
        model: str = "claude-3-5-sonnet-20241022",
        *,
        client: httpx.AsyncClient | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.2,
        anthropic_version: str = "2023-06-01",
        structured_json_tool_fallback: bool = True,
    ) -> None:
        if not base_url.strip():
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
        self.base_url = base_url.strip().rstrip("/")
        self.api_key = api_key
        self.model = model
        self.anthropic_version = anthropic_version
        self.structured_json_tool_fallback = structured_json_tool_fallback
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
        # Anthropic's Messages API does not expose a seed parameter. Validate it
        # at the common interface, but never send an unsupported provider field.
        validate_generation_parameters(
            temperature=temperature,
            seed=seed,
            max_tokens=max_tokens,
            provider=self.provider,
        )
        if temperature > 1:
            raise AdapterConfigurationError(
                "anthropic temperature must be between 0 and 1", provider=self.provider
            )
        normalized_messages = coerce_messages(messages)
        normalized_tools = coerce_tools(tools, provider=self.provider)
        system_parts = [
            message.content for message in normalized_messages if message.role == "system"
        ]
        provider_messages = self._messages_payload(normalized_messages)
        if not provider_messages:
            raise AdapterConfigurationError(
                "anthropic requires at least one user or assistant message",
                provider=self.provider,
            )
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": provider_messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if normalized_tools:
            payload["tools"] = [self._tool_payload(tool) for tool in normalized_tools]

        started = generation_started()
        result = await self._post_json(
            url=endpoint_url(self.base_url, "v1/messages"),
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": self.anthropic_version,
                "Content-Type": "application/json",
            },
            payload=payload,
        )
        return self._response(result, elapsed_ms(started))

    def _response(self, result: Mapping[str, Any], latency_ms: float) -> ModelResponse:
        content = result.get("content")
        if not isinstance(content, list):
            raise AdapterResponseError(
                "anthropic returned invalid content",
                provider=self.provider,
            )
        text_parts: list[str] = []
        tool_calls: list[ProposedToolCall] = []
        for index, block in enumerate(content):
            if not isinstance(block, Mapping):
                raise AdapterResponseError(
                    "anthropic returned an invalid content block",
                    provider=self.provider,
                )
            block_type = block.get("type")
            if block_type == "text":
                text_parts.append(content_to_text(block.get("text")))
            elif block_type == "tool_use":
                name = block.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise AdapterResponseError(
                        "anthropic returned an invalid tool call",
                        provider=self.provider,
                    )
                call_id = block.get("id")
                tool_calls.append(
                    ProposedToolCall(
                        name=name,
                        arguments=parse_tool_arguments(block.get("input"), provider=self.provider),
                        call_id=(
                            call_id
                            if isinstance(call_id, str) and call_id
                            else f"anthropic-call-{index + 1}"
                        ),
                    )
                )
        text = "".join(text_parts)
        if not tool_calls and self.structured_json_tool_fallback and text:
            fallback = parse_structured_tool_fallback(text, provider=self.provider)
            if fallback is not None:
                text, tool_calls = fallback
        usage = result.get("usage")
        usage_data = usage if isinstance(usage, Mapping) else {}
        stop_reason = result.get("stop_reason")
        finish_reason = stop_reason if isinstance(stop_reason, str) and stop_reason else "stop"
        response_id = result.get("id")
        return ModelResponse(
            text=text,
            tool_calls=tool_calls,
            provider=self.provider,
            model=self.model,
            input_tokens=optional_int(usage_data.get("input_tokens")),
            output_tokens=optional_int(usage_data.get("output_tokens")),
            finish_reason=finish_reason,
            latency_ms=latency_ms,
            provider_request_id=response_id if isinstance(response_id, str) else None,
        )

    @staticmethod
    def _messages_payload(messages: Sequence[ModelMessage]) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for message in messages:
            if message.role == "system":
                continue
            role = message.role if message.role in {"user", "assistant"} else "user"
            if result and result[-1]["role"] == role:
                result[-1]["content"] += f"\n{message.content}"
            else:
                result.append({"role": role, "content": message.content})
        return result

    @staticmethod
    def _tool_payload(tool: ToolDefinition) -> dict[str, Any]:
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.parameters or {"type": "object", "properties": {}},
        }


__all__ = ["AnthropicAdapter"]
