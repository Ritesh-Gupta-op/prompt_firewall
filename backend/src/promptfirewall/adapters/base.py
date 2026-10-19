"""Shared contracts, HTTP plumbing, and safe errors for model adapters."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from time import perf_counter
from typing import Any, Protocol, runtime_checkable

import httpx

from promptfirewall.contracts.models import ModelMessage, ModelResponse, ProposedToolCall, ToolDefinition

MessageInput = ModelMessage | Mapping[str, Any]
ToolInput = ToolDefinition | Mapping[str, Any]


@runtime_checkable
class ModelAdapter(Protocol):
    """Async provider-neutral model interface.

    The protocol deliberately accepts the application's typed message and tool
    contracts.  Concrete adapters also accept mapping-shaped values so callers
    at an HTTP or serialization boundary can pass validated JSON directly.
    """

    async def generate(
        self,
        messages: Sequence[ModelMessage],
        tools: Sequence[ToolDefinition],
        temperature: float,
        seed: int,
        max_tokens: int,
    ) -> ModelResponse:
        """Generate one response without exposing provider-specific objects."""


class AdapterError(RuntimeError):
    """Base class for safe, provider-facing adapter failures.

    Error messages contain only stable classifications and HTTP status codes;
    provider response bodies and request headers are intentionally excluded.
    """

    code = "adapter_error"

    def __init__(
        self,
        message: str,
        *,
        provider: str,
        retryable: bool = False,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.retryable = retryable
        self.status_code = status_code
        self.safe_message = message

    @property
    def error_code(self) -> str:
        """Stable machine-readable error classification."""

        return self.code


class AdapterConfigurationError(AdapterError):
    code = "configuration_error"


class AdapterAuthenticationError(AdapterError):
    code = "authentication_error"


class AdapterRateLimitError(AdapterError):
    code = "rate_limit_error"


class AdapterTimeoutError(AdapterError):
    code = "timeout_error"


class AdapterTransportError(AdapterError):
    code = "transport_error"


class AdapterUnavailableError(AdapterError):
    code = "provider_unavailable"


class AdapterResponseError(AdapterError):
    code = "invalid_provider_response"


def classify_adapter_error(error: BaseException, *, provider: str = "unknown") -> AdapterError:
    """Convert an arbitrary adapter/infrastructure exception to a safe error.

    This function is intentionally conservative: it never copies exception
    strings from HTTP clients because those strings can contain URLs, headers,
    or provider response data.
    """

    if isinstance(error, AdapterError):
        return error
    if isinstance(error, httpx.TimeoutException):
        return AdapterTimeoutError(
            f"{provider} request timed out",
            provider=provider,
            retryable=True,
        )
    if isinstance(error, httpx.RequestError):
        return AdapterTransportError(
            f"{provider} request failed",
            provider=provider,
            retryable=True,
        )
    if isinstance(error, httpx.HTTPStatusError):
        return classify_http_status(error.response.status_code, provider=provider)
    if isinstance(error, (json.JSONDecodeError, KeyError, TypeError, ValueError)):
        return AdapterResponseError(
            f"{provider} returned an invalid response",
            provider=provider,
        )
    return AdapterTransportError(
        f"{provider} adapter failed",
        provider=provider,
        retryable=False,
    )


def classify_http_status(status_code: int, *, provider: str) -> AdapterError:
    """Classify an HTTP status without retaining the response body."""

    if status_code in {401, 403}:
        return AdapterAuthenticationError(
            f"{provider} rejected authentication (HTTP {status_code})",
            provider=provider,
            status_code=status_code,
        )
    if status_code == 429:
        return AdapterRateLimitError(
            f"{provider} rate limit reached (HTTP 429)",
            provider=provider,
            retryable=True,
            status_code=status_code,
        )
    if status_code in {408, 504}:
        return AdapterTimeoutError(
            f"{provider} request timed out (HTTP {status_code})",
            provider=provider,
            retryable=True,
            status_code=status_code,
        )
    if status_code >= 500:
        return AdapterUnavailableError(
            f"{provider} is unavailable (HTTP {status_code})",
            provider=provider,
            retryable=True,
            status_code=status_code,
        )
    return AdapterResponseError(
        f"{provider} rejected the request (HTTP {status_code})",
        provider=provider,
        status_code=status_code,
    )


class HTTPAdapterMixin:
    """Small shared async HTTP implementation used by provider adapters."""

    provider: str

    def _init_http(
        self,
        *,
        client: httpx.AsyncClient | None,
        timeout_seconds: float,
        max_retries: int,
        retry_backoff_seconds: float,
    ) -> None:
        if timeout_seconds <= 0:
            raise AdapterConfigurationError(
                "adapter timeout must be greater than zero",
                provider=self.provider,
            )
        if max_retries < 0:
            raise AdapterConfigurationError(
                "adapter retry count cannot be negative",
                provider=self.provider,
            )
        if retry_backoff_seconds < 0:
            raise AdapterConfigurationError(
                "adapter retry backoff cannot be negative",
                provider=self.provider,
            )
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def _post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.post(
                    url,
                    headers=dict(headers),
                    json=dict(payload),
                    timeout=self.timeout_seconds,
                )
            except Exception as error:
                classified = classify_adapter_error(error, provider=self.provider)
                if classified.retryable and attempt < self.max_retries:
                    await self._retry_sleep(attempt)
                    continue
                raise classified from error

            if response.status_code >= 400:
                classified = classify_http_status(response.status_code, provider=self.provider)
                if classified.retryable and attempt < self.max_retries:
                    await self._retry_sleep(attempt)
                    continue
                raise classified

            try:
                result = response.json()
            except (json.JSONDecodeError, ValueError) as error:
                raise AdapterResponseError(
                    f"{self.provider} returned invalid JSON",
                    provider=self.provider,
                ) from error
            if not isinstance(result, dict):
                raise AdapterResponseError(
                    f"{self.provider} returned an invalid response",
                    provider=self.provider,
                )
            return result

        raise AdapterTransportError(
            f"{self.provider} adapter failed",
            provider=self.provider,
        )

    async def _retry_sleep(self, attempt: int) -> None:
        delay = self.retry_backoff_seconds * (2**attempt)
        if delay:
            await asyncio.sleep(delay)

    async def aclose(self) -> None:
        """Close a client created by the adapter, leaving injected clients open."""

        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()


def coerce_messages(messages: Sequence[MessageInput]) -> list[ModelMessage]:
    """Validate message-shaped inputs using the existing Pydantic contract."""

    return [
        item if isinstance(item, ModelMessage) else ModelMessage.model_validate(item)
        for item in messages
    ]


def coerce_tools(tools: Sequence[ToolInput]) -> list[ToolDefinition]:
    """Validate tool-shaped inputs using the existing Pydantic contract."""

    return [
        item if isinstance(item, ToolDefinition) else ToolDefinition.model_validate(item)
        for item in tools
    ]


def validate_generation_parameters(
    *,
    temperature: float,
    max_tokens: int,
    provider: str,
) -> None:
    if not 0 <= temperature <= 2:
        raise AdapterConfigurationError(
            "temperature must be between 0 and 2",
            provider=provider,
        )
    if max_tokens <= 0:
        raise AdapterConfigurationError(
            "max_tokens must be greater than zero",
            provider=provider,
        )


def endpoint_url(base_url: str, path: str) -> str:
    """Append a provider path while accepting a base URL with that path already."""

    base = base_url.strip().rstrip("/")
    if not base:
        raise ValueError("base URL cannot be empty")
    normalized_path = path.strip("/")
    if base.endswith(f"/{normalized_path}"):
        return base
    return f"{base}/{normalized_path}"


def content_to_text(content: Any) -> str:
    """Normalize provider content parts to the existing text response field."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                value = item.get("text") or item.get("content")
                if isinstance(value, str):
                    parts.append(value)
        return "".join(parts)
    return ""


def optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_tool_arguments(raw: Any, *, provider: str) -> dict[str, Any]:
    """Normalize native or JSON-encoded tool arguments to a dictionary."""

    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise AdapterResponseError(
            f"{provider} returned invalid tool-call arguments",
            provider=provider,
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AdapterResponseError(
            f"{provider} returned invalid tool-call arguments",
            provider=provider,
        ) from error
    if not isinstance(parsed, dict):
        raise AdapterResponseError(
            f"{provider} returned invalid tool-call arguments",
            provider=provider,
        )
    return parsed


def parse_structured_tool_fallback(
    text: str,
    *,
    provider: str,
) -> tuple[str, list[ProposedToolCall]] | None:
    """Parse the portable JSON tool-call format used when native calls are absent.

    Accepted shape::

        {"text": "optional text", "tool_calls": [{"name": "...", "arguments": {}}]}

    The parser also accepts OpenAI-shaped ``function`` objects and fenced JSON,
    which makes it useful with providers that ignore native tool metadata.
    """

    candidate = text.strip()
    if candidate.startswith("```") and candidate.endswith("```"):
        candidate = candidate[3:-3].strip()
        if candidate.casefold().startswith("json"):
            candidate = candidate[4:].lstrip()
    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    raw_calls = parsed.get("tool_calls")
    if not isinstance(raw_calls, list) or not raw_calls:
        return None

    calls: list[ProposedToolCall] = []
    for index, raw_call in enumerate(raw_calls):
        if not isinstance(raw_call, Mapping):
            raise AdapterResponseError(
                f"{provider} returned an invalid structured tool call",
                provider=provider,
            )
        function = raw_call.get("function")
        function_data = function if isinstance(function, Mapping) else raw_call
        name = function_data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AdapterResponseError(
                f"{provider} returned an invalid structured tool call",
                provider=provider,
            )
        arguments = parse_tool_arguments(
            function_data.get("arguments", function_data.get("input")),
            provider=provider,
        )
        call_id = raw_call.get("call_id") or raw_call.get("id")
        calls.append(
            ProposedToolCall(
                name=name,
                arguments=arguments,
                call_id=call_id if isinstance(call_id, str) and call_id else f"fallback-call-{index + 1}",
            )
        )
    response_text = parsed.get("text", "")
    return (response_text if isinstance(response_text, str) else "", calls)


def generation_started() -> float:
    return perf_counter()


def elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000, 3)


__all__ = [
    "AdapterAuthenticationError",
    "AdapterConfigurationError",
    "AdapterError",
    "AdapterRateLimitError",
    "AdapterResponseError",
    "AdapterTimeoutError",
    "AdapterTransportError",
    "AdapterUnavailableError",
    "MessageInput",
    "ModelAdapter",
    "ToolInput",
    "classify_adapter_error",
    "classify_http_status",
]
