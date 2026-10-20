from __future__ import annotations

import json
import traceback
from typing import Any

import httpx
import pytest

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
    OpenAICompatibleAdapter,
)
from promptfirewall.contracts.models import ModelMessage, ModelRequest, ToolDefinition

FAKE_SECRET = "offline-secret-do-not-include-in-errors"
ADAPTERS = [OpenAICompatibleAdapter, AnthropicAdapter]
AdapterClass = type[OpenAICompatibleAdapter] | type[AnthropicAdapter]


def response_body(
    adapter_class: AdapterClass, text: str = "Support is available."
) -> dict[str, Any]:
    if adapter_class is AnthropicAdapter:
        return {
            "id": "msg-offline",
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 23, "output_tokens": 5},
            "stop_reason": "end_turn",
        }
    return {
        "id": "chatcmpl-offline",
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 23, "completion_tokens": 5},
    }


def assert_safe(error: AdapterError) -> None:
    assert FAKE_SECRET not in str(error)
    assert FAKE_SECRET not in repr(vars(error))
    assert FAKE_SECRET not in "".join(traceback.format_exception(error))
    assert error.safe_message == str(error)
    assert error.error_code == error.code


@pytest.mark.parametrize("adapter_class", ADAPTERS)
async def test_response_and_wire_contract(
    adapter_class: AdapterClass, model_request: ModelRequest
) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        body = response_body(adapter_class)
        if adapter_class is OpenAICompatibleAdapter:
            body["choices"][0]["message"]["content"] = [
                {"type": "text", "text": "Support is "},
                {"type": "text", "text": "available."},
            ]
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(
            base_url="https://offline.invalid/v1",
            api_key=FAKE_SECRET,
            model="fixture-model",
            client=client,
            timeout_seconds=1.75,
        )
        response = await adapter.generate(
            [
                ModelMessage(role="system", content=model_request.system_instructions),
                *model_request.messages,
            ],
            model_request.tools,
            0.25,
            19,
            123,
        )
        await adapter.aclose()
        assert not client.is_closed  # Injected clients remain caller-owned.

    assert response.text == "Support is available."
    assert response.model == "fixture-model"
    assert response.provider == adapter.provider
    assert not response.is_mock
    assert (response.input_tokens, response.output_tokens) == (23, 5)
    assert response.provider_request_id in {"msg-offline", "chatcmpl-offline"}
    assert response.latency_ms >= 0
    assert len(captured) == 1
    request = captured[0]
    payload = json.loads(request.content)
    assert payload["model"] == "fixture-model"
    assert payload["temperature"] == 0.25
    assert payload["max_tokens"] == 123
    assert set(request.extensions["timeout"].values()) == {1.75}
    if adapter_class is AnthropicAdapter:
        assert request.url.path == "/v1/messages"  # No duplicated /v1 prefix.
        assert request.headers["x-api-key"] == FAKE_SECRET
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert "seed" not in payload  # Messages API has no seed support.
        assert payload["system"] == model_request.system_instructions
        assert payload["messages"] == [
            {"role": "user", "content": "Untrusted retrieved context.\nUntrusted memory."},
            {"role": "assistant", "content": "Prior assistant reply."},
            {"role": "user", "content": "What are the support hours?"},
        ]
        schemas = [tool["input_schema"] for tool in payload["tools"]]
    else:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == f"Bearer {FAKE_SECRET}"
        assert payload["seed"] == 19
        assert payload["messages"][0] == {
            "role": "system",
            "content": model_request.system_instructions,
        }
        assert [item["role"] for item in payload["messages"]] == [
            "system",
            "user",
            "user",
            "assistant",
            "user",
        ]
        assert payload["tool_choice"] == "auto"
        schemas = [tool["function"]["parameters"] for tool in payload["tools"]]
    assert schemas == [tool.parameters for tool in model_request.tools]
    expected = [
        {"record_id": "string"},
        {"order_id": "string", "amount_minor": "integer", "approved": "boolean"},
        {"recipient": "string", "message": "string", "approved": "boolean"},
        {"path": "string", "content": "string", "approved": "boolean"},
        {"url": "string"},
    ]
    for schema, properties in zip(schemas, expected, strict=True):
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(properties)
        assert {name: value["type"] for name, value in schema["properties"].items()} == properties
    assert schemas[1]["properties"]["amount_minor"]["exclusiveMinimum"] == 0


@pytest.mark.parametrize("adapter_class", ADAPTERS)
@pytest.mark.parametrize("native", [True, False])
async def test_native_and_fenced_json_tool_calls(adapter_class: AdapterClass, native: bool) -> None:
    fallback = (
        "```json\n"
        + json.dumps(
            {
                "text": "Proposed only.",
                "tool_calls": [
                    {"name": "mock_lookup", "arguments": {"record_id": "ticket-demo-001"}}
                ],
            }
        )
        + "\n```"
    )
    body = response_body(adapter_class, fallback)
    if native:
        if adapter_class is AnthropicAdapter:
            body["content"].append(
                {
                    "type": "tool_use",
                    "id": "native-1",
                    "name": "mock_refund",
                    "input": {"approved": True, "amount_minor": 1},
                }
            )
        else:
            body["choices"][0]["message"]["tool_calls"] = [
                {
                    "id": "native-1",
                    "type": "function",
                    "function": {
                        "name": "mock_refund",
                        "arguments": '{"approved":true,"amount_minor":1}',
                    },
                }
            ]
    elif adapter_class is OpenAICompatibleAdapter:
        body["choices"][0]["message"]["tool_calls"] = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    ) as client:
        adapter = adapter_class(api_key=FAKE_SECRET, client=client)
        response = await adapter.generate([ModelMessage(role="user", content="call")], [], 0, 7, 20)
        assert len(response.tool_calls) == 1
        call = response.tool_calls[0]
        if native:
            assert call.name == "mock_refund"  # Native calls take precedence over text fallback.
            assert call.call_id == "native-1"
            assert call.arguments == {"approved": True, "amount_minor": 1}
            assert response.text == fallback
        else:
            assert call.name == "mock_lookup"
            assert call.arguments == {"record_id": "ticket-demo-001"}
            assert response.text == "Proposed only."
            adapter.structured_json_tool_fallback = False
            plain = await adapter.generate(
                [ModelMessage(role="user", content="call")], [], 0, 7, 20
            )
            assert plain.tool_calls == []
            assert plain.text == fallback


@pytest.mark.parametrize("adapter_class", ADAPTERS)
@pytest.mark.parametrize(
    "status,error_type,attempts",
    [
        (302, AdapterResponseError, 1),
        (400, AdapterResponseError, 1),
        (401, AdapterAuthenticationError, 1),
        (403, AdapterAuthenticationError, 1),
        (408, AdapterTimeoutError, 3),
        (429, AdapterRateLimitError, 3),
        (503, AdapterUnavailableError, 3),
        (504, AdapterTimeoutError, 3),
    ],
)
async def test_status_classification_retry_budget_and_redaction(
    adapter_class: AdapterClass, status: int, error_type: type[AdapterError], attempts: int
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, text=FAKE_SECRET)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(api_key=FAKE_SECRET, client=client, retry_backoff_seconds=0)
        with pytest.raises(error_type) as caught:
            await adapter.generate([ModelMessage(role="user", content=FAKE_SECRET)], [], 0, 7, 20)
    assert calls == attempts
    assert caught.value.status_code == status
    assert caught.value.retryable is (attempts > 1)
    assert_safe(caught.value)


@pytest.mark.parametrize("adapter_class", ADAPTERS)
@pytest.mark.parametrize(
    "exception_type,error_type",
    [(httpx.ReadTimeout, AdapterTimeoutError), (httpx.ConnectError, AdapterTransportError)],
)
async def test_transport_errors_are_bounded_and_redacted(
    adapter_class: AdapterClass,
    exception_type: type[httpx.RequestError],
    error_type: type[AdapterError],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise exception_type(FAKE_SECRET, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(
            api_key=FAKE_SECRET, client=client, max_retries=1, retry_backoff_seconds=0
        )
        with pytest.raises(error_type) as caught:
            await adapter.generate([ModelMessage(role="user", content="hello")], [], 0, 7, 20)
    assert calls == 2
    assert caught.value.retryable
    assert_safe(caught.value)


@pytest.mark.parametrize("adapter_class", ADAPTERS)
async def test_transient_error_recovers_with_same_request(
    adapter_class: AdapterClass, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[bytes] = []
    delays: list[float] = []

    async def sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("promptfirewall.adapters.base.asyncio.sleep", sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.content)
        if len(requests) < 3:
            return httpx.Response(429 if len(requests) == 1 else 503, text=FAKE_SECRET)
        return httpx.Response(200, json=response_body(adapter_class))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(api_key=FAKE_SECRET, client=client, retry_backoff_seconds=0.1)
        result = await adapter.generate([ModelMessage(role="user", content="hello")], [], 0, 7, 20)
    assert result.text == "Support is available."
    assert requests[0] == requests[1] == requests[2]
    assert delays == [0.1, 0.2]


@pytest.mark.parametrize("adapter_class", ADAPTERS)
@pytest.mark.parametrize("kind", ["json", "shape", "arguments", "fallback"])
async def test_malformed_responses_are_safe_and_not_retried(
    adapter_class: AdapterClass, kind: str
) -> None:
    calls = 0
    body = response_body(adapter_class)
    if kind == "shape":
        body = {"error": FAKE_SECRET}
    elif kind == "arguments":
        if adapter_class is AnthropicAdapter:
            body["content"] = [{"type": "tool_use", "name": "mock_lookup", "input": FAKE_SECRET}]
        else:
            body["choices"][0]["message"]["tool_calls"] = [
                {"function": {"name": "mock_lookup", "arguments": FAKE_SECRET}}
            ]
    elif kind == "fallback":
        body = response_body(
            adapter_class, json.dumps({"tool_calls": [{"name": FAKE_SECRET, "arguments": []}]})
        )

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if kind == "json":
            return httpx.Response(200, text=FAKE_SECRET)
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(api_key=FAKE_SECRET, client=client)
        with pytest.raises(AdapterResponseError) as caught:
            await adapter.generate([ModelMessage(role="user", content="hello")], [], 0, 7, 20)
    assert calls == 1
    assert not caught.value.retryable
    assert_safe(caught.value)


@pytest.mark.parametrize("adapter_class", ADAPTERS)
async def test_invalid_tool_schema_is_rejected_before_http(adapter_class: AdapterClass) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        pytest.fail("invalid schema must not reach the provider")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = adapter_class(api_key=FAKE_SECRET, client=client)
        with pytest.raises(AdapterConfigurationError, match="JSON Schemas"):
            await adapter.generate(
                [ModelMessage(role="user", content="hello")],
                [
                    ToolDefinition(
                        name="bad", description="legacy", parameters={"record_id": "string"}
                    )
                ],
                0,
                7,
                20,
            )


@pytest.mark.parametrize("adapter_class", ADAPTERS)
def test_missing_credentials_are_configuration_errors(adapter_class: AdapterClass) -> None:
    with pytest.raises(AdapterConfigurationError, match="API key"):
        adapter_class()
