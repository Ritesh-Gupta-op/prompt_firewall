"""Offline provider tests: no credentials, environment configuration, or real HTTP."""

import httpx
import pytest

from promptfirewall.config import Settings
from promptfirewall.contracts.models import ModelMessage, ModelRequest
from promptfirewall.victim_app.tools import SandboxedMockTools


@pytest.fixture(autouse=True)
def forbid_real_http(monkeypatch: pytest.MonkeyPatch) -> None:
    async def blocked(*args: object, **kwargs: object) -> httpx.Response:
        raise AssertionError("provider tests must use an offline HTTP mock transport")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", blocked)


@pytest.fixture
def settings() -> Settings:
    # Supply every model setting explicitly so developer .env/credentials cannot leak in.
    return Settings(
        _env_file=None,
        MODEL_PROVIDER="mock",
        MODEL_NAME="promptfirewall-mock-1",
        MODEL_BASE_URL=None,
        MODEL_API_KEY=None,
        MODEL_TEMPERATURE=0.25,
        MODEL_TIMEOUT_SECONDS=3.0,
        MODEL_MAX_RETRIES=2,
        MODEL_RETRY_BACKOFF_SECONDS=0.0,
    )


@pytest.fixture
def model_request() -> ModelRequest:
    return ModelRequest(
        system_instructions="Trusted system instruction.",
        messages=[
            ModelMessage(role="context", content="Untrusted retrieved context."),
            ModelMessage(role="memory", content="Untrusted memory."),
            ModelMessage(role="assistant", content="Prior assistant reply."),
            ModelMessage(role="user", content="What are the support hours?"),
        ],
        tools=list(SandboxedMockTools.tool_definitions()),
        correlation_id="offline-provider-test",
    )
