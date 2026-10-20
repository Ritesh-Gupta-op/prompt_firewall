"""Keep the complete suite offline and independent of private local configuration."""

from __future__ import annotations

import os

import httpx
import pytest

from promptfirewall.config import Settings


def pytest_configure() -> None:
    # Runs before test-module imports, including main.py's application factory.
    # Never open a developer's .env or connect to their configured database/model.
    Settings.model_config["env_file"] = None
    for key in tuple(os.environ):
        if key.startswith(("MODEL_", "PROMPTFIREWALL_")):
            os.environ.pop(key)
    os.environ["MODEL_PROVIDER"] = "mock"
    os.environ["PROMPTFIREWALL_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
def forbid_network_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> httpx.Response:
        raise AssertionError("offline tests require an in-process or mock HTTP transport")

    async def blocked_async(*args: object, **kwargs: object) -> httpx.Response:
        return blocked(*args, **kwargs)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", blocked)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", blocked_async)
