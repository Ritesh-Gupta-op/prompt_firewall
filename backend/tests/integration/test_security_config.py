from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from promptfirewall.api import execution
from promptfirewall.config import Settings
from promptfirewall.contracts.models import ModelMessage, ModelRequest, ModelResponse
from promptfirewall.main import create_app
from promptfirewall.victim_app.model import DeterministicMockModel
from promptfirewall.victim_app.service import VictimService

TEST_KEY = "synthetic-service-key-for-tests"


def test_production_refuses_unauthenticated_startup() -> None:
    with pytest.raises(ValidationError, match="API_KEY is required"):
        Settings(environment="production")
    with pytest.raises(ValidationError):
        Settings(api_key="short")


@pytest.mark.parametrize("path", [
    "/api/runs", "/api/experiments", "/api/catalogs/attacks", "/docs", "/openapi.json",
])
def test_evidence_and_api_docs_require_key_when_configured(path: str) -> None:
    config = Settings(environment="production", api_key=TEST_KEY)
    with TestClient(create_app(config)) as client:
        assert client.get("/health").status_code == 200
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401
        response = client.get(path, headers={"X-API-Key": TEST_KEY})
        assert response.status_code == 200
        assert TEST_KEY not in response.text
        assert client.post("/api/victim/chat", json={"message": "Hello"}).status_code == 401


def test_chat_budget_uses_settings_and_test_run_preserves_session() -> None:
    class RecordingModel(DeterministicMockModel):
        def __init__(self) -> None:
            super().__init__()
            self.requests: list[ModelRequest] = []

        def complete(self, request: ModelRequest) -> ModelResponse:
            self.requests.append(request)
            return super().complete(request)

    model = RecordingModel()
    config = Settings(model_timeout_seconds=3)
    with TestClient(create_app(config, victim_service=VictimService(model=model))) as client:
        assert client.post("/api/victim/chat", json={"message": "Hello"}).status_code == 200
        assert 0 < model.requests[0].timeout_seconds <= 3
        response = client.post("/api/victim/test-run", json={
            "case_kind": "benign", "case_id": "benign-001", "session_id": "chosen-session",
        })
        assert response.status_code == 200
        sessions = [event["payload"]["session_id"] for event in response.json()["trace_events"]
                    if event["event_type"] == "session_initialized"]
        assert sessions == ["chosen-session"]


def test_experiments_default_to_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def factory(settings: Settings, **kwargs: Any) -> DeterministicMockModel:
        calls.append(kwargs)
        return DeterministicMockModel()

    monkeypatch.setattr(execution, "create_sync_model", factory)
    config = Settings(model_provider="openai", model_name="configured-test-model")
    with TestClient(create_app(config, victim_service=VictimService())) as client:
        response = client.post("/api/experiments", json={
            "name": "Configured selection", "benign_case_ids": ["benign-001"],
            "defense_profile_ids": ["full-stack"],
        })
        identifier = response.json()["id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            detail = client.get(f"/api/experiments/{identifier}").json()
            if detail["status"] not in {"queued", "running"}:
                break
            time.sleep(0.01)
        assert detail["status"] == "completed"
        assert calls[0]["provider"] == "openai"
        assert calls[0]["model_name"] == "configured-test-model"


def test_synthetic_tool_output_is_not_an_unpaired_native_tool_message() -> None:
    from promptfirewall.adapters.openai_compatible import OpenAICompatibleAdapter

    payload = OpenAICompatibleAdapter._message_payload(
        ModelMessage(role="tool", content="untrusted synthetic tool result"),
    )
    assert payload == {
        "role": "user", "content": "[tool data]\nuntrusted synthetic tool result",
    }
