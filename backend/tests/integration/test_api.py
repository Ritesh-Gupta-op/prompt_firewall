"""Offline HTTP checks against real SQLite storage and the real execution pipeline."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import Any

import pytest
from fastapi.testclient import TestClient

from promptfirewall.api import execution
from promptfirewall.api.job_manager import InProcessJobManager
from promptfirewall.config import Settings
from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.models import ModelRequest, ModelResponse
from promptfirewall.main import create_app
from promptfirewall.storage.repository import StorageRepository
from promptfirewall.storage.schema import initialize_schema
from promptfirewall.victim_app.model import DeterministicMockModel
from promptfirewall.victim_app.service import VictimService


def settings() -> Settings:
    values: dict[str, Any] = {
        "_env_file": None, "database_url": "sqlite+aiosqlite:///:memory:", "worker_count": 1,
        "MODEL_PROVIDER": "mock", "MODEL_NAME": "promptfirewall-mock-1",
    }
    return Settings(**values)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(settings())) as value:
        yield value


def experiment_payload(**changes: Any) -> dict[str, Any]:
    return {
        "name": "HTTP integration", "attack_ids": ["attack-dpi-001"],
        "defense_profile_ids": ["none", "full-stack"], **changes,
    }


def wait_for_experiment(client: TestClient, identifier: str) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = client.get(f"/api/experiments/{identifier}")
        assert response.status_code == 200, response.text
        record: dict[str, Any] = response.json()
        if record["status"] not in {"queued", "running"}:
            return record
        time.sleep(0.01)
    pytest.fail(f"experiment did not finish: {record}")


class GatedModel(DeterministicMockModel):
    def __init__(self) -> None:
        super().__init__()
        self.entered = Event()
        self.release = Event()

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.entered.set()
        if not self.release.wait(10):
            raise TimeoutError("test gate was not released")
        return super().complete(request)


def test_chat_defaults_to_firewall_and_persists_datetime_traces(client: TestClient) -> None:
    response = client.post("/api/victim/chat", json={
        "message": "What is the warranty policy?", "run_id": "chat-test",
    })
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["response"]["is_mock"] is True
    assert payload["defense_decisions"]
    assert payload["trace_events"]
    detail = client.get("/api/runs/chat-test").json()
    assert detail["run"]["status"] == "completed"
    assert detail["run"]["defense_profile_id"] == "full-stack"
    assert detail["result"]["response"] == payload["response"]
    traces = client.get("/api/runs/chat-test/traces").json()
    assert len(traces) == len(payload["trace_events"])
    assert all(isinstance(event["timestamp"], str) for event in traces)
    assert [event["sequence"] for event in traces] == sorted(
        event["sequence"] for event in traces
    )
    duplicate = client.post("/api/victim/chat", json={
        "message": "What is the warranty policy?", "run_id": "chat-test",
    })
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "duplicate_run_id"


def test_chat_vulnerable_profile_is_explicit(client: TestClient) -> None:
    message = client.get("/api/catalogs/attacks").json()[0]["payload_template"]
    protected = client.post("/api/victim/chat", json={"message": message})
    vulnerable = client.post("/api/victim/chat", json={
        "message": message, "defense_profile_id": "none",
    })
    assert protected.status_code == vulnerable.status_code == 200
    assert protected.json()["blocked"] is True
    assert vulnerable.json()["blocked"] is False


def test_chat_worker_keeps_http_loop_responsive() -> None:
    model = GatedModel()
    with TestClient(create_app(settings(), victim_service=VictimService(model=model))) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.post, "/api/victim/chat", json={
                "message": "What is the warranty policy?", "run_id": "in-flight-chat",
            })
            try:
                assert model.entered.wait(5)
                assert client.get("/health").status_code == 200
                assert client.post("/api/victim/chat", json={
                    "message": "Hello", "run_id": "in-flight-chat",
                }).status_code == 409
            finally:
                model.release.set()
            assert pending.result(timeout=5).status_code == 200


def test_test_run_uses_full_harness_evidence_beyond_input(client: TestClient) -> None:
    response = client.post("/api/victim/test-run", json={
        "case_id": "benign-001", "case_kind": "benign", "defense_profile_id": "full-stack",
        "run_id": "test-harness",
    })
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["run"]["id"] == "test-harness"
    assert result["run"]["experiment_id"] is None
    assert result["run"]["status"] == "completed", result
    assert result["blocked"] is False
    assert result["response"] is not None
    assert result["response"]["text"] == "Ticket ticket-demo-001 status: open."
    assert {"input", "context", "prompt", "output"} <= {
        decision["stage"] for decision in result["defense_decisions"]
    }
    assert result["judge_results"]
    assert result["judge_results"][0]["reason_code"] == "benign_expectations_met"
    detail = client.get("/api/runs/test-harness").json()
    assert detail["result"]["evidence"]
    assert detail["result"]["evidence"]["benign_expectations"]["required_output_substrings"] == [
        "ticket-demo-001", "status: open",
    ]
    assert detail["result"]["state_before"] is not None
    assert detail["result"]["state_after"] is not None
    assert len(detail["trace_events"]) == len(result["trace_events"])
    duplicate = client.post("/api/victim/test-run", json={
        "case_id": "benign-001", "case_kind": "benign", "run_id": "test-harness",
    })
    assert duplicate.status_code == 409


def test_experiment_completion_metrics_and_evidence_reports(client: TestClient) -> None:
    response = client.post("/api/experiments", json=experiment_payload())
    assert response.status_code == 200, response.text
    created = response.json()
    assert created["submitted"] is True
    identifier = created["id"]
    initial_ids = {item["id"] for item in client.get(
        f"/api/experiments/{identifier}/runs",
    ).json()}
    finished = wait_for_experiment(client, identifier)
    assert finished["status"] == "completed", finished
    assert finished["completed_runs"] == 2
    assert finished["remaining_runs"] == 0
    runs = client.get(f"/api/experiments/{identifier}/runs").json()
    assert {run["id"] for run in runs} == initial_ids
    assert len(runs) == 2
    metrics = client.get(f"/api/experiments/{identifier}/metrics").json()
    assert metrics["attack_success_rate"]["numerator"] == 1
    assert metrics["attack_success_rate"]["denominator"] == 2
    report = client.get(f"/api/experiments/{identifier}/report")
    assert report.status_code == 200, report.text
    assert report.json()["metrics"] == metrics
    assert {run["run_id"] for run in report.json()["evidence"]} == initial_ids
    assert all(run["trace_events"] and run["evidence"] for run in report.json()["evidence"])
    markdown = client.get(f"/api/experiments/{identifier}/report.md")
    assert markdown.status_code == 200
    assert "Run evidence" in markdown.text
    assert "## Traces" in markdown.text
    assert all(identifier in markdown.text for identifier in initial_ids)
    # Cancelling a finished job must not rewrite its terminal state or metrics.
    assert client.post(f"/api/experiments/{identifier}/cancel").json()["status"] == "completed"


def test_cancellation_persists_while_worker_finishes_and_queued_job_never_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = GatedModel()
    monkeypatch.setattr(execution, "create_sync_model", lambda *args, **kwargs: model)
    app = create_app(settings())
    with TestClient(app) as client:
        first = client.post("/api/experiments", json=experiment_payload(
            defense_profile_ids=["none"], repetitions=2, concurrency_limit=1,
        )).json()["id"]
        try:
            assert model.entered.wait(5)
            progress = client.get(f"/api/experiments/{first}").json()
            assert progress["status"] == "running"
            assert progress["remaining_runs"] == 2
            second = client.post("/api/experiments", json=experiment_payload()).json()["id"]
            for identifier in (first, second):
                cancelled = client.post(f"/api/experiments/{identifier}/cancel").json()
                assert cancelled["status"] == "cancelled"
                assert cancelled["cancelled_runs"] == 2
                assert cancelled["remaining_runs"] == 0
                assert client.post(f"/api/experiments/{identifier}/cancel").json() == cancelled
            metrics_before = client.get(f"/api/experiments/{first}/metrics").json()
            assert metrics_before["error_rate"]["denominator"] == 0
        finally:
            model.release.set()
        assert client.portal is not None
        client.portal.call(app.state.job_manager._queue.join)
        for identifier in (first, second):
            detail = client.get(f"/api/experiments/{identifier}").json()
            assert detail["status"] == "cancelled"
            assert detail["cancelled_runs"] == 2
            assert all(run["status"] == "cancelled" for run in client.get(
                f"/api/experiments/{identifier}/runs",
            ).json())
        metrics_after = client.get(f"/api/experiments/{first}/metrics").json()
        assert metrics_after == metrics_before
        assert client.get(f"/api/experiments/{first}/report").json()["metrics"] == metrics_after


def test_execution_errors_are_persisted_not_completed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("offline provider failure")

    monkeypatch.setattr(execution, "create_sync_model", fail)
    response = client.post("/api/experiments", json=experiment_payload(
        defense_profile_ids=["none"],
    ))
    identifier = response.json()["id"]
    finished = wait_for_experiment(client, identifier)
    assert finished["status"] == "completed_with_errors"
    assert finished["failed_runs"] == 1
    run = client.get(f"/api/experiments/{identifier}/runs").json()[0]
    detail = client.get(f"/api/runs/{run['id']}").json()
    assert detail["run"]["status"] == "failed"
    assert "offline provider failure" in detail["error"]["message"]
    assert detail["trace_events"]
    metrics = client.get(f"/api/experiments/{identifier}/metrics").json()
    assert metrics["error_rate"]["value"] == 1


def test_submission_failure_is_terminal_and_reportable() -> None:
    class RejectingJobs:
        async def submit(self, experiment_id: str) -> None:
            raise RuntimeError("queue unavailable")

        async def cancel(self, experiment_id: str) -> None:
            pass

    with TestClient(create_app(settings(), job_manager=RejectingJobs())) as client:
        response = client.post("/api/experiments", json=experiment_payload())
        assert response.status_code == 200
        record = response.json()
        assert record["submitted"] is False
        assert record["status"] == "failed"
        assert record["failed_runs"] == record["total_runs"] == 2
        assert record["metadata"]["execution_error"]["code"] == "submission_failed"


@pytest.mark.parametrize(("path", "body"), [
    ("/api/victim/chat", {"message": ""}),
    ("/api/victim/chat", {"message": "hello", "identity": {"user_id": "a", "role": "root"}}),
    ("/api/victim/chat", {"message": "hello", "identity": {"user_id": " ", "role": "admin"}}),
    ("/api/victim/chat", {"message": "hello", "defense_profile_id": "missing"}),
    ("/api/experiments", {"name": "empty"}),
    ("/api/experiments", experiment_payload(defense_profile_ids=[])),
    ("/api/experiments", experiment_payload(attack_ids=["attack-dpi-001", "attack-dpi-001"])),
    ("/api/experiments", experiment_payload(repetitions=0)),
])
def test_invalid_request_has_serializable_structured_error(
    client: TestClient, path: str, body: dict[str, Any],
) -> None:
    response = client.post(path, json=body)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"]
    assert client.get("/api/runs").json() == []


def test_unknown_resources_and_malformed_json(client: TestClient) -> None:
    assert client.get("/api/runs/missing").status_code == 404
    assert client.post("/api/experiments/missing/cancel").status_code == 404
    response = client.post("/api/victim/chat", content="{", headers={
        "content-type": "application/json",
    })
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_startup_marks_previous_process_work_interrupted() -> None:
    app = create_app(settings())

    async def seed() -> None:
        await initialize_schema(app.state.engine)
        async with app.state.session_factory() as session:
            repository = StorageRepository(session)
            await repository.create_experiment_with_runs(
                ExperimentCreate.model_validate(experiment_payload()), [{
                    "id": "stale-run", "case_id": "attack-dpi-001", "case_kind": "attack",
                    "defense_profile_id": "none", "status": "running",
                }], experiment_id="stale-experiment",
            )
            await repository.create_run(
                run_id="stale-chat", experiment_id=None, case_id="chat", case_kind="chat",
                status=RunStatus.RUNNING,
            )

    asyncio.run(seed())
    with TestClient(app) as client:
        record = client.get("/api/experiments/stale-experiment").json()
        assert record["status"] == "failed"
        assert record["failed_runs"] == 1
        for identifier in ("stale-run", "stale-chat"):
            run = client.get(f"/api/runs/{identifier}").json()
            assert run["run"]["status"] == "failed"
            assert run["error"]["code"] == "process_interrupted"


def test_configured_model_and_job_provider_overrides_reach_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from promptfirewall import main

    calls: list[tuple[str, str | None, str | None, int]] = []

    def factory(
        config: Settings, *, provider: str | None = None, model_name: str | None = None,
        seed: int = 7,
    ) -> DeterministicMockModel:
        calls.append((config.model_provider, provider, model_name, seed))
        return DeterministicMockModel(model_name=model_name or config.model_name, seed=seed)

    monkeypatch.setattr(main, "create_sync_model", factory)
    monkeypatch.setattr(execution, "create_sync_model", factory)
    config = settings().model_copy(update={
        "model_provider": "configured", "model_name": "chat-model",
    })
    with TestClient(create_app(config)) as client:
        response = client.post("/api/victim/chat", json={"message": "Hello"})
        assert response.status_code == 200
        assert response.json()["response"]["model"] == "chat-model"
        assert calls[0] == ("configured", None, None, 7)
        created = client.post("/api/experiments", json=experiment_payload(
            defense_profile_ids=["none"], model_provider="requested", model_name="job-model",
            random_seed=42,
        )).json()
        assert wait_for_experiment(client, created["id"])["status"] == "completed"
        assert ("configured", "requested", "job-model", 42) in calls
        response = client.post("/api/victim/test-run", json={
            "case_id": "benign-001", "case_kind": "benign", "model_provider": "test-provider",
            "model_name": "test-model",
        })
        assert response.status_code == 200
        assert response.json()["response"]["model"] == "test-model"
        assert ("configured", "test-provider", "test-model", 7) in calls


def test_chat_failure_is_persisted_and_id_stays_reserved() -> None:
    class BrokenModel(DeterministicMockModel):
        def complete(self, request: ModelRequest) -> ModelResponse:
            raise RuntimeError("offline model failure")

    app = create_app(settings(), victim_service=VictimService(model=BrokenModel()))
    with TestClient(app) as client:
        response = client.post("/api/victim/chat", json={
            "message": "Hello", "run_id": "failed-chat",
        })
        assert response.status_code == 502
        record = client.get("/api/runs/failed-chat").json()
        assert record["run"]["status"] == "failed"
        assert record["error"]["message"] == "offline model failure"
        assert client.post("/api/victim/chat", json={
            "message": "Hello", "run_id": "failed-chat",
        }).status_code == 409


def test_queue_capacity_failure_is_persisted(monkeypatch: pytest.MonkeyPatch) -> None:
    from promptfirewall import main

    model = GatedModel()
    monkeypatch.setattr(execution, "create_sync_model", lambda *args, **kwargs: model)
    monkeypatch.setattr(main, "InProcessJobManager", lambda factory, config: InProcessJobManager(
        factory, config, max_queued=1,
    ))
    with TestClient(create_app(settings())) as client:
        client.post("/api/experiments", json=experiment_payload(defense_profile_ids=["none"]))
        try:
            assert model.entered.wait(5)
            queued = client.post("/api/experiments", json=experiment_payload()).json()
            assert queued["submitted"] is True
            rejected = client.post("/api/experiments", json=experiment_payload()).json()
            assert rejected["submitted"] is False
            assert rejected["status"] == "failed"
            assert rejected["failed_runs"] == rejected["total_runs"]
            assert rejected["metadata"]["execution_error"]["type"] == "JobQueueFull"
        finally:
            model.release.set()


def test_shutdown_waits_for_workers_before_disposing_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = GatedModel()
    monkeypatch.setattr(execution, "create_sync_model", lambda *args, **kwargs: model)
    app = create_app(settings())
    shutdown_started = Event()
    stopped = Event()
    original_close = app.state.job_manager.close

    async def close() -> None:
        shutdown_started.set()
        await original_close()
        # The engine is still usable here and all worker writes have settled.
        async with app.state.session_factory() as session:
            runs = await StorageRepository(session).list_runs()
        assert len(runs) == 2
        assert all(run.status == "cancelled" for run in runs)
        assert any(run.result.get("trace_events") for run in runs)
        stopped.set()

    app.state.job_manager.close = close

    def lifecycle() -> None:
        with TestClient(app) as client:
            client.post("/api/experiments", json=experiment_payload(
                defense_profile_ids=["none"], repetitions=2, concurrency_limit=1,
            ))
            assert model.entered.wait(5)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(lifecycle)
        try:
            assert shutdown_started.wait(5)
            assert not stopped.is_set()
            assert not pending.done()
        finally:
            model.release.set()
        pending.result(timeout=10)
    assert stopped.is_set()
