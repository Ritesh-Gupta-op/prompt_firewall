"""Storage boundary checks for typed traces, transactions and terminal states."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.traces import TraceEvent, TraceEventType
from promptfirewall.storage.database import create_async_engine, create_session_factory
from promptfirewall.storage.repository import DuplicateRunError, StorageRepository
from promptfirewall.storage.schema import initialize_schema


@pytest.fixture
async def repository() -> AsyncIterator[StorageRepository]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await initialize_schema(engine)
    try:
        async with create_session_factory(engine)() as session:
            yield StorageRepository(session)
    finally:
        await engine.dispose()


async def test_iso_timestamp_round_trip_and_trace_batch_rollback(
    repository: StorageRepository,
) -> None:
    await repository.create_run(
        run_id="trace-run", experiment_id=None, case_id="chat", case_kind="chat",
    )
    timestamp = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    event = TraceEvent(
        event_id="trace-1", run_id="trace-run", sequence=1,
        event_type=TraceEventType.RUN_STARTED, timestamp=timestamp,
        correlation_id="trace-run", payload={"nested": ["evidence"]},
    )
    await repository.add_trace_events("trace-run", [event.model_dump(mode="json")])
    records = await repository.list_trace_events("trace-run")
    assert records[0].timestamp.replace(tzinfo=UTC) == timestamp
    assert records[0].payload == event.payload
    valid = event.model_copy(update={"event_id": "trace-2", "sequence": 2})
    invalid = event.model_copy(update={"event_id": "trace-3", "run_id": "wrong-run"})
    with pytest.raises(ValueError, match="owning run"):
        await repository.add_trace_events("trace-run", [valid, invalid])
    assert len(await repository.list_trace_events("trace-run")) == 1
    await repository.add_trace_events("trace-run", [valid])
    assert len(await repository.list_trace_events("trace-run")) == 2


async def test_duplicate_id_rolls_back_without_breaking_next_operation(
    repository: StorageRepository,
) -> None:
    await repository.create_run(
        run_id="reserved", experiment_id=None, case_id="chat", case_kind="chat",
    )
    with pytest.raises(DuplicateRunError):
        await repository.create_run(
            run_id="reserved", experiment_id=None, case_id="chat", case_kind="chat",
        )
    await repository.create_run(
        run_id="another", experiment_id=None, case_id="chat", case_kind="chat",
    )
    assert len(await repository.list_runs()) == 2


async def test_late_worker_cannot_resurrect_cancelled_runs(
    repository: StorageRepository,
) -> None:
    request = ExperimentCreate(name="cancel", attack_ids=["attack-dpi-001"])
    experiment = await repository.create_experiment_with_runs(request, [{
        "id": "cancelled-run", "case_id": "attack-dpi-001", "case_kind": "attack",
        "defense_profile_id": "none",
    }])
    await repository.cancel_experiment(experiment.id)
    saved = await repository.save_run_result(
        "cancelled-run", status=RunStatus.COMPLETED, outcome="attack_succeeded", latency_ms=10,
        result={"status": "completed", "evidence": {"observation": "late worker result"}},
    )
    assert saved is not None
    assert saved.status == "cancelled"
    assert saved.outcome is None
    assert saved.result["status"] == "cancelled"
    assert saved.result["evidence"] == {"observation": "late worker result"}
    assert await repository.metric_records(experiment.id) == []
    await repository.update_experiment_status(experiment.id, "completed")
    record = await repository.get_experiment(experiment.id)
    assert record is not None and record.status == "cancelled"
