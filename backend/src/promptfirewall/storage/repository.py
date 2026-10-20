"""Small async repository around the persistence records.

The repository deliberately accepts plain dictionaries for run/result payloads.  This
keeps the storage boundary useful to the existing contracts and leaves the future
experiment runner free to persist its richer result objects without coupling it to
FastAPI.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Any, Concatenate, ParamSpec, TypeVar
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from promptfirewall.contracts.experiments import ExperimentCreate, ExperimentStatus, RunStatus
from promptfirewall.contracts.traces import TraceEvent
from promptfirewall.storage.models import ExperimentRecord, RunRecord, TraceEventRecord


def _now() -> datetime:
    return datetime.now(UTC)


def _as_json(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if is_dataclass(value) and not isinstance(value, type):
        return _as_json(asdict(value))
    if isinstance(value, tuple):
        return [_as_json(item) for item in value]
    if isinstance(value, list):
        return [_as_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _as_json(item) for key, item in value.items()}
    if hasattr(value, "value"):
        return value.value
    return value


P = ParamSpec("P")
T = TypeVar("T")


def transaction(
    method: Callable[Concatenate[StorageRepository, P], Awaitable[T]],
) -> Callable[Concatenate[StorageRepository, P], Awaitable[T]]:
    """Keep each repository operation atomic, with no idle read transaction."""
    @wraps(method)
    async def wrapped(self: StorageRepository, /, *args: P.args, **kwargs: P.kwargs) -> T:
        lock = self.session.info.setdefault("storage_lock", asyncio.Lock())
        async with lock:
            try:
                result = await method(self, *args, **kwargs)
                await self.session.commit()
                return result
            except BaseException:
                await self.session.rollback()
                raise
    return wrapped


class DuplicateRunError(ValueError):
    """A caller attempted to reserve an already-used run ID."""


_ACTIVE = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)


@dataclass(frozen=True)
class ExperimentCounts:
    total_runs: int
    completed_runs: int
    failed_runs: int
    cancelled_runs: int

    @property
    def remaining_runs(self) -> int:
        return max(
            0,
            self.total_runs - self.completed_runs - self.failed_runs - self.cancelled_runs,
        )


class StorageRepository:
    """Persistence operations used by API routes and a future runner."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @transaction
    async def create_experiment(
        self,
        request: ExperimentCreate,
        *,
        experiment_id: str | None = None,
        total_runs: int = 0,
    ) -> ExperimentRecord:
        now = _now()
        record = ExperimentRecord(
            id=experiment_id or f"exp-{uuid4().hex}",
            name=request.name,
            status=ExperimentStatus.QUEUED.value,
            total_runs=total_runs,
            config=_as_json(request),
            experiment_metadata=_as_json(request.metadata),
            created_at=now,
            updated_at=now,
        )
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record

    @transaction
    async def create_experiment_with_runs(
        self,
        request: ExperimentCreate,
        run_specs: Iterable[dict[str, Any]],
        *,
        experiment_id: str | None = None,
    ) -> ExperimentRecord:
        specs = tuple(run_specs)
        now = _now()
        record = ExperimentRecord(
            id=experiment_id or f"exp-{uuid4().hex}",
            name=request.name,
            status=ExperimentStatus.QUEUED.value,
            total_runs=len(specs),
            config=_as_json(request),
            experiment_metadata=_as_json(request.metadata),
            created_at=now,
            updated_at=now,
        )
        self.session.add(record)
        self.session.add_all(
            [
                RunRecord(
                    id=str(spec.get("id") or f"run-{uuid4().hex}"),
                    experiment_id=record.id,
                    case_id=str(spec["case_id"]),
                    case_kind=str(spec["case_kind"]),
                    category=spec.get("category"),
                    defense_profile_id=str(spec["defense_profile_id"]),
                    status=str(spec.get("status", RunStatus.QUEUED.value)),
                    input_payload=_as_json(spec.get("input_payload", {})),
                    created_at=now,
                    updated_at=now,
                )
                for spec in specs
            ]
        )
        await self.session.commit()
        await self.session.refresh(record)
        return record

    @transaction
    async def list_experiments(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[ExperimentRecord]:
        result = await self.session.scalars(
            select(ExperimentRecord)
            .order_by(ExperimentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result)

    @transaction
    async def get_experiment(self, experiment_id: str) -> ExperimentRecord | None:
        return await self.session.get(ExperimentRecord, experiment_id, populate_existing=True)

    @transaction
    async def counts_for_experiment(self, experiment_id: str) -> ExperimentCounts:
        rows = await self.session.scalars(
            select(RunRecord.status).where(RunRecord.experiment_id == experiment_id)
        )
        statuses = list(rows)
        return ExperimentCounts(
            total_runs=len(statuses),
            completed_runs=statuses.count(RunStatus.COMPLETED.value),
            failed_runs=statuses.count(RunStatus.FAILED.value),
            cancelled_runs=statuses.count(RunStatus.CANCELLED.value),
        )

    @transaction
    async def update_experiment_status(
        self,
        experiment_id: str,
        status: ExperimentStatus | str,
    ) -> ExperimentRecord | None:
        record = await self.session.get(ExperimentRecord, experiment_id, populate_existing=True)
        if record is None:
            return None
        if record.status not in _ACTIVE:
            return record
        record.status = getattr(status, "value", status)
        record.updated_at = _now()
        await self.session.commit()
        await self.session.refresh(record)
        return record

    @transaction
    async def cancel_experiment(self, experiment_id: str) -> ExperimentRecord | None:
        record = await self.session.get(ExperimentRecord, experiment_id, populate_existing=True)
        if record is None:
            return None
        if record.status not in _ACTIVE:
            return record
        record.cancel_requested = True
        record.status = ExperimentStatus.CANCELLED.value
        record.updated_at = _now()
        await self.session.execute(
            update(RunRecord)
            .where(
                RunRecord.experiment_id == experiment_id,
                RunRecord.status.in_([RunStatus.QUEUED.value, RunStatus.RUNNING.value]),
            )
            .values(
                status=RunStatus.CANCELLED.value, updated_at=_now(),
                error={"code": "cancelled", "message": "Cancellation requested"},
            )
        )
        await self.session.commit()
        await self.session.refresh(record)
        return record

    @transaction
    async def create_run(
        self,
        *,
        run_id: str | None = None,
        experiment_id: str | None,
        case_id: str,
        case_kind: str,
        defense_profile_id: str = "none",
        category: str | None = None,
        status: RunStatus | str = RunStatus.QUEUED,
        input_payload: dict[str, Any] | None = None,
    ) -> RunRecord:
        now = _now()
        record = RunRecord(
            id=run_id or f"run-{uuid4().hex}",
            experiment_id=experiment_id,
            case_id=case_id,
            case_kind=case_kind,
            category=category,
            defense_profile_id=defense_profile_id,
            status=getattr(status, "value", status),
            input_payload=_as_json(input_payload or {}),
            created_at=now,
            updated_at=now,
        )
        self.session.add(record)
        try:
            await self.session.commit()
        except IntegrityError as error:
            await self.session.rollback()
            if run_id and await self.session.get(RunRecord, run_id) is not None:
                raise DuplicateRunError(run_id) from error
            raise
        await self.session.refresh(record)
        return record

    @transaction
    async def list_runs(
        self,
        *,
        experiment_id: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[RunRecord]:
        query = (
            select(RunRecord).execution_options(populate_existing=True)
            .order_by(RunRecord.created_at.asc()).offset(offset).limit(limit)
        )
        if experiment_id is not None:
            query = query.where(RunRecord.experiment_id == experiment_id)
        return list(await self.session.scalars(query))

    @transaction
    async def get_run(self, run_id: str) -> RunRecord | None:
        return await self.session.get(RunRecord, run_id, populate_existing=True)

    @transaction
    async def save_run_result(
        self,
        run_id: str,
        *,
        status: RunStatus | str,
        outcome: str | None = None,
        latency_ms: float | None = None,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> RunRecord | None:
        record = await self.session.get(RunRecord, run_id, populate_existing=True)
        if record is None:
            return None
        # A late worker may still return evidence after cancellation, but must never
        # resurrect a terminal run or change its contribution to metrics.
        if record.status not in _ACTIVE and record.status != RunStatus.CANCELLED.value:
            return record
        if record.status != RunStatus.CANCELLED.value:
            record.status = getattr(status, "value", status)
            record.outcome = getattr(outcome, "value", outcome)
            record.error = _as_json(error)
        if record.status != RunStatus.CANCELLED.value:
            record.latency_ms = latency_ms
        record.result = _as_json(result or {})
        if "status" in record.result:
            record.result = {
                **record.result, "status": record.status,
                "outcome": record.outcome, "error": record.error,
            }
        record.updated_at = _now()
        await self.session.commit()
        await self.session.refresh(record)
        return record

    @transaction
    async def add_trace_events(
        self,
        run_id: str,
        events: Iterable[TraceEvent | dict[str, Any]],
    ) -> None:
        records: list[TraceEventRecord] = []
        for event in events:
            validated = TraceEvent.model_validate(event)
            if validated.run_id != run_id:
                raise ValueError("trace run_id does not match its owning run")
            payload = validated.model_dump(mode="json")
            records.append(
                TraceEventRecord(
                    event_id=str(payload["event_id"]),
                    run_id=run_id,
                    sequence=int(payload["sequence"]),
                    event_type=str(payload["event_type"]),
                    timestamp=validated.timestamp,
                    stage=payload.get("stage"),
                    correlation_id=str(payload["correlation_id"]),
                    payload=payload.get("payload", {}),
                    defense_id=payload.get("defense_id"),
                    tool_name=payload.get("tool_name"),
                    error=payload.get("error"),
                )
            )
        if records:
            self.session.add_all(records)
            await self.session.commit()

    @transaction
    async def list_trace_events(self, run_id: str) -> list[TraceEventRecord]:
        result = await self.session.scalars(
            select(TraceEventRecord)
            .where(TraceEventRecord.run_id == run_id)
            .order_by(TraceEventRecord.sequence.asc())
        )
        return list(result)

    async def metric_records(self, experiment_id: str | None = None) -> list[dict[str, Any]]:
        runs = await self.list_runs(experiment_id=experiment_id, limit=100_000)
        return [
            {
                "case_kind": run.case_kind,
                "category": run.category,
                "defense_profile_id": run.defense_profile_id,
                "status": run.status,
                "outcome": run.outcome,
                "latency_ms": run.latency_ms,
                "error": run.error,
            }
            for run in runs
            if run.status in (RunStatus.COMPLETED.value, RunStatus.FAILED.value)
        ]

    @transaction
    async def fail_experiment(self, experiment_id: str, error: dict[str, Any]) -> None:
        record = await self.session.get(ExperimentRecord, experiment_id, populate_existing=True)
        if record is None or record.status not in _ACTIVE:
            return
        record.status = ExperimentStatus.FAILED.value
        record.updated_at = _now()
        record.experiment_metadata = {**record.experiment_metadata, "execution_error": error}
        await self.session.execute(
            update(RunRecord).where(
                RunRecord.experiment_id == experiment_id, RunRecord.status.in_(_ACTIVE),
            ).values(
                status=RunStatus.FAILED.value, outcome="execution_error", error=error,
                updated_at=_now(),
            )
        )

    @transaction
    async def mark_interrupted(self) -> None:
        """A fresh process cannot resume work owned by a previous process."""
        error = {
            "code": "process_interrupted", "message": "Execution interrupted by process restart",
        }
        experiments = await self.session.scalars(
            select(ExperimentRecord).where(ExperimentRecord.status.in_(_ACTIVE))
        )
        for record in experiments:
            record.status = ExperimentStatus.FAILED.value
            record.updated_at = _now()
            record.experiment_metadata = {**record.experiment_metadata, "execution_error": error}
        await self.session.execute(
            update(RunRecord).where(RunRecord.status.in_(_ACTIVE)).values(
                status=RunStatus.FAILED.value, outcome="execution_error", error=error,
                updated_at=_now(),
            )
        )


Repository = StorageRepository

__all__ = ["DuplicateRunError", "ExperimentCounts", "Repository", "StorageRepository"]
