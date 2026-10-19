"""Run records, persistence seams, and lightweight job state.

The harness deliberately keeps persistence small.  The runner only needs an
object that can upsert a run and append an ordered trace event; an API or a
database adapter can implement the same protocol later without becoming part
of the execution path.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from threading import Event, RLock
from typing import Any, Protocol, runtime_checkable

from promptfirewall.contracts.experiments import (
    ExperimentCreate,
    ExperimentStatus,
    RunStatus,
)
from promptfirewall.contracts.models import ModelResponse, ToolResult
from promptfirewall.contracts.results import JudgeResult, MetricsSnapshot, OutcomeLabel
from promptfirewall.contracts.traces import TraceEvent


def utc_now() -> datetime:
    """Return an aware timestamp without making time a module global."""

    return datetime.now(UTC)


@dataclass
class RunRecord:
    """The in-memory representation of one observable harness run.

    The record intentionally contains the actual response, tool results,
    state snapshots, judges, and trace events.  It is a plain dataclass so a
    future storage adapter can map it to SQLAlchemy, a document store, or an
    API response without coupling the harness to any one choice.
    """

    id: str
    experiment_id: str
    case_id: str
    case_kind: str
    defense_profile_id: str
    repetition_index: int
    seed: int
    status: RunStatus = RunStatus.QUEUED
    outcome: OutcomeLabel | None = None
    category: str | None = None
    case_name: str | None = None
    latency_ms: float | None = None
    response_text: str | None = None
    model_response: ModelResponse | None = None
    tool_results: tuple[ToolResult, ...] = ()
    trace_events: tuple[TraceEvent, ...] = ()
    judge_results: tuple[JudgeResult, ...] = ()
    aggregated_judgment: Any | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    state_before: dict[str, Any] | None = None
    state_after: dict[str, Any] | None = None
    blocked: bool = False
    error: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime = field(default_factory=utc_now)

    @property
    def run_id(self) -> str:
        return self.id

    @property
    def profile_id(self) -> str:
        return self.defense_profile_id

    @property
    def output(self) -> str | None:
        return self.response_text

    @property
    def text(self) -> str | None:
        return self.response_text

    def touch(self) -> None:
        self.updated_at = utc_now()


@dataclass
class ExperimentRecord:
    """Durable-looking experiment state used by the runner and repository."""

    id: str
    request: ExperimentCreate
    status: ExperimentStatus = ExperimentStatus.QUEUED
    runs: list[RunRecord] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    @property
    def name(self) -> str:
        return self.request.name

    @property
    def total_runs(self) -> int:
        return len(self.runs)

    @property
    def completed_runs(self) -> int:
        return sum(run.status is RunStatus.COMPLETED for run in self.runs)

    @property
    def failed_runs(self) -> int:
        return sum(run.status is RunStatus.FAILED for run in self.runs)

    @property
    def cancelled_runs(self) -> int:
        return sum(run.status is RunStatus.CANCELLED for run in self.runs)

    @property
    def remaining_runs(self) -> int:
        return sum(run.status in {RunStatus.QUEUED, RunStatus.RUNNING} for run in self.runs)

    def touch(self) -> None:
        self.updated_at = utc_now()


@dataclass(frozen=True)
class ExperimentResult:
    """Completed runner output, including metrics calculated from its records."""

    experiment: ExperimentRecord
    metrics: MetricsSnapshot

    @property
    def experiment_id(self) -> str:
        return self.experiment.id

    @property
    def runs(self) -> tuple[RunRecord, ...]:
        return tuple(self.experiment.runs)

    @property
    def status(self) -> ExperimentStatus:
        return self.experiment.status


class RunPersistenceError(RuntimeError):
    """Raised when a repository cannot accept a harness record."""


@runtime_checkable
class RunRepository(Protocol):
    """Minimal synchronous persistence protocol used by ``ExperimentRunner``."""

    def save_run(self, record: RunRecord) -> None:
        """Insert or replace a run record."""

    def save_trace(self, event: TraceEvent) -> None:
        """Append one trace event in the order supplied by the runner."""


class CancellationToken:
    """Thread-safe cooperative cancellation shared by a runner and its jobs."""

    def __init__(self, event: Event | None = None) -> None:
        self._event = event or Event()

    @property
    def event(self) -> Event:
        return self._event

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self.cancelled


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ExperimentJob:
    """Small job handle for API layers that want to retain cancellation state."""

    id: str
    request: ExperimentCreate
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    status: JobStatus = JobStatus.QUEUED

    def cancel(self) -> None:
        self.cancellation.cancel()
        if self.status is JobStatus.QUEUED:
            self.status = JobStatus.CANCELLED


class JobRegistry:
    """In-process job registry; execution remains owned by the runner."""

    def __init__(self) -> None:
        self._jobs: dict[str, ExperimentJob] = {}
        self._lock = RLock()

    def register(self, job: ExperimentJob) -> ExperimentJob:
        with self._lock:
            if job.id in self._jobs:
                raise ValueError(f"job already registered: {job.id}")
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> ExperimentJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as error:
                raise KeyError(f"unknown job: {job_id}") from error

    def cancel(self, job_id: str) -> None:
        self.get(job_id).cancel()

    def jobs(self) -> tuple[ExperimentJob, ...]:
        with self._lock:
            return tuple(self._jobs.values())


class InMemoryRunRepository:
    """Thread-safe repository with copies suitable for deterministic unit tests."""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._experiments: dict[str, ExperimentRecord] = {}
        self._traces: dict[str, list[TraceEvent]] = {}
        self._lock = RLock()

    def save_experiment(self, record: ExperimentRecord) -> None:
        with self._lock:
            self._experiments[record.id] = deepcopy(record)

    def save_run(self, record: RunRecord) -> None:
        with self._lock:
            self._runs[record.id] = deepcopy(record)

    persist_run = save_run

    def save_trace(self, event: TraceEvent) -> None:
        with self._lock:
            events = self._traces.setdefault(event.run_id, [])
            if events and event.sequence <= events[-1].sequence:
                raise RunPersistenceError(
                    f"trace sequence must increase for run {event.run_id}: {event.sequence}"
                )
            events.append(deepcopy(event))

    persist_trace = save_trace

    def get_experiment(self, experiment_id: str) -> ExperimentRecord:
        with self._lock:
            try:
                return deepcopy(self._experiments[experiment_id])
            except KeyError as error:
                raise KeyError(f"unknown experiment: {experiment_id}") from error

    def get_run(self, run_id: str) -> RunRecord:
        with self._lock:
            try:
                return deepcopy(self._runs[run_id])
            except KeyError as error:
                raise KeyError(f"unknown run: {run_id}") from error

    def list_runs(self, experiment_id: str | None = None) -> tuple[RunRecord, ...]:
        with self._lock:
            records = tuple(self._runs.values())
            if experiment_id is not None:
                records = tuple(
                    record for record in records if record.experiment_id == experiment_id
                )
            return deepcopy(records)

    def trace_events(self, run_id: str) -> tuple[TraceEvent, ...]:
        with self._lock:
            return tuple(deepcopy(self._traces.get(run_id, ())))


InMemoryRunStore = InMemoryRunRepository
RunRepositoryProtocol = RunRepository


__all__ = [
    "CancellationToken",
    "ExperimentJob",
    "ExperimentRecord",
    "ExperimentResult",
    "InMemoryRunRepository",
    "InMemoryRunStore",
    "JobRegistry",
    "JobStatus",
    "RunPersistenceError",
    "RunRecord",
    "RunRepository",
    "RunRepositoryProtocol",
]
