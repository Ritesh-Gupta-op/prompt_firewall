"""Synchronous harness persistence backed by the application's async sessions."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import fields
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from promptfirewall.contracts.defenses import DefenseDecision
from promptfirewall.contracts.experiments import RunStatus
from promptfirewall.contracts.models import ModelResponse, ToolResult
from promptfirewall.contracts.results import JudgeResult, JudgeStatus, OutcomeLabel
from promptfirewall.contracts.traces import TraceEvent
from promptfirewall.harness.jobs import ExperimentRecord, RunRecord
from promptfirewall.storage.models import RunRecord as StoredRun
from promptfirewall.storage.repository import StorageRepository, _as_json


def defense_decisions(events: tuple[TraceEvent, ...]) -> list[DefenseDecision]:
    """Recover the decisions actually recorded by the runner's trace emitter."""
    return [
        DefenseDecision.model_validate({
            **event.payload, "defense_id": event.defense_id,
            "stage": event.stage, "timestamp": event.timestamp,
        })
        for event in events
        if event.defense_id and "action" in event.payload
    ]


def run_payload(record: RunRecord) -> dict[str, Any]:
    payload: dict[str, Any] = _as_json(record)
    payload["response"] = payload.get("model_response")
    payload["defense_decisions"] = _as_json(defense_decisions(record.trace_events))
    return payload


def restore_run(record: StoredRun, events: list[TraceEvent]) -> RunRecord:
    """Restore typed report input, taking lifecycle state from the durable row."""
    allowed = {field.name for field in fields(RunRecord)}
    payload = {key: value for key, value in record.result.items() if key in allowed}
    payload.update(
        id=record.id, experiment_id=record.experiment_id or "", case_id=record.case_id,
        case_kind=record.case_kind, defense_profile_id=record.defense_profile_id,
        category=record.category, status=RunStatus(record.status),
        outcome=OutcomeLabel(record.outcome) if record.outcome else None,
        latency_ms=record.latency_ms, error=record.error, created_at=record.created_at,
        updated_at=record.updated_at, trace_events=tuple(events),
    )
    payload.setdefault("repetition_index", record.input_payload.get("repetition_index", 0))
    payload.setdefault("seed", 7)
    response = payload.get("model_response")
    payload["model_response"] = ModelResponse.model_validate(response) if response else None
    payload["tool_results"] = tuple(
        ToolResult.model_validate(item) for item in payload.get("tool_results", ())
    )
    payload["judge_results"] = tuple(
        JudgeResult.model_validate(item) for item in payload.get("judge_results", ())
    )
    aggregate = payload.get("aggregated_judgment")
    if aggregate:
        from promptfirewall.judges.aggregator import AggregatedJudgment

        payload["aggregated_judgment"] = AggregatedJudgment(
            outcome=OutcomeLabel(aggregate["outcome"]), status=JudgeStatus(aggregate["status"]),
            judge_results=tuple(
                JudgeResult.model_validate(item) for item in aggregate["judge_results"]
            ), evidence=aggregate["evidence"],
        )
    for name in ("started_at", "finished_at"):
        if isinstance(payload.get(name), str):
            payload[name] = datetime.fromisoformat(payload[name])
    return RunRecord(**payload)


class RunnerRepository:
    """Use only from runner worker threads; the event loop owns every DB session."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        loop: asyncio.AbstractEventLoop,
        *,
        standalone: bool = False,
    ) -> None:
        self.session_factory = session_factory
        self.loop = loop
        self.standalone = standalone

    def _wait(self, operation: Coroutine[Any, Any, None]) -> None:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self.loop:
            operation.close()
            raise RuntimeError("RunnerRepository must be called from a worker thread")
        asyncio.run_coroutine_threadsafe(operation, self.loop).result()

    def save_run(self, record: RunRecord) -> None:
        self._wait(self._save_run(record, run_payload(record)))

    async def _save_run(self, record: RunRecord, payload: dict[str, Any]) -> None:
        async with self.session_factory() as session:
            saved = await StorageRepository(session).save_run_result(
                record.id, status=record.status, outcome=record.outcome,
                latency_ms=record.latency_ms, result=payload, error=record.error,
            )
            if saved is None:
                raise ValueError(f"Runner attempted to save an unreserved run: {record.id}")

    def save_trace(self, event: TraceEvent) -> None:
        self._wait(self._save_trace(event))

    async def _save_trace(self, event: TraceEvent) -> None:
        async with self.session_factory() as session:
            await StorageRepository(session).add_trace_events(event.run_id, [event])

    def save_experiment(self, record: ExperimentRecord) -> None:
        if not self.standalone:
            self._wait(self._save_experiment(record))

    async def _save_experiment(self, record: ExperimentRecord) -> None:
        async with self.session_factory() as session:
            saved = await StorageRepository(session).update_experiment_status(
                record.id, record.status,
            )
            if saved is None:
                raise ValueError(f"Unknown experiment: {record.id}")
