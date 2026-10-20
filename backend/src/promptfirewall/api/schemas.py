"""Pydantic request and response schemas for the HTTP boundary."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from promptfirewall.contracts.attacks import AttackDefinition, BenignCase, CaseKind
from promptfirewall.contracts.defenses import DefenseDecision, DefenseProfile
from promptfirewall.contracts.experiments import ExperimentCreate, ExperimentStatus, RunStatus
from promptfirewall.contracts.models import ModelResponse, TestIdentity, ToolResult
from promptfirewall.contracts.results import JudgeResult, MetricsSnapshot, OutcomeLabel
from promptfirewall.contracts.traces import TraceEvent


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    database: Literal["configured"]


class VictimChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)
    identity: TestIdentity | None = None
    session_id: str = Field(default="session-default", min_length=1, max_length=160)
    run_id: str | None = Field(default=None, min_length=1, max_length=160)
    defense_profile_id: str = Field(default="full-stack", min_length=1, max_length=160)

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: TestIdentity | None) -> TestIdentity | None:
        return validate_test_identity(value)

    @field_validator("message", "session_id", "run_id")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("must not be blank")
        return value


class VictimChatResponse(BaseModel):
    run_id: str
    session_id: str
    response: ModelResponse
    tool_results: list[ToolResult]
    trace_events: list[TraceEvent]
    access_denials: list[str]
    defense_decisions: list[DefenseDecision] = Field(default_factory=list)
    blocked: bool = False


class TestRunRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=160)
    case_kind: CaseKind
    defense_profile_id: str = "none"
    identity: TestIdentity | None = None
    session_id: str = Field(default="session-default", min_length=1, max_length=160)
    run_id: str | None = Field(default=None, min_length=1, max_length=160)
    model_provider: str | None = None
    model_name: str | None = None

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: TestIdentity | None) -> TestIdentity | None:
        return validate_test_identity(value)

    @field_validator("case_id", "session_id", "run_id", "model_provider", "model_name")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("must not be blank")
        return value


def validate_test_identity(value: TestIdentity | None) -> TestIdentity | None:
    """Validate synthetic test metadata, without treating it as authentication."""
    if value is not None:
        for identifier in (value.user_id, value.tenant_id, value.customer_id):
            if identifier is not None and (not identifier.strip() or len(identifier) > 160):
                raise ValueError("identity identifiers must contain 1 to 160 characters")
    return value


class RunSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    experiment_id: str | None
    case_id: str
    case_kind: str
    defense_profile_id: str
    status: RunStatus
    outcome: str | None = None
    latency_ms: float | None = None
    created_at: str


class TestRunResponse(BaseModel):
    run: RunSummaryResponse
    response: ModelResponse | None = None
    tool_results: list[ToolResult] = Field(default_factory=list)
    trace_events: list[TraceEvent]
    defense_decisions: list[DefenseDecision] = Field(default_factory=list)
    judge_results: list[JudgeResult] = Field(default_factory=list)
    outcome: OutcomeLabel
    blocked: bool


class RunDetailResponse(BaseModel):
    run: RunSummaryResponse
    result: dict[str, Any]
    error: dict[str, Any] | None = None
    trace_events: list[TraceEvent] = Field(default_factory=list)


class ExperimentResponse(BaseModel):
    id: str
    name: str
    status: ExperimentStatus
    total_runs: int
    completed_runs: int
    failed_runs: int
    cancelled_runs: int
    remaining_runs: int
    created_at: str
    updated_at: str
    config: ExperimentCreate
    metadata: dict[str, Any]
    cancel_requested: bool


class ExperimentCreateResponse(ExperimentResponse):
    submitted: bool


class ReportResponse(BaseModel):
    experiment: ExperimentResponse
    runs: list[RunSummaryResponse]
    metrics: MetricsSnapshot
    generated_at: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class CatalogResponse(BaseModel):
    attacks: list[AttackDefinition]
    benign: list[BenignCase]
    defense_profiles: list[DefenseProfile]


__all__ = [
    "CatalogResponse",
    "ExperimentCreateResponse",
    "ExperimentResponse",
    "HealthResponse",
    "ReportResponse",
    "RunDetailResponse",
    "RunSummaryResponse",
    "TestRunRequest",
    "TestRunResponse",
    "VictimChatRequest",
    "VictimChatResponse",
]
