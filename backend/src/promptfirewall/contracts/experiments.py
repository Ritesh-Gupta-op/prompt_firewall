from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class ExperimentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExperimentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    attack_ids: list[str] = Field(default_factory=list)
    benign_case_ids: list[str] = Field(default_factory=list)
    defense_profile_ids: list[str] = Field(default_factory=lambda: ["none", "full-stack"])
    model_provider: str = "mock"
    model_name: str = "promptfirewall-mock-1"
    repetitions: int = Field(default=1, ge=1, le=20)
    random_seed: int = 7
    concurrency_limit: int = Field(default=2, ge=1, le=16)
    timeout_seconds: float = Field(default=10, gt=0, le=120)
    token_budget: int = Field(default=700, gt=0, le=4096)
    dataset_version: str = "acme-fixtures-v1"
    defense_config_version: str = "defense-v1"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def has_cases(self) -> "ExperimentCreate":
        if not self.attack_ids and not self.benign_case_ids:
            raise ValueError("select at least one attack or benign case")
        return self


class ExperimentSummary(BaseModel):
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


class RunSummary(BaseModel):
    id: str
    experiment_id: str
    case_id: str
    case_kind: str
    defense_profile_id: str
    status: RunStatus
    outcome: str | None = None
    latency_ms: float | None = None
    created_at: str
