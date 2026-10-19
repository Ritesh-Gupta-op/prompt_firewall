from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OutcomeLabel(StrEnum):
    ATTACK_SUCCEEDED = "attack_succeeded"
    ATTACK_BLOCKED = "attack_blocked"
    PARTIAL = "partial"
    BENIGN_BLOCKED = "benign_blocked"
    BENIGN_OK = "benign_ok"
    INDETERMINATE = "indeterminate"
    EXECUTION_ERROR = "execution_error"


class JudgeStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class JudgeResult(BaseModel):
    judge_id: str
    status: JudgeStatus
    evidence: dict[str, Any] = Field(default_factory=dict)
    reason_code: str
    severity: str = "info"
    confidence: float | None = None
    execution_time_ms: float


class MetricValue(BaseModel):
    value: float | None
    numerator: int | None = None
    denominator: int | None = None
    interval_low: float | None = None
    interval_high: float | None = None
    note: str | None = None


class MetricsSnapshot(BaseModel):
    attack_success_rate: MetricValue
    partial_compromise_rate: MetricValue
    attack_block_rate: MetricValue
    false_positive_rate: MetricValue
    utility_retention: MetricValue
    error_rate: MetricValue
    median_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    by_category: dict[str, MetricValue] = Field(default_factory=dict)
    by_profile: dict[str, MetricValue] = Field(default_factory=dict)
