from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TraceEventType(StrEnum):
    RUN_STARTED = "run_started"
    SESSION_INITIALIZED = "session_initialized"
    ATTACK_DELIVERED = "attack_delivered"
    INPUT_EVALUATED = "input_evaluated"
    CONTEXT_RETRIEVED = "context_retrieved"
    CONTEXT_FILTERED = "context_filtered"
    MODEL_INVOKED = "model_invoked"
    MODEL_RETURNED = "model_returned"
    TOOL_PROPOSED = "tool_proposed"
    TOOL_AUTHORIZED = "tool_authorized"
    TOOL_DENIED = "tool_denied"
    TOOL_EXECUTED = "tool_executed"
    OUTPUT_EVALUATED = "output_evaluated"
    JUDGE_COMPLETED = "judge_completed"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"


class TraceEvent(BaseModel):
    event_id: str
    run_id: str
    sequence: int
    event_type: TraceEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stage: str | None = None
    correlation_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    defense_id: str | None = None
    tool_name: str | None = None
    error: dict[str, Any] | None = None
