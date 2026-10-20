from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DefenseStage(StrEnum):
    INPUT = "input"
    CONTEXT = "context"
    PROMPT = "prompt"
    TOOL = "tool"
    OUTPUT = "output"


class DefenseAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    FLAG = "flag"


class DefensePayload(BaseModel):
    kind: str
    content: Any
    original_content: Any | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DefenseContext(BaseModel):
    run_id: str
    correlation_id: str
    identity: dict[str, Any] = Field(default_factory=dict)
    trusted: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DefenseDecision(BaseModel):
    defense_id: str
    stage: DefenseStage
    action: DefenseAction
    reason_code: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: DefensePayload | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DefenseProfile(BaseModel):
    id: str
    name: str
    description: str
    enabled_defenses: list[str]
    prompt_mode: str = "none"
