from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AttackCategory(StrEnum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    DATA_LEAKAGE = "data_leakage"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    OBFUSCATION = "obfuscation"
    MULTI_TURN = "multi_turn"
    MEMORY_POISONING = "memory_poisoning"
    RAG_POISONING = "rag_poisoning"
    OUTPUT_EXFILTRATION = "output_channel_exfiltration"
    RESOURCE_ABUSE = "resource_abuse"


class DeliveryMode(StrEnum):
    USER_MESSAGE = "user_message"
    RAG_DOCUMENT = "rag_document"
    TOOL_OUTPUT = "tool_output"
    CONVERSATION_MEMORY = "conversation_memory"


class CaseKind(StrEnum):
    ATTACK = "attack"
    BENIGN = "benign"


class SuccessCriterion(BaseModel):
    type: str
    value: str | None = None
    tool_name: str | None = None
    expected: Any | None = None


class AttackDefinition(BaseModel):
    id: str
    name: str
    category: AttackCategory
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    description: str
    delivery: DeliveryMode
    payload_template: str
    success_criteria: list[SuccessCriterion] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    version: str = "1.0"
    turns: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def stable_id(cls, value: str) -> str:
        if not value or " " in value:
            raise ValueError("attack id must be a non-empty stable token")
        return value


class BenignExpectations(BaseModel):
    """Observable fixture assertions, not a semantic or real-model quality score."""

    required_output_substrings: list[str] = Field(default_factory=list)
    forbidden_output_substrings: list[str] = Field(default_factory=list)
    expected_json: dict[str, str] | None = None
    forbid_tool_calls: bool = False
    unchanged_state_keys: list[str] = Field(default_factory=list)

    @field_validator("required_output_substrings", "forbidden_output_substrings")
    @classmethod
    def nonempty_substrings(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("output expectations must be non-empty substrings")
        return values


class BenignCase(BaseModel):
    id: str
    name: str
    request: str
    expected_behavior: str
    expectations: BenignExpectations | None = None
    identity: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    version: str = "1.0"


class Mutation(BaseModel):
    mutation_id: str
    parent_attack_id: str
    payload: str
    operators: list[str]
    relationship: str = "derived"
    seed: int
