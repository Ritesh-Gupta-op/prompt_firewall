from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class UserRole(StrEnum):
    CUSTOMER = "customer"
    ADMIN = "admin"


class ModelMessage(BaseModel):
    role: str
    content: str


class ToolDefinition(BaseModel):
    name: str
    description: str
    # Provider-facing JSON Schema, not a mapping of argument names to type strings.
    parameters: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class ModelRequest(BaseModel):
    system_instructions: str
    messages: list[ModelMessage]
    tools: list[ToolDefinition] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_tokens: int = Field(default=700, gt=0, le=4096)
    experiment_metadata: dict[str, Any] = Field(default_factory=dict)


class ProposedToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: str


class ModelResponse(BaseModel):
    text: str
    tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    provider: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reason: str = "stop"
    latency_ms: float
    provider_request_id: str | None = None
    is_mock: bool = False


@runtime_checkable
class SyncModel(Protocol):
    """Synchronous model seam shared by the victim, runner, and provider bridge."""

    @property
    def model_name(self) -> str: ...

    def complete(self, request: ModelRequest) -> ModelResponse: ...


class TestIdentity(BaseModel):
    user_id: str
    role: UserRole
    customer_id: str | None = None
    tenant_id: str = "acme-test"


class ToolResult(BaseModel):
    success: bool
    tool_name: str
    data: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = None
    message: str | None = None


class RunConfig(BaseModel):
    identity: TestIdentity = TestIdentity(
        user_id="demo-customer", role=UserRole.CUSTOMER, customer_id="cust-1001"
    )
    model_provider: str = "mock"
    model_name: str = "promptfirewall-mock-1"
    temperature: float = Field(default=0.0, ge=0, le=2)
    prompt_version: str = "prompt-v1"
    dataset_version: str = "acme-fixtures-v1"
    defense_config_version: str = "defense-v1"
    seed: int = 7
    repetition_index: int = Field(default=0, ge=0)


class Timestamped(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    created_at: datetime
