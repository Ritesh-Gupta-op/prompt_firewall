"""Public firewall entry point, independent of HTTP and persistence."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from promptfirewall.contracts.defenses import DefenseDecision
from promptfirewall.contracts.models import ModelResponse, TestIdentity, ToolResult, UserRole
from promptfirewall.contracts.traces import TraceEvent
from promptfirewall.defenses.execution import EnforcedRun, RunBudget, fresh_victim
from promptfirewall.defenses.pipeline import DefensePipeline
from promptfirewall.victim_app.service import VictimService


@dataclass(frozen=True)
class FirewallRunResult:
    run_id: str
    session_id: str
    model_response: ModelResponse
    tool_results: tuple[ToolResult, ...]
    trace_events: tuple[TraceEvent, ...]
    defense_decisions: tuple[DefenseDecision, ...]
    blocked: bool
    access_denials: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.model_response.text


class FirewallService:
    def __init__(self, victim: VictimService | None = None) -> None:
        self.victim = victim

    def run(
        self, message: str, identity: TestIdentity | None = None, *,
        run_id: str | None = None, session_id: str = "session-default",
        defense_profile_id: str = "full-stack",
        timeout_seconds: float = 10.0, max_tokens: int = 700,
    ) -> FirewallRunResult:
        if not isinstance(message, str) or not message.strip():
            raise ValueError("message must be non-empty")
        if not session_id.strip() or (run_id is not None and not run_id.strip()):
            raise ValueError("run_id and session_id must be non-empty")
        if not 0 < timeout_seconds <= 120 or not 0 < max_tokens <= 4096:
            raise ValueError("timeout_seconds must be in (0, 120] and max_tokens in [1, 4096]")
        resolved_id = run_id or f"run-{uuid.uuid4().hex}"
        identity = identity or TestIdentity(
            user_id="demo-customer", role=UserRole.CUSTOMER, customer_id="cust-1001",
        )
        pipeline = DefensePipeline(defense_profile_id)
        with fresh_victim(self.victim) as victim:
            execution = EnforcedRun(
                victim, pipeline, identity, run_id=resolved_id, session_id=session_id,
                budget=RunBudget(timeout_seconds, max_tokens),
            )
            result = execution.run_turn(message)
            denials = (*result.access_denials, *(
                item.error_code or "tool_denied" for item in result.tool_results if not item.success
            ))
            return FirewallRunResult(
                run_id=resolved_id, session_id=session_id, model_response=result.model_response,
                tool_results=result.tool_results, trace_events=execution.finish(),
                defense_decisions=tuple(execution.decisions), blocked=execution.blocked,
                access_denials=tuple(dict.fromkeys(denials)),
            )


__all__ = ["FirewallRunResult", "FirewallService"]
