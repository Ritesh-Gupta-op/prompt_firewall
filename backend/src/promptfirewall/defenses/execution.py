"""Run-local enforcement shared by interactive chat and the experiment harness.

Filters are deterministic signatures, not a guarantee against arbitrary injection.
The model never receives authority to bypass the sandbox's structured approvals.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore, Thread
from typing import Any, cast

from promptfirewall.contracts.defenses import DefenseAction, DefenseContext, DefenseDecision
from promptfirewall.contracts.models import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ProposedToolCall,
    SyncModel,
    TestIdentity,
    ToolDefinition,
    ToolResult,
)
from promptfirewall.contracts.traces import TraceEvent, TraceEventType
from promptfirewall.defenses.pipeline import DefensePipeline, PipelineResult
from promptfirewall.victim_app.memory import MemoryStore
from promptfirewall.victim_app.model import DeterministicMockModel
from promptfirewall.victim_app.rag import KeywordRetriever, RetrievalResult
from promptfirewall.victim_app.service import VictimRunResult, VictimService
from promptfirewall.victim_app.tools import RefundLedgerEntry, SandboxedMockTools

SAFE_RESPONSE = "I cannot complete that request because it was blocked by the firewall."
# Timed-out synchronous providers cannot be killed safely. Limit abandoned calls;
# their daemon workers can only return model data, never execute tools or save state.
_MODEL_SLOTS = BoundedSemaphore(16)


class DefenseBlockedError(RuntimeError):
    """Internal control flow for an explicit defense rejection."""


class TokenBudgetExceeded(RuntimeError):
    """The model exceeded, or exhausted, the run's output-token budget."""


class RunBudget:
    def __init__(self, timeout_seconds: float, token_budget: int, seed: int = 7) -> None:
        self.timeout_seconds = timeout_seconds
        self.deadline = time.monotonic() + timeout_seconds
        self.remaining_tokens = token_budget
        self.seed = seed

    def check(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("run deadline exceeded")
        return remaining

    def complete(self, model: SyncModel, request: ModelRequest) -> ModelResponse:
        remaining = self.check()
        if self.remaining_tokens <= 0:
            raise TokenBudgetExceeded("run output-token budget exhausted")
        # Keep the offline model's fingerprint reproducible; its actual elapsed
        # time is still checked before tools. Network providers get remaining time.
        offline = type(model) is DeterministicMockModel
        bounded = request.model_copy(deep=True, update={
            "timeout_seconds": min(120.0, self.timeout_seconds if offline else remaining),
            "max_tokens": self.remaining_tokens,
            "parameters": {**request.parameters, "seed": self.seed},
        })
        if offline:
            response = model.complete(bounded)
        else:
            if not _MODEL_SLOTS.acquire(timeout=remaining):
                raise TimeoutError("model capacity unavailable before run deadline")
            future: Future[ModelResponse] = Future()

            def invoke() -> None:
                try:
                    future.set_result(model.complete(bounded))
                except BaseException as error:
                    future.set_exception(error)
                finally:
                    _MODEL_SLOTS.release()

            Thread(target=invoke, name="firewall-model", daemon=True).start()
            try:
                response = future.result(timeout=self.check())
            except FutureTimeoutError as error:
                raise TimeoutError("model exceeded run deadline") from error
        self.check()
        if not isinstance(response, ModelResponse):
            raise TypeError("model must return ModelResponse")
        used = response.output_tokens
        if used is None:
            # Explicit fallback for adapters without usage: a conservative byte
            # bound, including structured calls, rather than silently unbounded output.
            rendered = response.text + "".join(
                call.model_dump_json() for call in response.tool_calls
            )
            used = max(1, len(rendered.encode("utf-8")))
        if used < 0 or used > self.remaining_tokens:
            raise TokenBudgetExceeded("model exceeded run output-token budget")
        self.remaining_tokens -= used
        return response


@contextmanager
def fresh_victim(template: VictimService | None = None) -> Iterator[VictimService]:
    """Copy configuration, never memory, ledgers, or a shared filesystem sandbox.

    Model adapters are used through their stateless complete(request) interface;
    no attributes of the supplied service or model are changed during a run.
    """
    with TemporaryDirectory(prefix="promptfirewall-chat-") as directory:
        if template is None:
            service = VictimService(tools=SandboxedMockTools(sandbox_root=Path(directory)))
        else:
            service = copy(template)
            service.memory = MemoryStore()
            service.retriever = deepcopy(template.retriever)
            service.tools = SandboxedMockTools(
                fixtures=template.fixtures,
                sandbox_root=Path(directory),
                approved_email_recipients=template.tools.approved_email_recipients,
            )
            service.trace_callback = None
        yield service


class EnforcedRun:
    """Enforce each boundary on an isolated victim; optionally execute several turns."""

    def __init__(
        self,
        victim: VictimService,
        pipeline: DefensePipeline,
        identity: TestIdentity,
        *,
        run_id: str,
        session_id: str,
        budget: RunBudget | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.identity = identity
        self.run_id = run_id
        self.session_id = session_id
        self.budget = budget or RunBudget(10.0, 700)
        self.context = DefenseContext(
            run_id=run_id,
            correlation_id=run_id,
            identity=identity.model_dump(mode="json"),
        )
        self.events: list[TraceEvent] = []
        self.decisions: list[DefenseDecision] = []
        self.blocked = False
        self.block_reason: str | None = None
        self.injected_documents: tuple[RetrievalResult, ...] = ()
        self.injected_messages: tuple[ModelMessage, ...] = ()
        self.history: list[ModelMessage] = []
        # Wrappers are installed only on a local copy, never the supplied service.
        self.service = copy(victim)
        self.service.retriever = _DefendedRetriever(victim.retriever, self)
        self.service.tools = _DefendedTools(victim.tools, self)
        self.service.model = _DefendedModel(victim.model, self)
        self.emit(TraceEventType.RUN_STARTED, "run", {"profile_id": pipeline.profile_id})
        self.emit(TraceEventType.SESSION_INITIALIZED, "session", {"session_id": session_id})

    def emit(self, event_type: TraceEventType, stage: str, payload: dict[str, Any]) -> None:
        self.events.append(TraceEvent(
            event_id=f"{self.run_id}-event-{len(self.events) + 1:04d}",
            run_id=self.run_id,
            sequence=len(self.events) + 1,
            event_type=event_type,
            stage=stage,
            correlation_id=self.run_id,
            payload=payload,
        ))

    def observe(self, result: PipelineResult, *, tool_name: str | None = None) -> None:
        for decision in result.decisions:
            public = decision.model_copy(update={"payload": None})
            self.decisions.append(public)
            event_type = {
                "input": TraceEventType.INPUT_EVALUATED,
                "context": TraceEventType.CONTEXT_FILTERED,
                "prompt": TraceEventType.INPUT_EVALUATED,
                "tool": (TraceEventType.TOOL_DENIED if decision.action is DefenseAction.BLOCK
                         else TraceEventType.TOOL_AUTHORIZED),
                "output": TraceEventType.OUTPUT_EVALUATED,
            }[decision.stage.value]
            self.emit(event_type, decision.stage.value, {
                "defense_id": decision.defense_id,
                "action": decision.action.value,
                "reason_code": decision.reason_code,
                "metadata": decision.metadata,
            })
            self.events[-1] = self.events[-1].model_copy(update={
                "defense_id": decision.defense_id, "tool_name": tool_name,
            })
        if result.blocked:
            self.blocked = True
            self.block_reason = (
                result.last_decision.reason_code if result.last_decision else "defense_blocked"
            )

    def filter_items(self, items: Sequence[Any]) -> tuple[Any, ...]:
        self.budget.check()
        result = self.pipeline.process_context(items, self.context)
        self.observe(result)
        if result.blocked:
            raise DefenseBlockedError(self.block_reason)
        content = result.payload.content
        if not isinstance(content, (tuple, list)):
            raise TypeError("context defense must return a sequence")
        return tuple(content)

    def deliver_memory(self, text: str) -> None:
        try:
            retained = self.filter_items([{"content": text, "trusted": False}])
        except DefenseBlockedError:
            return
        for item in retained:
            self.service.remember(
                run_id=self.run_id, session_id=self.session_id,
                key="catalog-delivery", value=item["content"], source="catalog_delivery",
            )

    def safe_response(self, original: ModelResponse | None = None) -> ModelResponse:
        if original is not None:
            return original.model_copy(update={
                "text": SAFE_RESPONSE, "tool_calls": [], "finish_reason": "content_filter",
                "provider_request_id": None,
            })
        return ModelResponse(
            text=SAFE_RESPONSE, provider="firewall", model=self.service.model.model_name,
            latency_ms=0.0, finish_reason="content_filter", is_mock=False,
        )

    def _capture(self, event: TraceEvent) -> None:
        if event.event_type not in {
            TraceEventType.RUN_STARTED, TraceEventType.SESSION_INITIALIZED,
            TraceEventType.RUN_COMPLETED, TraceEventType.MODEL_INVOKED,
        }:
            self.events.append(event)

    def run_turn(self, message: str) -> VictimRunResult:
        self.budget.check()
        try:
            if self.blocked:
                raise DefenseBlockedError(self.block_reason)
            result = self.pipeline.process_input(message, self.context)
            self.observe(result)
            if result.blocked:
                raise DefenseBlockedError(self.block_reason)
            effective = result.payload.content
            if not isinstance(effective, str) or not effective.strip():
                raise ValueError("input defense returned an empty or invalid message")
            victim_result = self.service.run(
                effective, self.identity, run_id=self.run_id, session_id=self.session_id,
                trace_callback=self._capture,
            )
            self.budget.check()
            if victim_result.access_denials:
                self.blocked = True
                self.block_reason = "context_access_denied"
            if self.blocked:
                victim_result = replace(victim_result, model_response=self.safe_response(
                    victim_result.model_response
                ))
            self.history.extend([
                ModelMessage(role="user", content=effective),
                ModelMessage(role="assistant", content=victim_result.text),
            ])
            return victim_result
        except DefenseBlockedError:
            return VictimRunResult(
                run_id=self.run_id, session_id=self.session_id, model_response=self.safe_response(),
                tool_results=(), retrieved=(), memory=(), trace_events=(),
            )

    def finish(self) -> tuple[TraceEvent, ...]:
        self.emit(TraceEventType.RUN_COMPLETED, "run", {"blocked": self.blocked})
        return tuple(event.model_copy(update={
            "event_id": f"{self.run_id}-event-{index:04d}", "sequence": index,
            "run_id": self.run_id, "correlation_id": self.run_id,
        }) for index, event in enumerate(self.events, 1))


class _DefendedRetriever(KeywordRetriever):
    def __init__(self, base: KeywordRetriever, run: EnforcedRun) -> None:
        self.base = base
        self.run = run

    def retrieve(
        self, query: str, *, tenant_id: str | None = None,
        identity: TestIdentity | None = None, limit: int = 3,
    ) -> tuple[RetrievalResult, ...]:
        retrieved = self.base.retrieve(query, tenant_id=tenant_id, identity=identity, limit=limit)
        return cast(tuple[RetrievalResult, ...], self.run.filter_items(
            (*self.run.injected_documents, *retrieved)
        ))


class _DefendedTools(SandboxedMockTools):
    def __init__(self, base: SandboxedMockTools, run: EnforcedRun) -> None:
        self.base = base
        self.run = run
        self.sandbox_root = base.sandbox_root

    @staticmethod
    def tool_definitions() -> tuple[ToolDefinition, ...]:
        return SandboxedMockTools.tool_definitions()

    def execute(
        self, call: ProposedToolCall | str, arguments: Mapping[str, Any] | None = None,
        *, identity: TestIdentity, run_id: str, trusted: bool = False,
    ) -> ToolResult:
        self.run.budget.check()
        if isinstance(call, str):
            call = ProposedToolCall(name=call, arguments=dict(arguments or {}), call_id="policy")
        result = self.run.pipeline.authorize_tool(call, self.run.context.model_copy(update={
            "identity": identity.model_dump(mode="json"), "trusted": trusted,
        }))
        self.run.observe(result, tool_name=call.name)
        if result.blocked:
            return ToolResult(
                success=False, tool_name=call.name, error_code=self.run.block_reason,
                message="Tool call blocked by the firewall.",
            )
        # Execute the validated effective call, never the original unvalidated data.
        effective = ProposedToolCall.model_validate(result.payload.content)
        tool_result = self.base.execute(
            effective, identity=identity, run_id=run_id, trusted=trusted
        )
        if not tool_result.success:
            self.run.blocked = True
            self.run.block_reason = tool_result.error_code
        # Tool results are also part of the public response. Keep successful
        # execution evidence, but never expose protected data through that path.
        output = self.run.pipeline.scan_output(
            json.dumps(tool_result.model_dump(mode="json"), ensure_ascii=False), self.run.context,
        )
        self.run.observe(output, tool_name=effective.name)
        if output.blocked or output.sanitized:
            self.run.blocked = True
            self.run.block_reason = "tool_output_redacted"
            tool_result = tool_result.model_copy(update={
                "data": {}, "message": "Tool output withheld by the firewall.",
            })
        return tool_result

    def refund_ledger(self, run_id: str) -> tuple[RefundLedgerEntry, ...]:
        return self.base.refund_ledger(run_id)

    def clear_run(self, run_id: str) -> None:
        self.base.clear_run(run_id)


class _DefendedModel(DeterministicMockModel):
    def __init__(self, base: SyncModel, run: EnforcedRun) -> None:
        self.base = base
        self.run = run
        self.model_name = base.model_name

    def complete(self, request: ModelRequest) -> ModelResponse:
        injected = self.run.filter_items([
            {"content": item.content, "role": item.role, "trusted": False}
            for item in self.run.injected_messages
        ]) if self.run.injected_messages else ()
        request = request.model_copy(update={"messages": [
            *self.run.history,
            *[ModelMessage(role=item["role"], content=item["content"]) for item in injected],
            *request.messages,
        ]})
        prompt = self.run.pipeline.process_prompt(request, self.run.context)
        self.run.observe(prompt)
        if prompt.blocked:
            raise DefenseBlockedError(self.run.block_reason)
        effective = prompt.payload.content
        if not isinstance(effective, ModelRequest):
            raise TypeError("prompt defense must return ModelRequest")
        self.run.emit(TraceEventType.MODEL_INVOKED, "model", {"model": self.model_name})
        response = self.run.budget.complete(self.base, effective)
        output = self.run.pipeline.scan_output(response, self.run.context.model_copy(update={
            "metadata": {"protected_prompt": effective.system_instructions},
        }))
        self.run.observe(output)
        if output.blocked:
            return self.run.safe_response(response)
        if output.sanitized:
            self.run.blocked = True
            self.run.block_reason = "output_redacted"
        if not isinstance(output.payload.content, ModelResponse):
            raise TypeError("output defense must return ModelResponse")
        return output.payload.content
