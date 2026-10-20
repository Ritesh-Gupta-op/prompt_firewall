from __future__ import annotations

import time
from threading import Event
from typing import Any

import pytest
from pydantic import ValidationError

from promptfirewall.attacks.registry import get_attack
from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.models import ModelRequest, ModelResponse, ProposedToolCall
from promptfirewall.contracts.results import OutcomeLabel
from promptfirewall.contracts.traces import TraceEventType
from promptfirewall.harness import ExperimentRunner, ExperimentValidationError


class ProviderStub:
    model_name = "provider-test-model"

    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            text="Support is available.", provider="test-provider", model=self.model_name,
            output_tokens=10, latency_ms=0.0,
        )


def install_provider(monkeypatch: pytest.MonkeyPatch, model: ProviderStub) -> list[dict[str, Any]]:
    from promptfirewall.adapters import bridge

    configurations: list[dict[str, Any]] = []

    def create(settings: object = None, **kwargs: Any) -> ProviderStub:
        assert settings is None
        configurations.append(kwargs)
        return model

    monkeypatch.setattr(bridge, "create_sync_model", create)
    return configurations


def request_for(case_id: str, **kwargs: Any) -> ExperimentCreate:
    return ExperimentCreate(
        name="Boundary test", attack_ids=[case_id], defense_profile_ids=["none"], **kwargs,
    )


def test_default_mock_stays_offline_and_explicit_provider_failure_never_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from promptfirewall.adapters import bridge

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("explicit provider unavailable")

    monkeypatch.setattr(bridge, "create_sync_model", fail)
    runner = ExperimentRunner()
    mock = runner.run(request_for("attack-dpi-001")).runs[0]
    assert mock.status is RunStatus.COMPLETED
    assert mock.model_response is not None and mock.model_response.is_mock
    provider = runner.run(request_for(
        "attack-dpi-001", model_provider="explicit-provider", model_name="explicit-model",
    )).runs[0]
    assert provider.status is RunStatus.FAILED
    assert provider.outcome is OutcomeLabel.EXECUTION_ERROR
    assert provider.model_response is None
    assert provider.error and "explicit provider unavailable" in provider.error["message"]


def test_provider_receives_deadline_generation_budget_and_actual_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = ProviderStub()
    configurations = install_provider(monkeypatch, model)
    result = ExperimentRunner().run(request_for(
        "attack-dpi-001", model_provider="test-provider", model_name=model.model_name,
        random_seed=41, repetitions=2, timeout_seconds=1.5, token_budget=47,
        concurrency_limit=1,
    ))
    assert all(run.status is RunStatus.COMPLETED for run in result.runs)
    assert configurations == [
        {"provider": "test-provider", "model_name": model.model_name, "seed": seed}
        for seed in (41, 42)
    ]
    assert [request.parameters["seed"] for request in model.requests] == [41, 42]
    assert all(request.max_tokens == 47 for request in model.requests)
    assert all(0 < request.timeout_seconds <= 1.5 for request in model.requests)
    assert all(run.model_response and not run.model_response.is_mock for run in result.runs)
    # The catalog attack is not classified as successful merely because it was delivered.
    assert all(run.outcome is OutcomeLabel.ATTACK_BLOCKED for run in result.runs)


@pytest.mark.parametrize(("case_id", "role"), [
    ("attack-ipi-001", "context"),
    ("attack-ipi-002", "tool"),
    ("attack-mp-001", "memory"),
])
@pytest.mark.parametrize("profile", ["none", "full-stack"])
def test_non_user_deliveries_use_declared_channels_and_context_filters(
    monkeypatch: pytest.MonkeyPatch, case_id: str, role: str, profile: str,
) -> None:
    model = ProviderStub()
    install_provider(monkeypatch, model)
    attack = get_attack(case_id)
    run = ExperimentRunner().run(ExperimentCreate(
        name="Delivery", attack_ids=[case_id], defense_profile_ids=[profile],
        model_provider="test-provider", model_name=model.model_name,
    )).runs[0]
    assert run.status is RunStatus.COMPLETED
    assert len(model.requests) == 1
    messages = model.requests[0].messages
    assert all(
        attack.payload_template not in item.content for item in messages if item.role == "user"
    )
    delivered = any(
        attack.payload_template in item.content for item in messages if item.role == role
    )
    assert delivered is (profile == "none")
    if role == "memory":
        assert run.state_before == {"memory": [], "refunds": []}
        assert run.state_after is not None
        assert bool(run.state_after["memory"]) is (profile == "none")
    if profile == "full-stack":
        decisions = run.evidence["defense_decisions"]
        assert any(item["reason_code"] == "context_items_filtered" for item in decisions)
        assert all(item["payload"] is None for item in decisions)
    assert run.judge_results
    assert run.state_after is not None


def test_multiturn_history_and_earlier_response_evidence_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EarlyLeak(ProviderStub):
        def complete(self, request: ModelRequest) -> ModelResponse:
            response = super().complete(request)
            return response.model_copy(update={
                "text": "PF-CANARY-MULTI-001" if len(self.requests) == 1 else "All done.",
            })

    model = EarlyLeak()
    install_provider(monkeypatch, model)
    run = ExperimentRunner().run(request_for(
        "attack-mt-001", model_provider="test-provider", token_budget=25,
    )).runs[0]
    assert run.status is RunStatus.COMPLETED
    assert len(model.requests) == 2
    assert [item.max_tokens for item in model.requests] == [25, 15]
    second_messages = model.requests[1].messages
    assert get_attack("attack-mt-001").turns[0] == second_messages[0].content
    assert second_messages[1].role == "assistant"
    assert "PF-CANARY-MULTI-001" in second_messages[1].content
    assert run.model_response and run.model_response.text == "All done."
    assert run.response_text and "PF-CANARY-MULTI-001" in run.response_text
    assert run.evidence["turn_count"] == 2
    assert run.outcome is OutcomeLabel.ATTACK_SUCCEEDED


def test_token_budget_is_shared_across_turns_and_failure_retains_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = ProviderStub()
    install_provider(monkeypatch, model)
    run = ExperimentRunner().run(request_for(
        "attack-mt-001", model_provider="test-provider", token_budget=15,
    )).runs[0]
    assert run.status is RunStatus.FAILED
    assert run.outcome is OutcomeLabel.EXECUTION_ERROR
    assert run.error and run.error["type"] == "TokenBudgetExceeded"
    assert [item.max_tokens for item in model.requests] == [15, 5]
    assert run.response_text == "Support is available."
    assert run.state_before == run.state_after
    assert run.evidence["turn_count"] == 1
    assert run.trace_events[-1].event_type is TraceEventType.RUN_FAILED


def test_deadline_returns_without_waiting_for_provider_and_late_tool_calls_are_discarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release, finished = Event(), Event(), Event()

    class SlowProvider(ProviderStub):
        def complete(self, request: ModelRequest) -> ModelResponse:
            entered.set()
            release.wait(3)
            response = super().complete(request).model_copy(update={"tool_calls": [
                ProposedToolCall(
                    name="mock_refund", call_id="late", arguments={
                        "order_id": "order-demo-018", "amount_minor": 100, "approved": True,
                    },
                ),
            ]})
            finished.set()
            return response

    model = SlowProvider()
    install_provider(monkeypatch, model)
    started = time.monotonic()
    try:
        run = ExperimentRunner().run(request_for(
            "attack-dpi-001", model_provider="test-provider", timeout_seconds=0.08,
        )).runs[0]
        elapsed = time.monotonic() - started
        assert entered.is_set()
        assert elapsed < 1.0
        assert not finished.is_set()
        assert run.status is RunStatus.FAILED
        assert run.error and run.error["type"] == "TimeoutError"
        assert run.model_response is None
        assert not run.tool_results
        assert run.state_before == run.state_after
        assert not any(
            event.event_type is TraceEventType.TOOL_EXECUTED for event in run.trace_events
        )
        saved_trace = run.trace_events
    finally:
        release.set()
    assert finished.wait(1)
    assert run.trace_events == saved_trace
    assert not run.tool_results


def test_expired_deadline_during_context_delivery_retains_real_failure() -> None:
    run = ExperimentRunner().run(request_for(
        "attack-mp-001", timeout_seconds=0.000000001,
    )).runs[0]
    assert run.status is RunStatus.FAILED
    assert run.error and run.error["type"] == "TimeoutError"
    assert run.evidence["turn_count"] == 0
    assert run.state_before == run.state_after
    assert run.trace_events[-1].event_type is TraceEventType.RUN_FAILED


def test_profile_normalization_rejects_alias_duplicates_and_empty_matrix() -> None:
    request = ExperimentCreate(
        name="Canonical", attack_ids=["attack-dpi-001"], defense_profile_ids=[" FULL_STACK "],
    )
    assert request.defense_profile_ids == ["full-stack"]
    assert ExperimentRunner().expand(request)[0].profile_id == "full-stack"
    for profiles in ([], [""], ["full-stack", "FULL_STACK"]):
        with pytest.raises(ValidationError):
            ExperimentCreate(name="Invalid", attack_ids=["attack-dpi-001"],
                             defense_profile_ids=profiles)
    with pytest.raises(ExperimentValidationError, match="unique"):
        ExperimentRunner().expand(request.model_copy(update={
            "defense_profile_ids": ["full-stack", "FULL_STACK"],
        }))


def test_replay_uses_actual_repetition_seed_and_preserves_generation_options() -> None:
    runner = ExperimentRunner()
    original = runner.run(request_for(
        "attack-dpi-001", random_seed=50, repetitions=3, token_budget=91,
        timeout_seconds=4.5,
    )).runs[2]
    assert original.seed == 52
    replayed = runner.replay(original)
    assert replayed.seed == 52
    assert replayed.metadata["token_budget"] == 91
    assert replayed.metadata["timeout_seconds"] == 4.5
    assert replayed.id != original.id
    assert replayed.metadata["replayed_from"] == original.id
    assert replayed.model_response == original.model_response
    assert replayed.outcome == original.outcome


def test_replay_preserves_explicit_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    model = ProviderStub()
    configurations = install_provider(monkeypatch, model)
    runner = ExperimentRunner()
    original = runner.run(request_for(
        "attack-dpi-001", model_provider="test-provider", model_name=model.model_name,
        random_seed=30, repetitions=2,
    )).runs[1]
    replayed = runner.replay(original)
    assert replayed.status is RunStatus.COMPLETED
    assert configurations[-1] == {
        "provider": "test-provider", "model_name": model.model_name, "seed": 31,
    }
