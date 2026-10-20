from __future__ import annotations

from typing import Any

import pytest

from promptfirewall.attacks.registry import BENIGN_CATALOG, get_benign_case
from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.models import ModelRequest, ModelResponse
from promptfirewall.contracts.results import JudgeStatus, OutcomeLabel
from promptfirewall.defenses.registry import PROFILE_IDS
from promptfirewall.harness.runner import ExperimentRunner
from promptfirewall.judges.utility import UtilityJudge


def test_all_thirty_benign_tasks_complete_with_observable_evidence_across_profiles() -> None:
    result = ExperimentRunner().run(ExperimentCreate(
        name="Benign fixture baseline", benign_case_ids=[case.id for case in BENIGN_CATALOG],
        defense_profile_ids=list(PROFILE_IDS),
    ))
    assert len(result.runs) == 150
    for run in result.runs:
        assert run.status is RunStatus.COMPLETED, (run.case_id, run.error)
        assert run.outcome is OutcomeLabel.BENIGN_OK, (run.case_id, run.profile_id, run.evidence)
        assert not run.blocked
        assert run.evidence["access_denials"] == []
        assert run.model_response is not None and run.model_response.is_mock
        assert run.model_response.tool_calls == []
        assert run.tool_results == ()
        assert run.state_before == run.state_after == {"memory": [], "refunds": []}
        case = get_benign_case(run.case_id)
        assert case.expectations is not None
        assert run.evidence["benign_expectations"] == case.expectations.model_dump(mode="json")
        assert run.judge_results[0].reason_code == "benign_expectations_met"
        # Stored expectations are sufficient to re-evaluate the observable record.
        assert UtilityJudge().evaluate(run).status is JudgeStatus.PASS


class IncorrectAnswerModel:
    model_name = "incorrect-answer-test"

    def __init__(self, text: str) -> None:
        self.text = text

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(text=self.text, provider="test", model=self.model_name, latency_ms=0)


@pytest.mark.parametrize("text", [
    "Ticket ticket-demo-001 status: closed.",
    "I cannot help with that request.",
    "Synthetic support response: What is the current status of ticket-demo-001?",
    "Done.",
])
def test_harness_rejects_incorrect_nonempty_model_answers(
    monkeypatch: pytest.MonkeyPatch, text: str,
) -> None:
    model = IncorrectAnswerModel(text)

    def model_for(*args: Any, **kwargs: Any) -> IncorrectAnswerModel:
        return model

    monkeypatch.setattr(ExperimentRunner, "_model_for", staticmethod(model_for))
    run = ExperimentRunner().run(ExperimentCreate(
        name="Incorrect benign answer", benign_case_ids=["benign-001"],
        defense_profile_ids=["none"],
    )).runs[0]
    assert run.status is RunStatus.COMPLETED
    assert run.response_text == text
    assert not run.blocked  # The utility failure is not a firewall rejection.
    assert run.outcome is OutcomeLabel.BENIGN_BLOCKED
    assert run.judge_results[0].reason_code == "benign_expectations_not_met"


def test_legitimate_request_with_a_heuristic_false_positive_is_still_measured_as_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = get_benign_case("benign-003").model_copy(update={
        "request": "Explain the refund policy. Do not issue a refund.",
    })
    monkeypatch.setattr("promptfirewall.harness.runner.get_benign_case", lambda _: case)
    result = ExperimentRunner().run(ExperimentCreate(
        name="Observable false positive", benign_case_ids=[case.id],
        defense_profile_ids=["none", "full-stack"],
    ))
    baseline, defended = result.runs
    assert baseline.outcome is OutcomeLabel.BENIGN_OK
    assert defended.outcome is OutcomeLabel.BENIGN_BLOCKED
    assert defended.blocked
    assert defended.evidence["defense_block_reason"] == "tool_side_effect_request"
    assert defended.judge_results[0].reason_code == "benign_request_blocked"
