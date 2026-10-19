from __future__ import annotations

from threading import Event

import pytest

from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.results import OutcomeLabel
from promptfirewall.harness import (
    ExperimentRunner,
    ExperimentValidationError,
    InMemoryRunRepository,
)


def test_runner_expands_matrix_persists_runs_and_emits_ordered_trace_events() -> None:
    repository = InMemoryRunRepository()
    identifiers = iter(f"run-test-{index}" for index in range(10))
    runner = ExperimentRunner(repository=repository, run_id_factory=lambda: next(identifiers))
    request = ExperimentCreate(
        name="matrix",
        attack_ids=["attack-dpi-001"],
        benign_case_ids=["benign-001"],
        defense_profile_ids=["none", "full-stack"],
        repetitions=2,
        concurrency_limit=2,
    )

    result = runner.run(request, experiment_id="experiment-test")

    assert len(result.runs) == 8
    assert result.experiment.total_runs == 8
    assert {run.id for run in result.runs} == {f"run-test-{index}" for index in range(8)}
    assert all(run.status is RunStatus.COMPLETED for run in result.runs)
    assert result.runs[0].outcome is OutcomeLabel.ATTACK_SUCCEEDED
    assert result.runs[1].outcome is OutcomeLabel.ATTACK_SUCCEEDED
    full_stack = [run for run in result.runs if run.defense_profile_id == "full-stack"]
    assert all(run.outcome is OutcomeLabel.ATTACK_BLOCKED for run in full_stack[:2])
    assert all(
        [event.sequence for event in run.trace_events]
        == list(range(1, len(run.trace_events) + 1))
        for run in result.runs
    )
    assert all(
        repository.trace_events(run.id) == run.trace_events for run in result.runs
    )
    assert len(repository.list_runs("experiment-test")) == 8


def test_every_run_gets_fresh_victim_service() -> None:
    runner = ExperimentRunner()
    request = ExperimentCreate(
        name="isolated",
        attack_ids=["attack-mp-001"],
        defense_profile_ids=["none"],
        repetitions=2,
        concurrency_limit=1,
    )

    result = runner.run(request)

    assert len(result.runs) == 2
    assert result.runs[0].state_before == {"memory": [], "refunds": []}
    assert result.runs[1].state_before == {"memory": [], "refunds": []}
    assert result.runs[0].run_id != result.runs[1].run_id


def test_cancellation_marks_unstarted_cells_without_security_classification() -> None:
    cancellation = Event()
    cancellation.set()
    repository = InMemoryRunRepository()
    runner = ExperimentRunner(repository=repository)

    result = runner.run(
        ExperimentCreate(
            name="cancelled",
            attack_ids=["attack-dpi-001"],
            defense_profile_ids=["none"],
            repetitions=2,
        ),
        cancellation=cancellation,
    )

    assert result.status.value == "cancelled"
    assert all(run.status is RunStatus.CANCELLED for run in result.runs)
    assert all(run.outcome is None for run in result.runs)
    assert all(run.error and run.error["type"] == "CancellationRequested" for run in result.runs)
    assert all(
        event.sequence == index
        for run in result.runs
        for index, event in enumerate(run.trace_events, 1)
    )


def test_unknown_case_and_profile_are_explicit_validation_errors() -> None:
    runner = ExperimentRunner()

    with pytest.raises(ExperimentValidationError, match="unknown attack"):
        runner.expand(ExperimentCreate(name="bad", attack_ids=["missing-attack"]))
    with pytest.raises(ExperimentValidationError, match="unknown defense profile"):
        runner.expand(
            ExperimentCreate(
                name="bad-profile",
                benign_case_ids=["benign-001"],
                defense_profile_ids=["missing-profile"],
            )
        )
