"""Replay helpers for a persisted run record."""

from __future__ import annotations

from promptfirewall.harness.jobs import RunRecord
from promptfirewall.harness.runner import ExperimentRunner


class RunReplayer:
    """Rerun one case/profile/repetition cell through a supplied runner."""

    def __init__(self, runner: ExperimentRunner | None = None) -> None:
        self.runner = runner or ExperimentRunner()

    def replay(self, record: RunRecord) -> RunRecord:
        return self.runner.replay(record)


def replay_run(record: RunRecord, *, runner: ExperimentRunner | None = None) -> RunRecord:
    return RunReplayer(runner).replay(record)


ReplayRunner = RunReplayer


__all__ = ["ReplayRunner", "RunReplayer", "replay_run"]
