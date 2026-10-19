"""The narrow job-manager seam used by experiment routes.

The benchmark runner is intentionally outside this change. A production runner
can implement ``ExperimentJobManager`` and be passed to ``create_app``; the
default implementation records submission/cancellation requests and performs no
work.
"""

from __future__ import annotations

from typing import Protocol


class ExperimentJobManager(Protocol):
    async def submit(self, experiment_id: str) -> None:
        """Queue an experiment for execution."""

    async def cancel(self, experiment_id: str) -> None:
        """Request cooperative cancellation for an experiment."""


class InProcessJobManager:
    """No-op hook that keeps API persistence usable before the runner exists."""

    def __init__(self) -> None:
        self.submitted: list[str] = []
        self.cancelled: list[str] = []

    async def submit(self, experiment_id: str) -> None:
        self.submitted.append(experiment_id)

    async def cancel(self, experiment_id: str) -> None:
        self.cancelled.append(experiment_id)


__all__ = ["ExperimentJobManager", "InProcessJobManager"]
