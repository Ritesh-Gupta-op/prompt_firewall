"""Bounded, lifecycle-owned experiment jobs with durable progress and cancellation."""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from promptfirewall.api.execution import make_runner
from promptfirewall.config import Settings
from promptfirewall.contracts.experiments import ExperimentCreate
from promptfirewall.harness.jobs import CancellationToken
from promptfirewall.storage.repository import StorageRepository
from promptfirewall.storage.runner import RunnerRepository

logger = logging.getLogger(__name__)


class ExperimentJobManager(Protocol):
    async def submit(self, experiment_id: str) -> None:
        """Queue an experiment for execution."""

    async def cancel(self, experiment_id: str) -> None:
        """Request cooperative cancellation for an experiment."""


class JobQueueFull(RuntimeError):
    """The bounded in-process queue has no free slots."""


class InProcessJobManager:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        max_queued: int = 32,
    ) -> None:
        if max_queued < 1:
            raise ValueError("max_queued must be positive")
        self.session_factory = session_factory
        self.settings = settings
        self._queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=max_queued)
        self._tokens: dict[str, CancellationToken] = {}
        self._workers: list[asyncio.Task[None]] = []
        self._accepting = False

    async def start(self) -> None:
        if self._workers:
            return
        self._accepting = True
        self._workers = [
            asyncio.create_task(self._worker(), name=f"experiment-worker-{index}")
            for index in range(self.settings.worker_count)
        ]

    async def submit(self, experiment_id: str) -> None:
        if not self._accepting:
            raise RuntimeError("Experiment workers are not accepting jobs")
        if experiment_id in self._tokens:
            return
        try:
            self._queue.put_nowait(experiment_id)
        except asyncio.QueueFull as error:
            raise JobQueueFull("Experiment queue is full") from error
        self._tokens[experiment_id] = CancellationToken()

    async def cancel(self, experiment_id: str) -> None:
        token = self._tokens.get(experiment_id)
        if token is not None:
            token.cancel()

    async def close(self) -> None:
        self._accepting = False
        for experiment_id, token in tuple(self._tokens.items()):
            token.cancel()
            async with self.session_factory() as session:
                await StorageRepository(session).cancel_experiment(experiment_id)
        # Do not cancel to_thread tasks: their threads may still need this loop and
        # database to finish persisting evidence. Drain before disposing the engine.
        await self._queue.join()
        for _ in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers)
        self._workers.clear()

    async def _worker(self) -> None:
        while True:
            experiment_id = await self._queue.get()
            try:
                if experiment_id is None:
                    return
                await self._execute(experiment_id, self._tokens[experiment_id])
            except Exception as error:
                logger.exception("Experiment %s failed", experiment_id)
                if experiment_id is not None:
                    try:
                        async with self.session_factory() as session:
                            await StorageRepository(session).fail_experiment(
                                experiment_id,
                                {"code": "experiment_execution_error", "type": type(error).__name__,
                                 "message": str(error)},
                            )
                    except Exception:
                        logger.exception("Could not persist experiment failure")
            finally:
                if experiment_id is not None:
                    self._tokens.pop(experiment_id, None)
                self._queue.task_done()

    async def _execute(self, experiment_id: str, token: CancellationToken) -> None:
        async with self.session_factory() as session:
            repository = StorageRepository(session)
            experiment = await repository.get_experiment(experiment_id)
            if experiment is None or experiment.status != "queued":
                return
            runs = await repository.list_runs(experiment_id=experiment_id, limit=100_000)
        if token.cancelled:
            return
        request = ExperimentCreate.model_validate(experiment.config)
        request = request.model_copy(update={
            "concurrency_limit": min(request.concurrency_limit, self.settings.worker_count),
        })
        runs.sort(key=lambda run: run.input_payload["matrix_index"])
        bridge = RunnerRepository(self.session_factory, asyncio.get_running_loop())
        runner = make_runner(self.settings, request, bridge, [run.id for run in runs])
        await asyncio.to_thread(
            runner.run, request, experiment_id=experiment_id, cancellation=token,
        )


__all__ = ["ExperimentJobManager", "InProcessJobManager", "JobQueueFull"]
