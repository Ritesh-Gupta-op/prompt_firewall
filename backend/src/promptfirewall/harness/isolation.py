"""Fresh victim state for every experiment run."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from promptfirewall.contracts.models import SyncModel
from promptfirewall.victim_app.rag import KeywordRetriever
from promptfirewall.victim_app.service import TraceCallback, VictimService
from promptfirewall.victim_app.tools import SandboxedMockTools

VictimFactory = Callable[[], VictimService]


@dataclass
class IsolatedVictim:
    """Own one fresh service and its run-local filesystem sandbox."""

    run_id: str
    service: VictimService
    _sandbox: tempfile.TemporaryDirectory[str] | None = None

    def close(self) -> None:
        self.service.clear_run(self.run_id)
        if self._sandbox is not None:
            self._sandbox.cleanup()
            self._sandbox = None

    def __enter__(self) -> IsolatedVictim:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class IsolationFactory:
    """Build a new ``VictimService`` rather than reusing state between runs."""

    def __init__(self, victim_factory: VictimFactory | None = None) -> None:
        self.victim_factory = victim_factory

    def create(
        self,
        run_id: str,
        *,
        model: SyncModel | None = None,
        retriever: object | None = None,
        tools: object | None = None,
        trace_callback: TraceCallback | None = None,
    ) -> IsolatedVictim:
        if not run_id.strip():
            raise ValueError("run_id must be non-empty")
        if self.victim_factory is not None:
            service = self.victim_factory()
            if model is not None:
                service.model = model
            if retriever is not None:
                service.retriever = cast(KeywordRetriever, retriever)
            if tools is not None:
                service.tools = cast(SandboxedMockTools, tools)
            return IsolatedVictim(run_id=run_id, service=service)

        sandbox = tempfile.TemporaryDirectory(prefix="promptfirewall-run-")
        run_tools = tools or SandboxedMockTools(sandbox_root=Path(sandbox.name))
        service = VictimService(
            model=model,
            retriever=retriever,  # type: ignore[arg-type]
            tools=run_tools,  # type: ignore[arg-type]
            trace_callback=trace_callback,
        )
        return IsolatedVictim(run_id=run_id, service=service, _sandbox=sandbox)


def create_isolated_victim(run_id: str) -> IsolatedVictim:
    """Convenience constructor for callers that only need a fresh victim."""

    return IsolationFactory().create(run_id)


RunIsolation = IsolationFactory


__all__ = [
    "IsolationFactory",
    "IsolatedVictim",
    "RunIsolation",
    "VictimFactory",
    "create_isolated_victim",
]
