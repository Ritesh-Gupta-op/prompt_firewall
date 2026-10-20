"""API configuration at the existing harness's execution seams."""

from __future__ import annotations

from promptfirewall.adapters.bridge import create_sync_model
from promptfirewall.config import Settings
from promptfirewall.contracts.attacks import AttackDefinition, BenignCase
from promptfirewall.contracts.experiments import ExperimentCreate
from promptfirewall.contracts.models import SyncModel, TestIdentity
from promptfirewall.harness.runner import ExperimentRunner
from promptfirewall.storage.runner import RunnerRepository


class _ConfiguredRunner(ExperimentRunner):
    @staticmethod
    def _identity_for(
        case: AttackDefinition | BenignCase, request: ExperimentCreate,
    ) -> TestIdentity:
        identity = request.metadata.get("test_identity")
        if identity is not None:
            return TestIdentity.model_validate(identity)
        return ExperimentRunner._identity_for(case, request)


def make_runner(
    settings: Settings,
    request: ExperimentCreate,
    repository: RunnerRepository,
    run_ids: list[str],
) -> ExperimentRunner:
    class ConfiguredRunner(_ConfiguredRunner):
        @staticmethod
        def _model_for(request: ExperimentCreate, seed: int) -> SyncModel:
            return create_sync_model(
                settings, provider=request.model_provider, model_name=request.model_name, seed=seed,
            )

    identifiers = iter(run_ids)
    runner = ConfiguredRunner(
        repository=repository,
        run_id_factory=lambda: next(identifiers),
    )
    if len(runner.expand(request)) != len(run_ids):
        raise ValueError("Stored run IDs do not match the experiment matrix")
    return runner
