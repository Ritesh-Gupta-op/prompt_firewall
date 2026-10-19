"""Composable defense execution for individual observable stages."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseProfile,
)
from promptfirewall.defenses.registry import DEFAULT_REGISTRY, DefenseRegistry


@dataclass(frozen=True)
class PipelineResult:
    payload: DefensePayload
    decisions: tuple[DefenseDecision, ...]

    @property
    def blocked(self) -> bool:
        return any(decision.action is DefenseAction.BLOCK for decision in self.decisions)

    @property
    def sanitized(self) -> bool:
        return any(decision.action is DefenseAction.SANITIZE for decision in self.decisions)

    @property
    def allowed(self) -> bool:
        return not self.blocked

    @property
    def last_decision(self) -> DefenseDecision | None:
        return self.decisions[-1] if self.decisions else None


class DefensePipeline:
    """Apply only defenses enabled by a profile, except tool host safety.

    ``none`` means no experimental controls.  It never means that a model can
    bypass the deterministic tool policy.
    """

    def __init__(
        self,
        profile: str | DefenseProfile = "none",
        *,
        registry: DefenseRegistry = DEFAULT_REGISTRY,
    ) -> None:
        self.registry = registry
        self.profile = registry.get_profile(profile) if isinstance(profile, str) else profile
        defenses = registry.defenses_for(self.profile)
        if "tool-policy" not in {defense.defense_id for defense in defenses}:
            try:
                defenses = (*defenses, registry.get("tool-policy"))
            except KeyError:
                pass
        self._defenses = defenses

    @property
    def profile_id(self) -> str:
        return self.profile.id

    @property
    def active_defense_ids(self) -> tuple[str, ...]:
        return tuple(defense.defense_id for defense in self._defenses)

    def process(self, payload: DefensePayload, context: DefenseContext) -> PipelineResult:
        """Run defenses applicable to a payload kind in stable profile order."""

        current = payload
        decisions: list[DefenseDecision] = []
        for defense in self._defenses:
            # Tool policy is the only tool-stage defense and is deliberately
            # present in every built-in profile.
            if not _applies(defense.defense_id, current.kind):
                continue
            decision = defense.evaluate(current, context)
            decisions.append(decision)
            if decision.payload is not None:
                current = decision.payload
            if decision.action is DefenseAction.BLOCK:
                break
        return PipelineResult(payload=current, decisions=tuple(decisions))

    def process_input(self, text: str, context: DefenseContext) -> PipelineResult:
        return self.process(DefensePayload(kind="input", content=text), context)

    def process_context(
        self,
        items: Sequence[Any] | dict[str, Any],
        context: DefenseContext,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> PipelineResult:
        return self.process(
            DefensePayload(kind="context", content=items, metadata=metadata or {}),
            context,
        )

    def process_prompt(self, prompt: Any, context: DefenseContext) -> PipelineResult:
        return self.process(DefensePayload(kind="prompt", content=prompt), context)

    def authorize_tool(self, call: Any, context: DefenseContext) -> PipelineResult:
        return self.process(DefensePayload(kind="tool", content=call), context)

    def scan_output(self, output: Any, context: DefenseContext) -> PipelineResult:
        return self.process(DefensePayload(kind="output", content=output), context)


def _applies(defense_id: str, kind: str) -> bool:
    if kind == "input":
        return defense_id in {"input-normalization", "input-heuristic"}
    if kind == "context":
        return defense_id == "context-filter"
    if kind == "prompt":
        return defense_id == "prompt-profile"
    if kind in {"tool", "tool_call"}:
        return defense_id == "tool-policy"
    if kind == "output":
        return defense_id == "output-scanner"
    return False


__all__ = ["DefensePipeline", "PipelineResult"]
