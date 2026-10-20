"""Common interfaces and helpers for composable defenses."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)


class Defense(ABC):
    """A deterministic transformation or decision at one pipeline stage."""

    defense_id: str
    stage: DefenseStage

    @abstractmethod
    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        """Evaluate ``payload`` and optionally return a transformed payload."""

    def __call__(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        return self.evaluate(payload, context)

    def apply(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        """Named alias for callers that treat a defense as a transformation."""

        return self.evaluate(payload, context)


def make_decision(
    defense: Defense,
    action: DefenseAction,
    reason_code: str,
    *,
    payload: DefensePayload | None = None,
    metadata: dict[str, Any] | None = None,
) -> DefenseDecision:
    """Build a decision with the identity and stage declared by a defense."""

    return DefenseDecision(
        defense_id=defense.defense_id,
        stage=defense.stage,
        action=action,
        reason_code=reason_code,
        payload=payload,
        metadata=metadata or {},
    )


def replace_payload(
    payload: DefensePayload,
    content: Any,
    *,
    original_content: Any | None = None,
    metadata: dict[str, Any] | None = None,
) -> DefensePayload:
    """Create an effective payload without retaining sensitive pre-filter content.

    The legacy argument is accepted for callers, but originals must never survive
    serialization of a sanitized decision or pipeline result.
    """

    del original_content
    merged_metadata = {**payload.metadata, **(metadata or {})}
    return payload.model_copy(
        update={
            "content": content,
            "original_content": None,
            "metadata": merged_metadata,
        }
    )


__all__ = ["Defense", "make_decision", "replace_payload"]
