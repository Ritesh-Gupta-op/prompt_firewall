"""Deterministic, explainable prompt-injection input heuristics."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)
from promptfirewall.defenses.base import Defense, make_decision
from promptfirewall.defenses.input_normalization import normalize_text


@dataclass(frozen=True)
class HeuristicSignal:
    code: str
    pattern: str
    severity: str


_SIGNALS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction_override",
        re.compile(r"\b(ignore|disregard|forget)\b.{0,50}\b(previous|prior|system|rules?)\b", re.I),
        "high",
    ),
    (
        "prompt_disclosure_request",
        re.compile(
            r"\b(reveal|disclose|print|repeat|summari[sz]e)\b.{0,70}\b(system|private|hidden)\b"
            r".{0,30}\b(prompt|instruction|policy|rule)",
            re.I,
        ),
        "high",
    ),
    (
        "canary_disclosure_request",
        re.compile(r"\b(disclose|reveal|print|output)\b.{0,80}\bPF-[A-Z0-9-]+\b", re.I),
        "high",
    ),
    (
        "privilege_claim",
        re.compile(
            r"\b(i am|assume|pretend)\b.{0,45}\b(admin|administrator|supervisor|authorized)\b",
            re.I,
        ),
        "high",
    ),
    (
        "tool_side_effect_request",
        re.compile(
            r"\b(call|invoke|execute|send|write|issue|process)\b.{0,60}\b(mock_|refund|message|file)\b",
            re.I,
        ),
        "high",
    ),
    (
        "resource_abuse_request",
        re.compile(
            r"\b(\d{2,4}\s+times|repetit(?:ion|ive)|recursive(?:ly)?|expand.{0,15}\d+\s+levels?)\b",
            re.I,
        ),
        "medium",
    ),
    (
        "obfuscated_override",
        re.compile(r"1gn0r3.{0,45}(rul|pr3v10u5)|r3v34l.{0,30}pf-", re.I),
        "high",
    ),
)

_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


def _decoded_instruction_signal(text: str) -> HeuristicSignal | None:
    for token in _BASE64_TOKEN.findall(text):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
        if re.search(r"\b(disclose|reveal|ignore|follow)\b", decoded, re.I):
            return HeuristicSignal("encoded_instruction", token, "high")
    return None


def find_signals(text: str) -> tuple[HeuristicSignal, ...]:
    """Return stable, deduplicated signals for a string."""

    normalized = normalize_text(text)
    found = [
        HeuristicSignal(code, match.group(0), severity)
        for code, pattern, severity in _SIGNALS
        if (match := pattern.search(normalized)) is not None
    ]
    encoded = _decoded_instruction_signal(normalized)
    if encoded is not None:
        found.append(encoded)
    return tuple(found)


class InputHeuristic(Defense):
    """Block high-confidence injection and side-effect requests."""

    defense_id = "input-heuristic"
    stage = DefenseStage.INPUT

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        del context
        if not isinstance(payload.content, str):
            return make_decision(
                self,
                DefenseAction.BLOCK,
                "invalid_input_content",
                metadata={"expected": "string"},
            )
        signals = find_signals(payload.content)
        if not signals:
            return make_decision(
                self,
                DefenseAction.ALLOW,
                "no_injection_signal",
                payload=payload,
                metadata={"signals": []},
            )
        return make_decision(
            self,
            DefenseAction.BLOCK,
            signals[0].code,
            metadata={
                "signals": [signal.code for signal in signals],
                "severities": [signal.severity for signal in signals],
            },
        )


PromptInjectionHeuristic = InputHeuristic
InputHeuristicDefense = InputHeuristic


__all__ = [
    "HeuristicSignal",
    "InputHeuristic",
    "InputHeuristicDefense",
    "PromptInjectionHeuristic",
    "find_signals",
]
