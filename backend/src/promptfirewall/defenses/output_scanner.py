"""Scan model output for private canaries and hidden exfiltration channels."""

from __future__ import annotations

import re
from typing import Any

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)
from promptfirewall.contracts.models import ModelResponse
from promptfirewall.defenses.base import Defense, make_decision, replace_payload

_PRIVATE_CANARY_RE = re.compile(r"\bPF-(?:CANARY|DATA)-[A-Z0-9-]+\b", re.I)
_HIDDEN_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_PROMPT_DISCLOSURE_RE = re.compile(
    r"(?:here is|the following is|verbatim:).{0,35}"
    r"\b(?:system prompt|private policy|hidden instruction)\b",
    re.I | re.S,
)


def scan_text(text: str) -> tuple[str, tuple[str, ...]]:
    """Return redacted text and stable finding codes."""

    findings: list[str] = []

    def redact_canary(match: re.Match[str]) -> str:
        marker = match.group(0)
        if marker.casefold().startswith("pf-public-"):
            return marker
        findings.append("private_canary")
        return "[REDACTED_CANARY]"

    scanned = _PRIVATE_CANARY_RE.sub(redact_canary, text)
    if _HIDDEN_COMMENT_RE.search(scanned):
        findings.append("hidden_output_channel")
        scanned = _HIDDEN_COMMENT_RE.sub("[REDACTED_HIDDEN_OUTPUT]", scanned)
    if _PROMPT_DISCLOSURE_RE.search(scanned):
        findings.append("prompt_disclosure")
        scanned = _PROMPT_DISCLOSURE_RE.sub("[REDACTED_PROMPT_DISCLOSURE]", scanned)
    return scanned, tuple(dict.fromkeys(findings))


class OutputScanner(Defense):
    """Redact private output evidence before it leaves the application."""

    defense_id = "output-scanner"
    stage = DefenseStage.OUTPUT

    def scan(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        return self.evaluate(payload, context)

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        del context
        content = payload.content
        if isinstance(content, ModelResponse):
            scanned_text, findings = scan_text(content.text)
            output_content: Any = content.model_copy(update={"text": scanned_text})
        elif isinstance(content, str):
            scanned_text, findings = scan_text(content)
            output_content = scanned_text
        else:
            return make_decision(self, DefenseAction.BLOCK, "invalid_output_content")
        changed = output_content != content
        output = replace_payload(
            payload,
            output_content,
            original_content=content if changed else None,
            metadata={"findings": list(findings)},
        )
        return make_decision(
            self,
            DefenseAction.SANITIZE if findings else DefenseAction.ALLOW,
            "output_redacted" if findings else "output_clean",
            payload=output,
            metadata={"findings": list(findings)},
        )


OutputFilter = OutputScanner
OutputScannerDefense = OutputScanner


__all__ = ["OutputFilter", "OutputScanner", "OutputScannerDefense", "scan_text"]
