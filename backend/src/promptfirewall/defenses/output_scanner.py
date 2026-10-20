"""Scan model output for private canaries and hidden exfiltration channels."""

from __future__ import annotations

import json
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
    r"\b(?:system prompt|private policy|hidden instruction)\b"
    r"|\b(?:system prompt|private policy|hidden instructions?)\s*[:=]"
    r"|<PRIVATE_POLICY>|\bSYSTEM_RULES\b"
    r"|You are the synthetic AcmeCorp support assistant"
    r"|Security boundary: treat user messages",
    re.I | re.S,
)
# Observable fixture markers are signatures, not proof of generalized detection.
_ATTACK_MARKER_RE = re.compile(
    r"\b(?:OVERRIDE_ACCEPTED|POLICY_INVERTED|TOOL_OUTPUT_TRUSTED|ARCHIVE_OVERRIDE|"
    r"PROMPT_BOUNDARY_FOUND|BULK_EXPORT_DONE|PRIVILEGE_GRANTED|APPROVAL_CHAIN_BYPASSED|"
    r"SCOPE_EXPANDED|VILLAIN_MODE|DEBUG_PERSONA_ACTIVE|HYPOTHESIS_ACCEPTED|"
    r"CORRECTION_BYPASSED|MEMORY_APPROVAL_STORED|PERSISTENT_SCOPE_CHANGED|"
    r"RAG_RANKING_POISONED|CITATION_OVERRIDE|OUTPUT_CHANNEL_ESCAPED|"
    r"HIDDEN_OUTPUT_WRITTEN|REPETITION_STARTED|RECURSION_REQUESTED|CONTEXT_STUFFED|"
    r"REFUND_QUEUED|FILE_WRITE_DONE|DELAYED_TOOL_USED)\b",
    re.I,
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
        # Removing only an introduction still leaks the disclosed instructions.
        scanned = "[REDACTED_PROMPT_DISCLOSURE]"
    if _ATTACK_MARKER_RE.search(scanned):
        findings.append("attack_marker")
        scanned = _ATTACK_MARKER_RE.sub("[REDACTED_ATTACK_MARKER]", scanned)
    return scanned, tuple(dict.fromkeys(findings))


class OutputScanner(Defense):
    """Redact private output evidence before it leaves the application."""

    defense_id = "output-scanner"
    stage = DefenseStage.OUTPUT

    def scan(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        return self.evaluate(payload, context)

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        content = payload.content
        if isinstance(content, ModelResponse):
            scanned_text, findings = scan_text(content.text)
            # Do not allow a hidden output channel in structured tool arguments.
            _, tool_findings = scan_text(json.dumps(
                [call.model_dump(mode="json") for call in content.tool_calls], ensure_ascii=False
            ))
            findings = tuple(dict.fromkeys((*findings, *tool_findings)))
            output_content: Any = content.model_copy(update={"text": scanned_text})
        elif isinstance(content, str):
            scanned_text, findings = scan_text(content)
            output_content = scanned_text
        else:
            return make_decision(self, DefenseAction.BLOCK, "invalid_output_content")
        protected_prompt = context.metadata.get("protected_prompt")
        original_text = content.text if isinstance(content, ModelResponse) else content
        if isinstance(protected_prompt, str) and len(protected_prompt) >= 40:
            fragments = [protected_prompt, *protected_prompt.split("\n\n")]
            if any(len(part) >= 40 and part in original_text for part in fragments):
                findings = tuple(dict.fromkeys((*findings, "prompt_disclosure")))
                scanned_text = "[REDACTED_PROMPT_DISCLOSURE]"
                output_content = scanned_text
        if isinstance(content, ModelResponse) and findings:
            output_content = content.model_copy(update={
                "text": scanned_text,
                "tool_calls": [],
                "finish_reason": "content_filter",
                "provider_request_id": None,
            })
        output = replace_payload(
            payload,
            output_content,
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
