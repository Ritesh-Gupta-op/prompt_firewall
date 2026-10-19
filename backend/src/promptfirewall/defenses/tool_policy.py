"""Deterministic host-side policy for every model-proposed tool call."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)
from promptfirewall.contracts.models import ProposedToolCall
from promptfirewall.defenses.base import Defense, make_decision, replace_payload

ALLOWED_TOOLS = frozenset(
    {"mock_lookup", "mock_refund", "mock_message", "mock_file_write", "mock_http_get"}
)
READ_ONLY_TOOLS = frozenset({"mock_lookup", "mock_http_get"})
SIDE_EFFECT_TOOLS = ALLOWED_TOOLS - READ_ONLY_TOOLS
APPROVED_RECIPIENTS = frozenset(
    {"support@mock.local", "mock-recipient-001", "mock-recipient-001@mock.local"}
)
MOCK_HTTP_PATHS = frozenset({"/fixtures/status", "/fixtures/support-hours"})
_RECORD_RE = re.compile(r"^(?:ticket|order)-demo-\d{3}$", re.I)


def _call(value: ProposedToolCall | Mapping[str, Any] | Any) -> ProposedToolCall | None:
    if isinstance(value, ProposedToolCall):
        return value
    if isinstance(value, Mapping):
        try:
            return ProposedToolCall.model_validate(value)
        except Exception:
            return None
    return None


def _role(context: DefenseContext) -> str:
    role = context.identity.get("role", "")
    return getattr(role, "value", role).casefold() if isinstance(role, str) else ""


def _valid_http_url(url: Any) -> bool:
    if not isinstance(url, str):
        return False
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and parsed.hostname == "mock.local"
        and parsed.username is None
        and parsed.password is None
        and port is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path in MOCK_HTTP_PATHS
    )


def _valid_fixture_path(path: Any) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    parsed = urlsplit(path)
    if parsed.scheme != "fixture" or parsed.query or parsed.fragment:
        return False
    relative = f"{parsed.netloc}{parsed.path}"
    return bool(relative) and not relative.startswith("/") and ".." not in relative.split("/")


class ToolPolicy(Defense):
    """Authorize only known, well-formed, locally bounded tool calls.

    This defense is intentionally active in every profile.  Prompt profiles and
    filters are experimental controls; this policy is the host safety boundary.
    """

    defense_id = "tool-policy"
    stage = DefenseStage.TOOL

    def authorize(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        return self.evaluate(payload, context)

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        call = _call(payload.content)
        if call is None:
            return make_decision(self, DefenseAction.BLOCK, "invalid_tool_call")
        if call.name not in ALLOWED_TOOLS:
            return make_decision(
                self,
                DefenseAction.BLOCK,
                "unknown_tool",
                metadata={"tool_name": call.name},
            )

        validation_error = self._validate_arguments(call)
        if validation_error is not None:
            return make_decision(
                self,
                DefenseAction.BLOCK,
                validation_error,
                metadata={"tool_name": call.name},
            )
        if call.name in SIDE_EFFECT_TOOLS:
            if not context.trusted:
                return make_decision(
                    self,
                    DefenseAction.BLOCK,
                    "tool_requires_trusted_approval",
                    metadata={"tool_name": call.name},
                )
            if _role(context) != "admin":
                return make_decision(
                    self,
                    DefenseAction.BLOCK,
                    "tool_requires_admin_identity",
                    metadata={"tool_name": call.name},
                )
            if call.arguments.get("approved") is not True:
                return make_decision(
                    self,
                    DefenseAction.BLOCK,
                    "tool_requires_structured_approval",
                    metadata={"tool_name": call.name},
                )

        output = replace_payload(payload, call.model_dump(mode="json"))
        return make_decision(
            self,
            DefenseAction.ALLOW,
            "read_only_tool_allowed" if call.name in READ_ONLY_TOOLS else "approved_tool_allowed",
            payload=output,
            metadata={"tool_name": call.name, "trusted": context.trusted},
        )

    @staticmethod
    def _validate_arguments(call: ProposedToolCall) -> str | None:
        arguments = call.arguments
        if call.name == "mock_lookup":
            return (
                None
                if _RECORD_RE.fullmatch(arguments.get("record_id", ""))
                else "invalid_record_id"
            )
        if call.name == "mock_http_get":
            return None if _valid_http_url(arguments.get("url")) else "url_not_allowlisted"
        if call.name == "mock_refund":
            order_id = arguments.get("order_id")
            amount = arguments.get("amount_minor")
            if not _RECORD_RE.fullmatch(order_id or "") or (
                isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0
            ):
                return "invalid_refund_arguments"
        elif call.name == "mock_message":
            if (
                not isinstance(arguments.get("recipient"), str)
                or arguments["recipient"] not in APPROVED_RECIPIENTS
                or not isinstance(arguments.get("message"), str)
                or not arguments["message"].strip()
            ):
                return "invalid_message_arguments"
        elif call.name == "mock_file_write":
            content = arguments.get("content")
            if not _valid_fixture_path(arguments.get("path")) or not isinstance(content, str):
                return "invalid_file_arguments"
            if len(content.encode("utf-8")) > 16_384:
                return "file_too_large"
        return None


ToolAuthorizationPolicy = ToolPolicy
ToolPolicyDefense = ToolPolicy


__all__ = [
    "ALLOWED_TOOLS",
    "READ_ONLY_TOOLS",
    "SIDE_EFFECT_TOOLS",
    "ToolAuthorizationPolicy",
    "ToolPolicy",
    "ToolPolicyDefense",
]
