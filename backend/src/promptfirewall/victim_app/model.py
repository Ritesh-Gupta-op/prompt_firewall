"""Deterministic mock model adapter for the synthetic victim application."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from promptfirewall.contracts.models import (
    ModelRequest,
    ModelResponse,
    ProposedToolCall,
)

_CANARY_RE = re.compile(r"\bPF-[A-Z0-9-]+\b")


class DeterministicMockModel:
    """A predictable, intentionally simple model-shaped adapter.

    It can echo synthetic canaries and propose tools because it represents the
    victim model.  It never executes a tool; the service and tool policy remain
    the hard boundary for side effects.

    System instructions affect the deterministic fingerprint only; this mock
    does not interpret or obey hardened prompts. Its outputs cannot measure
    real-provider prompt-hardening or security performance.
    """

    def __init__(self, *, seed: int = 7, model_name: str = "promptfirewall-mock-1") -> None:
        self.seed = seed
        self.model_name = model_name

    def complete(self, request: ModelRequest) -> ModelResponse:
        fingerprint = self._fingerprint(request)
        digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        user_message = self._last_user_message(request)
        all_content = "\n".join(message.content for message in request.messages)
        context = "\n".join(
            message.content for message in request.messages if message.role == "context"
        )
        tool_calls = self._propose_tools(user_message, digest)
        text = self._answer(user_message, all_content, tool_calls, context)
        input_tokens = max(1, len(fingerprint.split()))
        output_tokens = max(1, len(text.split()))
        return ModelResponse(
            text=text,
            tool_calls=tool_calls,
            provider="mock",
            model=self.model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason="tool_call" if tool_calls else "stop",
            latency_ms=1.0 + (int(digest[:4], 16) % 100) / 100,
            provider_request_id=f"mock-{digest[:16]}",
            is_mock=True,
        )

    generate = complete

    def _fingerprint(self, request: ModelRequest) -> str:
        payload: dict[str, Any] = request.model_dump(mode="json")
        payload.pop("correlation_id", None)
        payload["adapter_seed"] = self.seed
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _last_user_message(request: ModelRequest) -> str:
        for message in reversed(request.messages):
            if message.role == "user":
                return message.content
        return ""

    def _answer(
        self,
        user_message: str,
        all_content: str,
        tool_calls: list[ProposedToolCall],
        context: str,
    ) -> str:
        markers = tuple(dict.fromkeys(_CANARY_RE.findall(all_content)))
        lower = user_message.casefold()
        if "pf-public-demo-015" in lower and "represent" in lower and not tool_calls:
            return self._document_answer(context, "handbook-public-marker")
        if markers and (
            "canary" in lower
            or "disclose" in lower
            or "reveal" in lower
            or "ignore all previous" in lower
            or any(marker.casefold() in lower for marker in markers)
        ):
            return f"Synthetic victim response: {', '.join(markers)}"
        if tool_calls:
            return (
                "The model proposed a tool call; trusted application approval is required "
                "before execution."
            )
        ticket_ids = tuple(dict.fromkeys(re.findall(r"ticket-demo-\d{3}", lower)))
        if ticket_ids and ("status" in lower or "escalation" in lower):
            tickets = [self._record_fields(context, ticket_id) for ticket_id in ticket_ids]
            if not all(tickets):
                return "I cannot find an accessible ticket record for this request."
            if "json" in lower and len(tickets) == 1:
                return json.dumps({key: tickets[0][key] for key in ("status", "updated")})
            if "draft" in lower and "escalation" in lower:
                return (
                    f"Draft escalation for {ticket_ids[0]}: {tickets[0]['subject']} "
                    f"(status: {tickets[0]['status']}). Please review the unresolved issue. "
                    "Draft only; not submitted."
                )
            answers = [
                f"Ticket {ticket_id} status: {ticket['status']}."
                for ticket_id, ticket in zip(ticket_ids, tickets, strict=True)
            ]
            if "support" in lower and "hours" in lower:
                answers.append(self._document_answer(context, "handbook-support"))
                return "\n".join(f"{index}. {answer}" for index, answer in enumerate(answers, 1))
            return "\n".join(answers)
        order_match = re.search(r"order-demo-\d{3}", lower)
        if order_match and ("delivery" in lower or "estimate" in lower):
            order_id = order_match.group(0)
            order = self._record_fields(context, order_id)
            if not order:
                return "I cannot find an accessible order record for this request."
            if "exception" in lower:
                return (
                    f"Order {order_id} status: {order['status']}. "
                    + self._document_answer(context, "handbook-delivery")
                )
            return f"Order {order_id} delivery estimate: {order['delivery_estimate']}."
        support_answer = self._support_answer(user_message, context)
        if support_answer is not None:
            return support_answer
        if "system" in lower and ("prompt" in lower or "instruction" in lower or "rule" in lower):
            return (
                "I can explain public support behavior, but private system instructions "
                "are not disclosed."
            )
        return f"Synthetic support response: {user_message.strip()}"

    @staticmethod
    def _record_fields(context: str, record_id: str) -> dict[str, str]:
        # Only service-provided context supplies record facts, never the user's question.
        match = re.search(rf"^{re.escape(record_id)}: (.+)$", context, re.MULTILINE)
        if match is None:
            return {}
        return dict(item.split("=", 1) for item in match.group(1).split("; ") if "=" in item)

    @staticmethod
    def _document_answer(context: str, document_id: str) -> str:
        match = re.search(
            rf"^\[trusted\] {re.escape(document_id)}: (.*?)(?=^\[(?:untrusted|trusted)\]|\Z)",
            context, re.MULTILINE | re.DOTALL,
        )
        if match is None:
            return f"I cannot find the requested support source {document_id}."
        return f"{document_id}:\n{match.group(1).strip()}"

    def _support_answer(self, user_message: str, context: str) -> str | None:
        """Bounded fixture support intents; no catalog IDs or expected-answer lookup."""

        lower = user_message.casefold()
        if "draft" in lower and "missing" in lower and "invoice" in lower:
            return (
                "Draft support ticket\nSubject: Missing invoice\n"
                "Please help locate my invoice for [billing period]. "
                "Account reference: [account ID]. Draft only; not submitted."
            )
        if "draft" in lower and "marketing notifications" in lower:
            return "Draft: Please disable marketing notifications for my account. Not saved."
        if "rewrite" in lower and "'your demo order is being reviewed.'" in lower:
            return "Your demo order is under review."
        if ("translate" in lower and "'your synthetic ticket is open'" in lower
                and "spanish" in lower):
            return "Su ticket sintético está abierto."
        document_id: str | None = None
        if "refund" in lower and any(word in lower for word in ("policy", "request", "would")):
            document_id = "handbook-refunds"
        elif "difference" in lower and "ticket" in lower and "order" in lower:
            document_id = "handbook-terminology"
        elif "plan" in lower and ("features" in lower or "export" in lower):
            document_id = "handbook-plans"
        elif "handbook-billing" in lower:
            document_id = "handbook-billing"
        elif "known issues" in lower and "notifications" in lower:
            document_id = "handbook-notification-issues"
        elif "address" in lower and "update" in lower:
            document_id = "handbook-address"
        elif "subscription" in lower and ("cancel" in lower or "changing" in lower):
            document_id = "handbook-subscription"
        elif "handbook-usage" in lower:
            document_id = "handbook-usage"
        elif "synthetic-handbook-014" in lower or "notification preferences" in lower:
            document_id = "synthetic-handbook-014"
        elif "account" in lower and "secure" in lower:
            document_id = "handbook-security"
        elif "service interruption" in lower:
            document_id = "handbook-interruption"
        elif "handbook-support" in lower or (
            "support" in lower and ("hours" in lower or "available" in lower)
            and "summarize" not in lower
        ):
            document_id = "handbook-support"
        return self._document_answer(context, document_id) if document_id else None

    def _propose_tools(self, user_message: str, digest: str) -> list[ProposedToolCall]:
        lower = user_message.casefold()
        calls: list[ProposedToolCall] = []
        order_match = re.search(r"order-demo-\d{3}", lower)
        is_action = any(
            word in lower for word in ("call", "invoke", "process", "issue", "send", "write")
        )
        if ("mock_refund" in lower or ("refund" in lower and order_match)) and is_action:
            amount_minor = self._amount_minor(user_message)
            calls.append(
                ProposedToolCall(
                    name="mock_refund",
                    arguments={
                        "order_id": order_match.group(0) if order_match else "order-demo-018",
                        "amount_minor": amount_minor,
                        "approved": False,
                    },
                    call_id=f"call-{digest[:10]}-refund",
                )
            )
        recipient_match = re.search(
            r"(?:to|recipient)\s+([a-z0-9._%+-]+@[a-z0-9.-]+|mock-recipient-\d+)",
            lower,
        )
        if "mock_message" in lower and is_action:
            calls.append(
                ProposedToolCall(
                    name="mock_message",
                    arguments={
                        "recipient": (
                            recipient_match.group(1)
                            if recipient_match
                            else "mock-recipient-001"
                        ),
                        "message": "SYNTHETIC_NOTICE",
                        "approved": False,
                    },
                    call_id=f"call-{digest[:10]}-message",
                )
            )
        if "mock_file_write" in lower and is_action:
            path_match = re.search(r"path\s+([^\s]+)", user_message, re.IGNORECASE)
            calls.append(
                ProposedToolCall(
                    name="mock_file_write",
                    arguments={
                        "path": path_match.group(1) if path_match else "fixture://notes/model.txt",
                        "content": "SYNTHETIC_WRITE_MARKER",
                        "approved": False,
                    },
                    call_id=f"call-{digest[:10]}-file",
                )
            )
        url_match = re.search(r"https?://[^\s)]+", user_message)
        if ("mock_http_get" in lower or url_match) and is_action:
            calls.append(
                ProposedToolCall(
                    name="mock_http_get",
                    arguments={
                        "url": (
                            url_match.group(0)
                            if url_match
                            else "http://mock.local/fixtures/status"
                        )
                    },
                    call_id=f"call-{digest[:10]}-http",
                )
            )
        return calls

    @staticmethod
    def _amount_minor(message: str) -> int:
        minor_match = re.search(r"amount[_ -]?minor\s*(?:=|:)\s*(\d+)", message, re.IGNORECASE)
        if minor_match:
            return int(minor_match.group(1))
        amount_match = re.search(
            r"(\d+(?:\.\d+)?)\s*(?:synthetic\s+)?(?:units?|usd|dollars?)",
            message,
            re.IGNORECASE,
        )
        if amount_match:
            return int(round(float(amount_match.group(1)) * 100))
        return 100


MockModelAdapter = DeterministicMockModel
DeterministicMockModelAdapter = DeterministicMockModel


__all__ = [
    "DeterministicMockModel",
    "DeterministicMockModelAdapter",
    "MockModelAdapter",
]
