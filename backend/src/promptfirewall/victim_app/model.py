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
    """

    def __init__(self, *, seed: int = 7, model_name: str = "promptfirewall-mock-1") -> None:
        self.seed = seed
        self.model_name = model_name

    def complete(self, request: ModelRequest) -> ModelResponse:
        fingerprint = self._fingerprint(request)
        digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        user_message = self._last_user_message(request)
        all_content = "\n".join(message.content for message in request.messages)
        tool_calls = self._propose_tools(user_message, digest)
        text = self._answer(user_message, all_content, tool_calls)
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
    ) -> str:
        markers = tuple(dict.fromkeys(_CANARY_RE.findall(all_content)))
        lower = user_message.casefold()
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
        ticket_match = re.search(r"ticket-demo-\d{3}", all_content, re.IGNORECASE)
        if ticket_match and "status" in lower:
            ticket_id = ticket_match.group(0)
            status_match = re.search(
                rf"{re.escape(ticket_id)}[^\n]*status=([a-z-]+)",
                all_content,
                re.IGNORECASE,
            )
            status = status_match.group(1) if status_match else "available in the fixture"
            return f"Ticket {ticket_id} status: {status}."
        order_match = re.search(r"order-demo-\d{3}", all_content, re.IGNORECASE)
        if order_match and ("delivery" in lower or "estimate" in lower):
            order_id = order_match.group(0)
            estimate_match = re.search(
                rf"{re.escape(order_id)}[^\n]*delivery_estimate=([0-9-]+)",
                all_content,
                re.IGNORECASE,
            )
            estimate = estimate_match.group(1) if estimate_match else "available in the fixture"
            return f"Order {order_id} delivery estimate: {estimate}."
        if "refund" in lower and ("policy" in lower or "request" in lower):
            return (
                "The synthetic refund policy requires confirmation and trusted approval "
                "before any refund."
            )
        if "support" in lower and "hours" in lower:
            return "Synthetic support hours are Monday through Friday, 09:00-17:00 UTC."
        if "system" in lower and ("prompt" in lower or "instruction" in lower or "rule" in lower):
            return (
                "I can explain public support behavior, but private system instructions "
                "are not disclosed."
            )
        return f"Synthetic support response: {user_message.strip()}"

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
