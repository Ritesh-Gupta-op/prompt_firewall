"""Filter untrusted or out-of-scope context before it reaches a model."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)
from promptfirewall.defenses.base import Defense, make_decision, replace_payload

_INSTRUCTION_RE = re.compile(
    r"\b(ignore|disregard|follow only|outranks|call mock_|disclose|reveal)\b", re.I
)


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _document(item: Any) -> Any:
    document = _value(item, "document")
    return document if document is not None else item


def _item_text(item: Any) -> str:
    document = _document(item)
    for key in ("content", "value", "text"):
        value = _value(document, key)
        if isinstance(value, str):
            return value
    return ""


def _item_tenant(item: Any) -> str | None:
    document = _document(item)
    value = _value(document, "tenant_id")
    return value if isinstance(value, str) else None


def _is_trusted(item: Any) -> bool | None:
    document = _document(item)
    trusted = _value(document, "trusted")
    return trusted if isinstance(trusted, bool) else None


def filter_context_items(
    items: Sequence[Any],
    *,
    tenant_id: str | None = None,
) -> tuple[tuple[Any, ...], tuple[dict[str, str], ...]]:
    """Return retained items and deterministic reasons for removed items."""

    retained: list[Any] = []
    filtered: list[dict[str, str]] = []
    for index, item in enumerate(items):
        reason: str | None = None
        if tenant_id is not None and _item_tenant(item) not in (None, tenant_id):
            reason = "tenant_scope"
        elif _is_trusted(item) is False:
            reason = "untrusted_source"
        elif _INSTRUCTION_RE.search(_item_text(item)):
            reason = "embedded_instruction"
        if reason is None:
            retained.append(item)
        else:
            filtered.append({"index": str(index), "reason": reason})
    return tuple(retained), tuple(filtered)


class ContextFilter(Defense):
    """Remove poisoned documents and context outside the structured tenant."""

    defense_id = "context-filter"
    stage = DefenseStage.CONTEXT

    def filter(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        return self.evaluate(payload, context)

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        content = payload.content
        if isinstance(content, Mapping) and "items" in content:
            raw_items = content["items"]
            if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes)):
                return make_decision(self, DefenseAction.BLOCK, "invalid_context_items")
            retained, filtered = filter_context_items(
                raw_items,
                tenant_id=_tenant_id(context, payload),
            )
            filtered_content: Any = {**content, "items": list(retained)}
        elif isinstance(content, Sequence) and not isinstance(content, (str, bytes)):
            retained, filtered = filter_context_items(
                content,
                tenant_id=_tenant_id(context, payload),
            )
            filtered_content = list(retained) if isinstance(content, list) else retained
        else:
            return make_decision(self, DefenseAction.BLOCK, "invalid_context_content")

        output = replace_payload(
            payload,
            filtered_content,
            original_content=content if filtered else None,
            metadata={"filtered_items": list(filtered)},
        )
        return make_decision(
            self,
            DefenseAction.SANITIZE if filtered else DefenseAction.ALLOW,
            "context_items_filtered" if filtered else "context_clean",
            payload=output,
            metadata={"filtered_items": list(filtered), "retained_count": len(retained)},
        )


ContextFiltering = ContextFilter
ContextFilterDefense = ContextFilter


def _tenant_id(context: DefenseContext, payload: DefensePayload) -> str | None:
    identity_tenant = context.identity.get("tenant_id") or context.identity.get("tenant")
    if isinstance(identity_tenant, str):
        return identity_tenant
    payload_tenant = payload.metadata.get("tenant_id")
    return payload_tenant if isinstance(payload_tenant, str) else None


__all__ = [
    "ContextFilter",
    "ContextFilterDefense",
    "ContextFiltering",
    "filter_context_items",
]
