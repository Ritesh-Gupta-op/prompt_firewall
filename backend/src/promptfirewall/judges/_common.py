"""Small adapters for consuming mappings, Pydantic models, and run objects."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from promptfirewall.contracts.models import ModelResponse

MISSING = object()


def field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def nested_field(value: Any, *names: str, default: Any = None) -> Any:
    current = value
    for name in names:
        current = field(current, name, MISSING)
        if current is MISSING:
            return default
    return current


def response(record: Any) -> Any:
    candidate = field(record, "model_response", MISSING)
    if candidate is MISSING:
        candidate = field(record, "response", MISSING)
    if candidate is MISSING and isinstance(record, ModelResponse):
        candidate = record
    return None if candidate is MISSING else candidate


def output_text(record: Any) -> str | None:
    direct = field(record, "output", MISSING)
    if direct is MISSING:
        direct = field(record, "text", MISSING)
    if direct is not MISSING and isinstance(direct, str):
        return direct
    model_response = response(record)
    text = field(model_response, "text", MISSING)
    return text if isinstance(text, str) else None


def tool_calls(record: Any) -> tuple[Any, ...]:
    model_response = response(record)
    calls = field(record, "tool_calls", MISSING)
    if calls is MISSING:
        calls = field(model_response, "tool_calls", ())
    if isinstance(calls, Sequence) and not isinstance(calls, (str, bytes)):
        return tuple(calls)
    return ()


def tool_results(record: Any) -> tuple[Any, ...]:
    results = field(record, "tool_results", ())
    if isinstance(results, Sequence) and not isinstance(results, (str, bytes)):
        return tuple(results)
    return ()


def trace_events(record: Any) -> tuple[Any, ...]:
    events = field(record, "trace_events", ())
    if isinstance(events, Sequence) and not isinstance(events, (str, bytes)):
        return tuple(events)
    return ()


def event_type(event: Any) -> str:
    value = field(event, "event_type", "")
    return getattr(value, "value", value) if isinstance(getattr(value, "value", value), str) else ""


def tool_name(value: Any) -> str:
    name = field(value, "tool_name", MISSING)
    if name is MISSING:
        name = field(value, "name", "")
    return name if isinstance(name, str) else ""


def result_bool(value: Any, key: str = "success") -> bool | None:
    result = field(value, key, MISSING)
    if isinstance(result, bool):
        return result
    return None


def case_kind(record: Any) -> str | None:
    value = field(record, "case_kind", MISSING)
    if value is MISSING:
        value = field(record, "kind", MISSING)
    if value is MISSING:
        outcome = field(record, "outcome", "")
        value = "attack" if str(outcome).startswith("attack") or str(outcome) == "partial" else None
    value = getattr(value, "value", value)
    return value if value in {"attack", "benign"} else None


__all__ = [
    "MISSING",
    "case_kind",
    "event_type",
    "field",
    "nested_field",
    "output_text",
    "response",
    "result_bool",
    "tool_calls",
    "tool_name",
    "tool_results",
    "trace_events",
]
