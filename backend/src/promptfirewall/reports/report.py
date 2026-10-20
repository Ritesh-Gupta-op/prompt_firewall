"""Evidence-first JSON and Markdown reports for harness executions."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

from promptfirewall.harness.jobs import ExperimentResult, RunRecord
from promptfirewall.metrics import calculate_metrics


class ReportGenerationError(ValueError):
    """Raised when report input is not a run result or run-record iterable."""


class ReportGenerator:
    """Render actual run records without inventing cost or token information."""

    def generate(
        self,
        source: ExperimentResult | Iterable[RunRecord],
        *,
        format: str = "json",
    ) -> str:
        normalized = format.casefold()
        if normalized == "json":
            return self.render_json(source)
        if normalized in {"markdown", "md"}:
            return self.render_markdown(source)
        raise ReportGenerationError(f"unsupported report format: {format}")

    def render_json(self, source: ExperimentResult | Iterable[RunRecord]) -> str:
        return json.dumps(self.to_dict(source), indent=2, sort_keys=True)

    def render_markdown(self, source: ExperimentResult | Iterable[RunRecord]) -> str:
        data = self.to_dict(source)
        lines = [
            f"# Experiment report: {data.get('name') or data['experiment_id']}",
            "",
            f"- Experiment ID: `{data['experiment_id']}`",
            f"- Status: `{data.get('status', 'unknown')}`",
            f"- Runs: {len(data['runs'])}",
            "",
            "## Metrics",
            "",
            "| Metric | Value | Eligible observations | Note |",
            "| --- | ---: | ---: | --- |",
        ]
        metrics = data["metrics"]
        for key, value in metrics.items():
            if not isinstance(value, dict) or "value" not in value:
                continue
            lines.append(
                f"| {key.replace('_', ' ')} | {_format_metric(key, value)} | "
                f"{_format_denominator(value)} | {value.get('note') or ''} |"
            )
        for group_name in ("by_category", "by_profile"):
            group = metrics.get(group_name) or {}
            if not group:
                continue
            lines.extend(["", f"### {group_name.replace('_', ' ').title()}", ""])
            lines.append("| Group | Value | Eligible observations | Note |")
            lines.append("| --- | ---: | ---: | --- |")
            for group_key, metric in group.items():
                lines.append(
                    f"| {group_key} | {_format_metric(group_name, metric)} | "
                    f"{_format_denominator(metric)} | {metric.get('note') or ''} |"
                )

        lines.extend(["", "## Run evidence", ""])
        if not data["runs"]:
            lines.append("No run records were available.")
        for run in data["runs"]:
            lines.extend(
                [
                    f"### `{run['run_id']}` — {run['case_id']}",
                    "",
                    f"- Case: `{run['case_kind']}`",
                    f"- Profile: `{run['defense_profile_id']}`",
                    f"- Status: `{run['status']}`",
                    f"- Outcome: `{run.get('outcome') or 'unavailable'}`",
                    f"- Latency: {_format_number(run.get('latency_ms'), ' ms')}",
                ]
            )
            response = run.get("response") or {}
            if response.get("text") is not None:
                lines.extend(["- Observed response:", "", "```text", response["text"], "```"])
            token_text = _actual_token_text(response)
            lines.append(f"- Token usage: {token_text}")
            if run.get("error"):
                lines.extend(["", "Error:", "", "```json", _pretty_json(run["error"]), "```"])
            lines.extend(
                [
                    "",
                    "Evidence:",
                    "",
                    "```json",
                    _pretty_json(run.get("evidence", {})),
                    "```",
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

    def to_dict(self, source: ExperimentResult | Iterable[RunRecord]) -> dict[str, Any]:
        records, experiment_id, name, status = _source_parts(source)
        metrics = calculate_metrics(records)
        return {
            "experiment_id": experiment_id,
            "name": name,
            "status": status,
            "metrics": _json_value(metrics),
            "runs": [_run_dict(record) for record in records],
        }


def _source_parts(
    source: ExperimentResult | Iterable[RunRecord],
) -> tuple[tuple[RunRecord, ...], str | None, str | None, str | None]:
    if isinstance(source, ExperimentResult):
        return (
            source.runs,
            source.experiment_id,
            source.experiment.name,
            _enum_value(source.status),
        )
    try:
        records = tuple(source)
    except TypeError as error:
        raise ReportGenerationError(
            "report source must be an experiment result or run iterable"
        ) from error
    if not all(isinstance(record, RunRecord) for record in records):
        raise ReportGenerationError("report iterables must contain RunRecord values")
    experiment_ids = {record.experiment_id for record in records}
    experiment_id = (
        next(iter(experiment_ids), "unknown") if len(experiment_ids) <= 1 else "multiple"
    )
    return records, experiment_id, None, None


def _run_dict(record: RunRecord) -> dict[str, Any]:
    response: dict[str, Any] = {}
    if record.model_response is not None:
        response.update(
            {
                "provider": record.model_response.provider,
                "model": record.model_response.model,
                "text": record.model_response.text,
                "finish_reason": record.model_response.finish_reason,
                "latency_ms": record.model_response.latency_ms,
                "is_mock": record.model_response.is_mock,
            }
        )
        if record.model_response.input_tokens is not None:
            response["input_tokens"] = record.model_response.input_tokens
        if record.model_response.output_tokens is not None:
            response["output_tokens"] = record.model_response.output_tokens
    elif record.response_text is not None:
        response["text"] = record.response_text

    aggregated = record.aggregated_judgment
    aggregate_dict = None
    if aggregated is not None:
        aggregate_dict = {
            "outcome": _enum_value(getattr(aggregated, "outcome", None)),
            "status": _enum_value(getattr(aggregated, "status", None)),
            "evidence": _json_value(getattr(aggregated, "evidence", {})),
        }
    return {
        "run_id": record.id,
        "experiment_id": record.experiment_id,
        "case_id": record.case_id,
        "case_kind": record.case_kind,
        "category": record.category,
        "case_name": record.case_name,
        "defense_profile_id": record.defense_profile_id,
        "repetition_index": record.repetition_index,
        "seed": record.seed,
        "status": _enum_value(record.status),
        "outcome": _enum_value(record.outcome),
        "latency_ms": record.latency_ms,
        "blocked": record.blocked,
        "response": response,
        "tool_results": [_json_value(result) for result in record.tool_results],
        "judges": [_json_value(result) for result in record.judge_results],
        "aggregated_judgment": aggregate_dict,
        "evidence": _json_value(record.evidence),
        "state_before": _json_value(record.state_before),
        "state_after": _json_value(record.state_after),
        "trace_events": [_json_value(event) for event in record.trace_events],
        "error": _json_value(record.error),
        "metadata": _json_value(record.metadata),
        "created_at": _json_value(record.created_at),
        "started_at": _json_value(record.started_at),
        "finished_at": _json_value(record.finished_at),
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    return value


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _format_metric(key: str, value: Mapping[str, Any]) -> str:
    raw = value.get("value")
    if raw is None:
        return "N/A"
    if key.endswith("rate") or key.endswith("retention"):
        return f"{float(raw):.1%}"
    return f"{float(raw):.3f}"


def _format_denominator(value: Mapping[str, Any]) -> str:
    numerator = value.get("numerator")
    denominator = value.get("denominator")
    if numerator is None or denominator is None:
        return "—"
    return f"{numerator}/{denominator}"


def _format_number(value: Any, suffix: str = "") -> str:
    if value is None:
        return "unavailable"
    return f"{float(value):.3f}{suffix}"


def _actual_token_text(response: Mapping[str, Any]) -> str:
    fields = []
    if "input_tokens" in response:
        fields.append(f"input={response['input_tokens']}")
    if "output_tokens" in response:
        fields.append(f"output={response['output_tokens']}")
    return ", ".join(fields) if fields else "unavailable"


def _pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def render_json(source: ExperimentResult | Iterable[RunRecord]) -> str:
    return ReportGenerator().render_json(source)


def render_markdown(source: ExperimentResult | Iterable[RunRecord]) -> str:
    return ReportGenerator().render_markdown(source)


generate_json = render_json
generate_markdown = render_markdown
generate_report_json = render_json
generate_report_markdown = render_markdown


__all__ = [
    "ReportGenerationError",
    "ReportGenerator",
    "generate_json",
    "generate_markdown",
    "generate_report_json",
    "generate_report_markdown",
    "render_json",
    "render_markdown",
]
