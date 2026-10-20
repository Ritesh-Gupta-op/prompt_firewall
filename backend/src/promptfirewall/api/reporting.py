"""Reuse the evidence renderer with metrics from durable, eligible executions."""

import json
from collections.abc import Iterable
from typing import Any

from promptfirewall.harness.jobs import ExperimentResult, RunRecord
from promptfirewall.reports import ReportGenerator


class PersistedReportGenerator(ReportGenerator):
    def render_markdown(self, source: ExperimentResult | Iterable[RunRecord]) -> str:
        source = source if isinstance(source, ExperimentResult) else tuple(source)
        markdown = super().render_markdown(source)
        lines = [markdown, "## Traces", ""]
        for run in self.to_dict(source)["runs"]:
            lines.extend([
                f"### `{run['run_id']}`", "", "```json",
                json.dumps(run["trace_events"], indent=2, sort_keys=True), "```", "",
            ])
        return "\n".join(lines)

    def to_dict(self, source: ExperimentResult | Iterable[RunRecord]) -> dict[str, Any]:
        data = super().to_dict(source)
        if isinstance(source, ExperimentResult):
            # Keep queued/cancelled evidence in the report, but do not count it as
            # an execution observation or infer an outcome from a late worker.
            data["metrics"] = source.metrics.model_dump(mode="json")
        return data
