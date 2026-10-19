from __future__ import annotations

import json

from promptfirewall.contracts.experiments import ExperimentCreate
from promptfirewall.contracts.results import OutcomeLabel
from promptfirewall.harness import ExperimentRunner
from promptfirewall.reports import ReportGenerator


def test_json_report_uses_actual_metrics_evidence_and_tokens() -> None:
    result = ExperimentRunner().run(
        ExperimentCreate(
            name="reportable",
            attack_ids=["attack-dpi-001"],
            defense_profile_ids=["none", "full-stack"],
        )
    )

    payload = json.loads(ReportGenerator().render_json(result))

    assert payload["metrics"]["attack_success_rate"]["numerator"] == 1
    assert payload["metrics"]["attack_success_rate"]["denominator"] == 2
    assert payload["runs"][0]["evidence"]["judges"]
    assert payload["runs"][0]["response"]["input_tokens"] > 0
    assert payload["runs"][0]["response"]["output_tokens"] > 0
    assert "cost" not in payload
    assert all("cost" not in run for run in payload["runs"])
    assert {run["outcome"] for run in payload["runs"]} == {
        OutcomeLabel.ATTACK_SUCCEEDED.value,
        OutcomeLabel.ATTACK_BLOCKED.value,
    }


def test_reports_do_not_fabricate_unavailable_usage_data() -> None:
    from promptfirewall.harness.jobs import RunRecord

    record = RunRecord(
        id="run-no-usage",
        experiment_id="experiment-no-usage",
        case_id="attack-dpi-001",
        case_kind="attack",
        defense_profile_id="none",
        repetition_index=0,
        seed=7,
        outcome=OutcomeLabel.INDETERMINATE,
        evidence={"source": "test"},
    )

    generator = ReportGenerator()
    payload = json.loads(generator.render_json([record]))
    markdown = generator.render_markdown([record])

    assert payload["runs"][0]["response"] == {}
    assert "input_tokens" not in payload["runs"][0]["response"]
    assert "output_tokens" not in payload["runs"][0]["response"]
    assert "cost" not in payload
    assert "Token usage: unavailable" in markdown
    assert "N/A" in markdown
    assert '"source": "test"' in markdown
