from __future__ import annotations

from promptfirewall.contracts.results import OutcomeLabel
from promptfirewall.metrics import calculate_metrics, wilson_interval


def test_wilson_interval_is_bounded_and_non_degenerate_for_small_samples() -> None:
    low, high = wilson_interval(1, 2)

    assert 0 < low < 0.5
    assert 0.5 < high < 1
    assert low < high


def test_metrics_use_explicit_run_outcomes_and_group_actual_records() -> None:
    records = [
        {
            "case_kind": "attack",
            "category": "direct_prompt_injection",
            "defense_profile_id": "none",
            "outcome": OutcomeLabel.ATTACK_SUCCEEDED,
            "latency_ms": 10,
        },
        {
            "case_kind": "attack",
            "category": "direct_prompt_injection",
            "defense_profile_id": "full-stack",
            "outcome": "attack_blocked",
            "latency_ms": 20,
        },
        {
            "case_kind": "attack",
            "category": "tool_abuse",
            "defense_profile_id": "full-stack",
            "outcome": "partial",
            "latency_ms": 30,
        },
        {
            "case_kind": "benign",
            "defense_profile_id": "full-stack",
            "outcome": "benign_ok",
            "latency_ms": 40,
        },
        {
            "case_kind": "benign",
            "defense_profile_id": "full-stack",
            "outcome": "benign_blocked",
            "latency_ms": 50,
        },
        {"status": "failed", "outcome": "execution_error", "latency_ms": 60},
        {"case_kind": "attack", "outcome": None, "latency_ms": 70},
    ]

    metrics = calculate_metrics(records)

    assert metrics.attack_success_rate.value == 1 / 3
    assert metrics.attack_success_rate.numerator == 1
    assert metrics.attack_success_rate.denominator == 3
    assert metrics.partial_compromise_rate.value == 1 / 3
    assert metrics.attack_block_rate.value == 1 / 3
    assert metrics.false_positive_rate.value == 0.5
    assert metrics.utility_retention.value == 0.5
    assert metrics.error_rate.value == 1 / 7
    assert metrics.median_latency_ms == 40
    assert metrics.p95_latency_ms == 67.0
    assert metrics.by_category["direct_prompt_injection"].denominator == 2
    assert metrics.by_profile["full-stack"].numerator == 0
    assert metrics.attack_success_rate.interval_low is not None
    assert metrics.attack_success_rate.interval_high is not None


def test_metrics_report_empty_eligible_sets_without_inventing_rates() -> None:
    metrics = calculate_metrics([{"case_kind": "attack", "outcome": "indeterminate"}])

    assert metrics.attack_success_rate.value is None
    assert metrics.attack_success_rate.denominator == 0
    assert metrics.error_rate.value == 0.0
    assert metrics.median_latency_ms is None
    assert metrics.p95_latency_ms is None
