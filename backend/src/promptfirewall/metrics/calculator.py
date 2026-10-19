"""Metrics calculated from completed run result records only."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from math import sqrt
from statistics import NormalDist, median
from typing import Any

from promptfirewall.contracts.results import MetricsSnapshot, MetricValue, OutcomeLabel


@dataclass(frozen=True)
class _Observation:
    case_kind: str | None
    category: str | None
    profile: str | None
    outcome: str | None
    latency_ms: float | None
    is_error: bool


def wilson_interval(
    successes: int,
    trials: int,
    *,
    confidence: float = 0.95,
) -> tuple[float, float] | None:
    """Return a Wilson score interval for a Bernoulli proportion."""

    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("successes and trials must satisfy 0 <= successes <= trials")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between zero and one")
    if trials == 0:
        return None
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    proportion = successes / trials
    denominator = 1 + z**2 / trials
    center = (proportion + z**2 / (2 * trials)) / denominator
    margin = (
        z
        * sqrt((proportion * (1 - proportion) + z**2 / (4 * trials)) / trials)
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _nested(value: Any, *names: str) -> Any:
    current = value
    for name in names:
        current = _field(current, name, None)
        if current is None:
            return None
    return current


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _observation(record: Any) -> _Observation:
    outcome = _enum_value(_field(record, "outcome"))
    if outcome is None:
        aggregate = _field(record, "aggregated_judgment")
        outcome = _enum_value(_field(aggregate, "outcome")) if aggregate is not None else None
    case_kind = _enum_value(_field(record, "case_kind"))
    if case_kind not in {"attack", "benign"}:
        case_kind = "attack" if outcome in {
            OutcomeLabel.ATTACK_SUCCEEDED.value,
            OutcomeLabel.ATTACK_BLOCKED.value,
            OutcomeLabel.PARTIAL.value,
        } else "benign" if outcome in {
            OutcomeLabel.BENIGN_OK.value,
            OutcomeLabel.BENIGN_BLOCKED.value,
        } else None
    metadata = _field(record, "metadata", {})
    if not isinstance(metadata, Mapping):
        metadata = {}
    case = _field(record, "case")
    category = _field(record, "category")
    if category is None:
        category = _field(record, "attack_category")
    if category is None:
        category = metadata.get("category") or metadata.get("attack_category")
    if category is None and case is not None:
        category = _field(case, "category")
    profile = _field(record, "defense_profile_id")
    if profile is None:
        profile = _field(record, "profile_id") or metadata.get("defense_profile_id")
    latency = _field(record, "latency_ms")
    try:
        latency_value = float(latency) if latency is not None else None
    except (TypeError, ValueError):
        latency_value = None
    status = _enum_value(_field(record, "status"))
    error = _field(record, "error")
    is_error = outcome == OutcomeLabel.EXECUTION_ERROR.value or status in {
        "failed",
        "execution_error",
        "error",
    }
    return _Observation(
        case_kind=case_kind,
        category=_enum_value(category) if category is not None else None,
        profile=str(_enum_value(profile)) if profile is not None else None,
        outcome=str(outcome) if outcome is not None else None,
        latency_ms=latency_value if latency_value is not None and latency_value >= 0 else None,
        is_error=is_error or error is not None,
    )


def _rate(
    successes: int,
    trials: int,
    *,
    confidence: float,
    label: str,
) -> MetricValue:
    if trials == 0:
        return MetricValue(
            value=None,
            numerator=0,
            denominator=0,
            note=f"no eligible observations for {label}",
        )
    interval = wilson_interval(successes, trials, confidence=confidence)
    return MetricValue(
        value=successes / trials,
        numerator=successes,
        denominator=trials,
        interval_low=interval[0] if interval else None,
        interval_high=interval[1] if interval else None,
        note=f"{confidence:.0%} Wilson interval",
    )


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


class MetricsCalculator:
    """Calculate benchmark metrics from actual run records.

    Records without an explicit aggregated outcome are not silently classified
    as successes or blocks.  This keeps metric values tied to observed runs.
    """

    def __init__(self, *, confidence: float = 0.95) -> None:
        if not 0 < confidence < 1:
            raise ValueError("confidence must be between zero and one")
        self.confidence = confidence

    def calculate(self, records: Iterable[Any]) -> MetricsSnapshot:
        observations = tuple(_observation(record) for record in records)
        attack = tuple(item for item in observations if item.case_kind == "attack")
        benign = tuple(item for item in observations if item.case_kind == "benign")
        attack_eligible = tuple(
            item
            for item in attack
            if item.outcome
            in {
                OutcomeLabel.ATTACK_SUCCEEDED.value,
                OutcomeLabel.ATTACK_BLOCKED.value,
                OutcomeLabel.PARTIAL.value,
            }
        )
        benign_eligible = tuple(
            item
            for item in benign
            if item.outcome in {OutcomeLabel.BENIGN_OK.value, OutcomeLabel.BENIGN_BLOCKED.value}
        )
        latencies = [item.latency_ms for item in observations if item.latency_ms is not None]
        error_count = sum(item.is_error for item in observations)

        return MetricsSnapshot(
            attack_success_rate=_rate(
                sum(
                    item.outcome == OutcomeLabel.ATTACK_SUCCEEDED.value
                    for item in attack_eligible
                ),
                len(attack_eligible),
                confidence=self.confidence,
                label="attack success rate",
            ),
            partial_compromise_rate=_rate(
                sum(item.outcome == OutcomeLabel.PARTIAL.value for item in attack_eligible),
                len(attack_eligible),
                confidence=self.confidence,
                label="partial compromise rate",
            ),
            attack_block_rate=_rate(
                sum(
                    item.outcome == OutcomeLabel.ATTACK_BLOCKED.value
                    for item in attack_eligible
                ),
                len(attack_eligible),
                confidence=self.confidence,
                label="attack block rate",
            ),
            false_positive_rate=_rate(
                sum(
                    item.outcome == OutcomeLabel.BENIGN_BLOCKED.value
                    for item in benign_eligible
                ),
                len(benign_eligible),
                confidence=self.confidence,
                label="false positive rate",
            ),
            utility_retention=_rate(
                sum(item.outcome == OutcomeLabel.BENIGN_OK.value for item in benign_eligible),
                len(benign_eligible),
                confidence=self.confidence,
                label="utility retention",
            ),
            error_rate=_rate(
                error_count,
                len(observations),
                confidence=self.confidence,
                label="error rate",
            ),
            median_latency_ms=median(latencies) if latencies else None,
            p95_latency_ms=_quantile(latencies, 0.95),
            by_category=self._grouped(attack_eligible, "category"),
            by_profile=self._grouped(attack_eligible, "profile"),
        )

    def _grouped(
        self,
        observations: tuple[_Observation, ...],
        attribute: str,
    ) -> dict[str, MetricValue]:
        keys = sorted(
            {getattr(item, attribute) for item in observations if getattr(item, attribute)}
        )
        grouped: dict[str, MetricValue] = {}
        for key in keys:
            selected = tuple(item for item in observations if getattr(item, attribute) == key)
            grouped[key] = _rate(
                sum(item.outcome == OutcomeLabel.ATTACK_SUCCEEDED.value for item in selected),
                len(selected),
                confidence=self.confidence,
                label=f"attack success rate for {key}",
            )
        return grouped


def calculate_metrics(records: Iterable[Any], *, confidence: float = 0.95) -> MetricsSnapshot:
    return MetricsCalculator(confidence=confidence).calculate(records)


compute_metrics = calculate_metrics
metrics_from_records = calculate_metrics


__all__ = [
    "MetricsCalculator",
    "calculate_metrics",
    "compute_metrics",
    "metrics_from_records",
    "wilson_interval",
]
