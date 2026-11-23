"""
Unit tests for DET-CPU-001 and DET-MEM-001.

Both rules share one implementation, so every behaviour is checked against
both. Threshold 90, 3 consecutive samples, 60s cooldown unless stated.
Samples are 2s apart (tests.detection_helpers.at).
"""

from __future__ import annotations

import pytest

from detection.rules.resource import CpuAnomalyRule, MemoryAnomalyRule, _SustainedPercentRule
from models.enums import Classification, Severity
from tests.detection_helpers import feed, fired

CASES = [
    pytest.param(CpuAnomalyRule, "cpu_percent", "DET-CPU-001", "cpu_sustained_high", id="cpu"),
    pytest.param(
        MemoryAnomalyRule, "memory_percent", "DET-MEM-001", "memory_sustained_high", id="mem"
    ),
]


def make(
    cls: type[_SustainedPercentRule],
    threshold: float = 90.0,
    consecutive: int = 3,
    cooldown: float = 60.0,
) -> _SustainedPercentRule:
    return cls(
        threshold_percent=threshold, consecutive_samples=consecutive, cooldown_seconds=cooldown
    )


@pytest.mark.parametrize(("cls", "metric", "rule_id", "event_type"), CASES)
class TestSustainedPercentRules:
    def test_identity(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        rule = make(cls)
        assert rule.rule_id == rule_id
        assert rule.info().enabled is True
        assert rule.info().severity == Severity.MEDIUM

    def test_below_threshold_never_fires(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [89.9] * 10)
        assert fired(out) == []

    def test_exactly_at_threshold_counts_as_violation(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        # testing-requirements: an input at the exact threshold is a detection.
        out = feed(make(cls), metric, [90.0, 90.0, 90.0])
        assert fired(out) == [2]

    def test_above_threshold_fires_on_third_consecutive_sample(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [96.0, 96.0, 96.0])
        assert fired(out) == [2]
        assert out[2][0].event_type == event_type

    def test_isolated_spike_does_not_fire(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [10.0, 99.0, 10.0, 10.0, 99.0, 10.0])
        assert fired(out) == []

    def test_two_violations_then_recovery_does_not_fire(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [95.0, 95.0, 20.0, 95.0, 95.0])
        assert fired(out) == []

    def test_recovery_resets_the_run(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        # Needs a *fresh* run of 3 after recovery, not 1 more.
        out = feed(make(cls, cooldown=0), metric, [95.0, 95.0, 20.0, 95.0, 95.0, 95.0])
        assert fired(out) == [5]

    def test_single_sample_config_fires_on_isolated_spike(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        # "No alert from one isolated spike unless explicitly configured."
        out = feed(make(cls, consecutive=1), metric, [10.0, 99.0])
        assert fired(out) == [1]

    def test_missing_sample_breaks_the_run(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [95.0, 95.0, None, 95.0])
        assert fired(out) == []

    def test_cooldown_suppresses_repeats(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        # 20 samples * 2s = 40s < 60s cooldown: only the first detection.
        out = feed(make(cls), metric, [95.0] * 20)
        assert fired(out) == [2]

    def test_fires_again_after_cooldown(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        # Fires at sample 2 (t=4s); cooldown 10s expires at t=14s -> sample 7.
        out = feed(make(cls, cooldown=10.0), metric, [95.0] * 10)
        assert fired(out) == [2, 7]

    def test_evidence_is_structured(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls), metric, [91.0, 93.0, 96.2])
        result = out[2][0]
        assert result.evidence["metric"] == metric
        assert result.evidence["observed"] == 96.2
        assert result.evidence["threshold"] == 90.0
        assert result.evidence["consecutive_samples"] == 3
        assert result.evidence["required_samples"] == 3
        assert result.evidence["observed_values"] == [91.0, 93.0, 96.2]
        assert result.evidence["contributing_sample_ids"] == [1, 2, 3]
        assert result.evidence["comparison"] == "gte"
        assert result.evidence["window_start"] < result.evidence["window_end"]  # type: ignore[operator]

    def test_result_fields(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        result = feed(make(cls), metric, [95.0] * 3)[2][0]
        assert result.rule_id == rule_id
        assert result.metric_key == metric
        assert result.metric_value == 95.0
        assert result.threshold_value == 90.0
        assert result.telemetry_sample_id == 3
        assert result.is_synthetic is False
        assert result.classification == Classification.INFORMATIONAL

    def test_single_indicator_confidence_is_capped(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        out = feed(make(cls, cooldown=0), metric, [95.0] * 40)
        confidences = [r[0].confidence for r in out if r]
        assert confidences[0] == pytest.approx(0.3)
        assert confidences == sorted(confidences)  # never decreases while sustained
        assert max(confidences) == pytest.approx(0.6)

    def test_deterministic(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        series = [10.0, 95.0, 96.0, 97.0, 20.0, 95.0, 95.0, 95.0, 95.0]
        a = feed(make(cls, cooldown=0), metric, series)
        b = feed(make(cls, cooldown=0), metric, series)
        assert a == b

    def test_reset_clears_state(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        rule = make(cls)
        feed(rule, metric, [95.0, 95.0])
        rule.reset()
        assert fired(feed(rule, metric, [95.0], start=2)) == []

    def test_threshold_zero_and_hundred_are_valid(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        assert fired(feed(make(cls, threshold=0.0, consecutive=1), metric, [0.0])) == [0]
        assert fired(feed(make(cls, threshold=100.0, consecutive=1), metric, [100.0])) == [0]
        assert fired(feed(make(cls, threshold=100.0, consecutive=1), metric, [99.9])) == []

    @pytest.mark.parametrize("bad", [-0.1, 100.1])
    def test_threshold_out_of_range_rejected(
        self,
        cls: type[_SustainedPercentRule],
        metric: str,
        rule_id: str,
        event_type: str,
        bad: float,
    ) -> None:
        with pytest.raises(ValueError):
            make(cls, threshold=bad)

    def test_other_metrics_are_ignored(
        self, cls: type[_SustainedPercentRule], metric: str, rule_id: str, event_type: str
    ) -> None:
        other = "memory_percent" if metric == "cpu_percent" else "cpu_percent"
        assert fired(feed(make(cls), other, [99.0] * 10)) == []
