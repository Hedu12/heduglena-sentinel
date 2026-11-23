"""Unit tests for DET-PROC-001 (process-count deviation)."""

from __future__ import annotations

import pytest

from detection.rules.process import ProcessCountAnomalyRule
from tests.detection_helpers import feed, fired


def make(
    window: int = 20,
    min_baseline: int = 10,
    ratio: float = 1.5,
    min_increase: int = 50,
    consecutive: int = 2,
    cooldown: float = 600.0,
) -> ProcessCountAnomalyRule:
    return ProcessCountAnomalyRule(
        window_samples=window,
        min_baseline_samples=min_baseline,
        increase_ratio=ratio,
        min_increase=min_increase,
        consecutive_samples=consecutive,
        cooldown_seconds=cooldown,
    )


NORMAL = [100] * 10  # warms the baseline to mean 100 -> effective threshold 150


class TestProcessCount:
    def test_normal_counts_never_fire(self) -> None:
        assert fired(feed(make(), "process_count", [100, 101, 99, 102] * 10)) == []

    def test_abnormal_sustained_increase_fires(self) -> None:
        out = feed(make(), "process_count", [*NORMAL, 200, 210])
        assert fired(out) == [11]

    def test_single_abnormal_sample_does_not_fire(self) -> None:
        assert fired(feed(make(), "process_count", [*NORMAL, 300, 100, 100])) == []

    def test_missing_value_breaks_run(self) -> None:
        out = feed(make(), "process_count", [*NORMAL, 200, None, 200])
        assert fired(out) == []

    def test_missing_values_do_not_pollute_baseline(self) -> None:
        rule = make()
        feed(rule, "process_count", [None] * 50)
        # Baseline is still empty -> warm-up -> no detection even for a huge value.
        assert fired(feed(rule, "process_count", [10_000, 10_000], start=50)) == []

    def test_no_detection_during_warm_up(self) -> None:
        # Fewer than min_baseline_samples prior samples: nothing to deviate from.
        assert fired(feed(make(), "process_count", [100] * 5 + [500, 500])) == []

    def test_exactly_at_effective_threshold_fires(self) -> None:
        # mean 100, ratio 1.5 -> 150; min_increase 50 -> 150. Both give 150.
        assert fired(feed(make(), "process_count", [*NORMAL, 150, 150])) == [11]

    def test_just_below_effective_threshold_does_not_fire(self) -> None:
        assert fired(feed(make(), "process_count", [*NORMAL, 149, 149])) == []

    def test_absolute_floor_prevents_small_baseline_alerts(self) -> None:
        # mean 10: ratio threshold 15 but floor is mean + 50 = 60.
        series = [10] * 10 + [40, 40, 40]
        assert fired(feed(make(), "process_count", series)) == []
        series = [10] * 10 + [60, 60]
        assert fired(feed(make(), "process_count", series)) == [11]

    def test_ratio_dominates_for_large_baselines(self) -> None:
        # mean 1000: ratio -> 1500 (> mean + 50 = 1050).
        series = [1000] * 10 + [1200, 1200, 1200]
        assert fired(feed(make(), "process_count", series)) == []
        series = [1000] * 10 + [1500, 1500]
        assert fired(feed(make(), "process_count", series)) == [11]

    def test_evidence_explains_the_decision(self) -> None:
        result = feed(make(), "process_count", [*NORMAL, 200, 210])[11][0]
        e = result.evidence
        assert e["metric"] == "process_count"
        assert e["observed"] == 210
        assert e["baseline_mean"] == pytest.approx(100.0)
        assert e["increase_ratio"] == 1.5
        assert e["min_increase"] == 50
        assert e["increase"] == pytest.approx(110.0)
        assert e["threshold"] == pytest.approx(150.0)
        assert e["observed_values"] == [200, 210]
        assert result.threshold_value == pytest.approx(150.0)
        assert result.metric_value == 210

    def test_violations_do_not_poison_the_baseline(self) -> None:
        rule = make(window=20, cooldown=0)
        feed(rule, "process_count", NORMAL)
        out = feed(rule, "process_count", [300] * 15, start=10)
        # Baseline stayed at 100, so the anomaly keeps being detected.
        assert fired(out) == list(range(1, 15))

    def test_persistent_new_level_is_eventually_accepted_as_normal(self) -> None:
        rule = make(window=10, min_baseline=5, cooldown=0)
        feed(rule, "process_count", [100] * 10)
        out = feed(rule, "process_count", [300] * 60, start=10)
        hits = fired(out)
        assert hits, "must alert at first"
        assert hits[-1] < 59, "must stop alerting once the new level has persisted"

    def test_cooldown_suppresses_repeats(self) -> None:
        out = feed(make(cooldown=600.0), "process_count", [*NORMAL, *[300] * 20])
        assert len(fired(out)) == 1

    def test_never_sees_anything_but_a_count(self) -> None:
        # Behavioural guard for SR-05/06: the rule's input type has no process names.
        from detection.types import TelemetryObservation

        assert "process_count" in TelemetryObservation.__slots__  # type: ignore[attr-defined]
        assert not any("name" in s or "cmd" in s for s in TelemetryObservation.__slots__)  # type: ignore[attr-defined]

    def test_deterministic(self) -> None:
        series = [*NORMAL, 300, 300, 100, 300, 300, 300]
        assert feed(make(cooldown=0), "process_count", series) == feed(
            make(cooldown=0), "process_count", series
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"min_baseline": 0},
            {"min_baseline": 25, "window": 20},
            {"ratio": 1.0},
            {"min_increase": 0},
        ],
    )
    def test_invalid_parameters_rejected(self, kwargs: dict[str, int | float]) -> None:
        with pytest.raises(ValueError):
            make(**kwargs)  # type: ignore[arg-type]

    def test_reset_clears_baseline_and_run(self) -> None:
        rule = make()
        feed(rule, "process_count", [*NORMAL, 200])
        rule.reset()
        assert fired(feed(rule, "process_count", [200, 200], start=11)) == []
