"""Unit tests for bounded detection state and core detection types."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from database.models import TelemetrySample
from detection.state import ConsecutiveTracker, Cooldown, RollingBaseline
from detection.types import DetectionResult, TelemetryObservation
from models.enums import Classification, Severity
from tests.detection_helpers import T0, at


class TestConsecutiveTracker:
    def test_counts_violations(self) -> None:
        t = ConsecutiveTracker(3)
        assert [t.violate(90.0 + i, at(i), i) for i in range(3)] == [1, 2, 3]
        assert t.satisfied

    def test_not_satisfied_until_required(self) -> None:
        t = ConsecutiveTracker(3)
        t.violate(1.0, at(0), 1)
        t.violate(1.0, at(1), 2)
        assert not t.satisfied

    def test_reset_breaks_run(self) -> None:
        t = ConsecutiveTracker(2)
        t.violate(1.0, at(0), 1)
        t.reset()
        assert t.run_length == 0
        assert t.recent == ()

    def test_recent_is_bounded_by_required(self) -> None:
        t = ConsecutiveTracker(3)
        for i in range(100):
            t.violate(float(i), at(i), i)
        assert t.run_length == 100
        assert [v.value for v in t.recent] == [97.0, 98.0, 99.0]

    def test_required_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            ConsecutiveTracker(0)


class TestRollingBaseline:
    def test_mean_of_empty_is_none(self) -> None:
        assert RollingBaseline(5).mean() is None

    def test_mean(self) -> None:
        b = RollingBaseline(5)
        for v in (10.0, 20.0, 30.0):
            b.add(v)
        assert b.mean() == pytest.approx(20.0)

    def test_window_is_bounded(self) -> None:
        b = RollingBaseline(3)
        for v in range(1, 11):
            b.add(float(v))
        assert len(b) == 3
        assert b.mean() == pytest.approx(9.0)  # 8, 9, 10

    def test_clear(self) -> None:
        b = RollingBaseline(3)
        b.add(1.0)
        b.clear()
        assert len(b) == 0

    def test_maxlen_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            RollingBaseline(0)


class TestCooldown:
    def test_first_use_is_ready(self) -> None:
        assert Cooldown(60).ready("k", T0)

    def test_blocked_within_window(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        assert not c.ready("k", T0 + timedelta(seconds=59.9))

    def test_ready_at_exact_expiry(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        assert c.ready("k", T0 + timedelta(seconds=60))

    def test_keys_are_independent(self) -> None:
        c = Cooldown(60)
        c.mark("a", T0)
        assert c.ready("b", T0)

    def test_higher_level_bypasses_cooldown(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0, level=0)
        assert c.ready("k", T0 + timedelta(seconds=1), level=1)
        assert not c.ready("k", T0 + timedelta(seconds=1), level=0)

    def test_same_level_does_not_bypass(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0, level=1)
        assert not c.ready("k", T0 + timedelta(seconds=1), level=1)

    def test_backwards_time_does_not_block_forever(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        assert c.ready("k", T0 - timedelta(hours=1))

    def test_release_restores_previous_entry(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        c.mark("k", T0 + timedelta(seconds=100))
        c.release("k")
        # Back to the first mark: 100s after T0 is past its 60s expiry.
        assert c.ready("k", T0 + timedelta(seconds=100))
        assert not c.ready("k", T0 + timedelta(seconds=30))

    def test_release_of_first_mark_clears_key(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        c.release("k")
        assert c.ready("k", T0)

    def test_release_without_mark_is_noop(self) -> None:
        Cooldown(60).release("never")

    def test_zero_seconds_never_blocks(self) -> None:
        c = Cooldown(0)
        c.mark("k", T0)
        assert c.ready("k", T0)

    def test_negative_seconds_rejected(self) -> None:
        with pytest.raises(ValueError):
            Cooldown(-1)

    def test_clear(self) -> None:
        c = Cooldown(60)
        c.mark("k", T0)
        c.clear()
        assert c.ready("k", T0)


class TestTelemetryObservationFromSample:
    def _sample(self, **kwargs: object) -> TelemetrySample:
        base: dict[str, object] = {"collected_at": T0}
        base.update(kwargs)
        return TelemetrySample(**base)  # type: ignore[arg-type]

    def test_valid_values_pass_through(self) -> None:
        s = self._sample(
            cpu_percent=50.0,
            memory_percent=60.0,
            net_bytes_sent=1000.0,
            net_bytes_recv=2000.0,
            process_count=120,
        )
        o = TelemetryObservation.from_sample(s)
        assert (o.cpu_percent, o.memory_percent) == (50.0, 60.0)
        assert (o.net_sent_rate, o.net_recv_rate) == (1000.0, 2000.0)
        assert o.process_count == 120

    @pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0, 100.5])
    def test_invalid_percent_becomes_none(self, bad: float) -> None:
        o = TelemetryObservation.from_sample(self._sample(cpu_percent=bad, memory_percent=bad))
        assert o.cpu_percent is None
        assert o.memory_percent is None

    @pytest.mark.parametrize("bad", [math.nan, math.inf, -5.0])
    def test_invalid_rate_becomes_none(self, bad: float) -> None:
        o = TelemetryObservation.from_sample(self._sample(net_bytes_sent=bad, net_bytes_recv=bad))
        assert o.net_sent_rate is None
        assert o.net_recv_rate is None

    def test_zero_rate_is_preserved_not_dropped(self) -> None:
        o = TelemetryObservation.from_sample(self._sample(net_bytes_sent=0.0))
        assert o.net_sent_rate == 0.0

    def test_negative_process_count_becomes_none(self) -> None:
        assert (
            TelemetryObservation.from_sample(self._sample(process_count=-1)).process_count is None
        )

    def test_naive_timestamp_is_treated_as_utc(self) -> None:
        o = TelemetryObservation.from_sample(self._sample(collected_at=datetime(2025, 1, 1, 12, 0)))
        assert o.collected_at.tzinfo is not None

    def test_missing_values_stay_none(self) -> None:
        o = TelemetryObservation.from_sample(self._sample())
        assert o.cpu_percent is None
        assert o.process_count is None


class TestDetectionResultValidation:
    def _result(self, **overrides: object) -> DetectionResult:
        base: dict[str, object] = {
            "rule_id": "R",
            "rule_name": "Rule",
            "event_type": "t",
            "severity": Severity.LOW,
            "classification": Classification.INFORMATIONAL,
            "confidence": 0.5,
            "detected_at": datetime.now(UTC),
            "metric_key": "m",
            "evidence": {"a": 1},
        }
        base.update(overrides)
        return DetectionResult(**base)  # type: ignore[arg-type]

    def test_valid(self) -> None:
        assert self._result().confidence == 0.5

    @pytest.mark.parametrize("bad", [-0.01, 1.01, math.nan, math.inf])
    def test_confidence_out_of_range_rejected(self, bad: float) -> None:
        with pytest.raises(ValueError):
            self._result(confidence=bad)

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValueError):
            self._result(detected_at=datetime(2025, 1, 1))

    def test_nan_in_evidence_rejected(self) -> None:
        with pytest.raises(ValueError):
            self._result(evidence={"x": math.nan})

    def test_nested_infinity_in_evidence_rejected(self) -> None:
        with pytest.raises(ValueError):
            self._result(evidence={"x": [1, {"y": math.inf}]})

    def test_non_finite_metric_value_rejected(self) -> None:
        with pytest.raises(ValueError):
            self._result(metric_value=math.nan)
