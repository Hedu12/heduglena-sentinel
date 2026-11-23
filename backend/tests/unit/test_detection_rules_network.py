"""Unit tests for DET-NET-001 (sustained network throughput)."""

from __future__ import annotations

import math

import pytest

from detection.rules.network import NetworkAnomalyRule
from detection.types import TelemetryObservation
from tests.detection_helpers import at, feed, fired, obs

MB = 1_000_000.0


def make(
    threshold: float = 50 * MB, consecutive: int = 3, cooldown: float = 60.0
) -> NetworkAnomalyRule:
    return NetworkAnomalyRule(
        threshold_bytes_per_second=threshold,
        consecutive_samples=consecutive,
        cooldown_seconds=cooldown,
    )


class TestNetworkThroughput:
    def test_below_threshold_never_fires(self) -> None:
        assert fired(feed(make(), "net_sent_rate", [49 * MB] * 10)) == []

    def test_exactly_at_threshold_fires_when_sustained(self) -> None:
        assert fired(feed(make(), "net_sent_rate", [50 * MB] * 3)) == [2]

    def test_above_threshold_sustained_fires(self) -> None:
        out = feed(make(), "net_sent_rate", [80 * MB] * 3)
        assert fired(out) == [2]

    def test_isolated_burst_does_not_fire(self) -> None:
        assert fired(feed(make(), "net_sent_rate", [1.0, 200 * MB, 1.0, 200 * MB, 1.0])) == []

    def test_zero_rate_is_traffic_below_threshold_and_breaks_run(self) -> None:
        out = feed(make(), "net_sent_rate", [80 * MB, 80 * MB, 0.0, 80 * MB])
        assert fired(out) == []

    def test_missing_rate_breaks_run_and_is_not_zero_traffic(self) -> None:
        # None (first sample / counter reset) must neither count nor fire.
        out = feed(make(), "net_sent_rate", [80 * MB, 80 * MB, None, 80 * MB, 80 * MB])
        assert fired(out) == []

    def test_all_missing_never_fires(self) -> None:
        assert fired(feed(make(), "net_sent_rate", [None] * 10)) == []

    def test_invalid_rates_cannot_reach_the_rule_via_observation(self) -> None:
        # NaN/negative are sanitised to None before any rule sees them.
        from database.models import TelemetrySample
        from tests.detection_helpers import T0

        for bad in (math.nan, math.inf, -1.0):
            sample = TelemetrySample(collected_at=T0, net_bytes_sent=bad, net_bytes_recv=bad)
            o = TelemetryObservation.from_sample(sample)
            assert o.net_sent_rate is None
            assert o.net_recv_rate is None

    def test_inbound_direction_detected(self) -> None:
        out = feed(make(), "net_recv_rate", [90 * MB] * 3)
        assert fired(out) == [2]
        assert out[2][0].evidence["direction"] == "inbound"
        assert out[2][0].metric_key == "net_bytes_recv_rate"

    def test_outbound_direction_detected(self) -> None:
        out = feed(make(), "net_sent_rate", [90 * MB] * 3)
        assert out[2][0].evidence["direction"] == "outbound"
        assert out[2][0].metric_key == "net_bytes_sent_rate"

    def test_directions_are_tracked_independently(self) -> None:
        rule = make()
        results = []
        for i in range(3):
            results.extend(
                rule.evaluate_telemetry(obs(i, net_sent_rate=90 * MB, net_recv_rate=1.0))
            )
        assert [r.evidence["direction"] for r in results] == ["outbound"]

    def test_both_directions_can_fire_on_the_same_sample(self) -> None:
        rule = make()
        last: list = []
        for i in range(3):
            last = rule.evaluate_telemetry(obs(i, net_sent_rate=90 * MB, net_recv_rate=90 * MB))
        assert sorted(r.evidence["direction"] for r in last) == ["inbound", "outbound"]  # type: ignore[type-var]

    def test_each_direction_has_its_own_cooldown(self) -> None:
        rule = make(cooldown=600.0)
        for i in range(3):
            rule.evaluate_telemetry(obs(i, net_sent_rate=90 * MB))
        # Outbound is now in cooldown; inbound has not fired and must still fire.
        out = [rule.evaluate_telemetry(obs(3 + i, net_recv_rate=90 * MB)) for i in range(3)]
        assert fired(out) == [2]

    def test_evidence_contains_rate_threshold_direction_and_duration(self) -> None:
        result = feed(make(), "net_sent_rate", [60 * MB, 70 * MB, 80 * MB])[2][0]
        e = result.evidence
        assert e["observed"] == 80 * MB
        assert e["threshold"] == 50 * MB
        assert e["direction"] == "outbound"
        assert e["unit"] == "bytes_per_second"
        assert e["consecutive_samples"] == 3
        assert e["observed_values"] == [60 * MB, 70 * MB, 80 * MB]
        assert e["window_start"] == at(0).isoformat()
        assert e["window_end"] == at(2).isoformat()
        assert result.telemetry_sample_id == 3

    def test_cooldown_suppresses_repeats(self) -> None:
        assert fired(feed(make(), "net_sent_rate", [90 * MB] * 20)) == [2]

    def test_deterministic(self) -> None:
        series = [90 * MB, 90 * MB, 90 * MB, None, 90 * MB] * 3
        assert feed(make(cooldown=0), "net_sent_rate", series) == feed(
            make(cooldown=0), "net_sent_rate", series
        )

    def test_invalid_threshold_rejected(self) -> None:
        with pytest.raises(ValueError):
            make(threshold=0)

    def test_reset_clears_state(self) -> None:
        rule = make()
        feed(rule, "net_sent_rate", [90 * MB, 90 * MB])
        rule.reset()
        assert fired(feed(rule, "net_sent_rate", [90 * MB], start=2)) == []
