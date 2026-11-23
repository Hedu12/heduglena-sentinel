"""
DET-NET-001: abnormal network throughput.

Operates only on the per-second rates derived in Phase 2 (never on cumulative
counters). Each direction is tracked independently, with its own consecutive
run and its own debounce, so heavy download traffic does not mask or suppress
an upload anomaly.

A missing rate (first sample, counter reset, invalid value) breaks the run:
it is never treated as zero traffic and never counted as a violation.
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.rules.base import (
    DetectionRule,
    consecutive_evidence,
    sustained_confidence,
)
from detection.state import ConsecutiveTracker
from detection.types import DetectionResult, TelemetryObservation
from models.enums import Classification, Severity


@dataclass(frozen=True, slots=True)
class _Direction:
    key: str
    metric_key: str


_OUTBOUND = _Direction(key="outbound", metric_key="net_bytes_sent_rate")
_INBOUND = _Direction(key="inbound", metric_key="net_bytes_recv_rate")


class NetworkAnomalyRule(DetectionRule):
    """DET-NET-001: sustained high network throughput in either direction."""

    rule_id = "DET-NET-001"
    name = "Sustained high network throughput"
    description = (
        "Network throughput in one direction stayed at or above the configured "
        "bytes-per-second threshold for the configured number of consecutive samples."
    )
    severity = Severity.MEDIUM
    event_type = "network_throughput_high"

    def __init__(
        self,
        *,
        threshold_bytes_per_second: float,
        consecutive_samples: int,
        cooldown_seconds: float,
        enabled: bool = True,
    ) -> None:
        if threshold_bytes_per_second <= 0:
            raise ValueError("threshold_bytes_per_second must be > 0")
        super().__init__(cooldown_seconds=cooldown_seconds, enabled=enabled)
        self.threshold_bytes_per_second = threshold_bytes_per_second
        self._trackers = {
            _OUTBOUND.key: ConsecutiveTracker(consecutive_samples),
            _INBOUND.key: ConsecutiveTracker(consecutive_samples),
        }

    def evaluate_telemetry(self, observation: TelemetryObservation) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        readings = (
            (_OUTBOUND, observation.net_sent_rate),
            (_INBOUND, observation.net_recv_rate),
        )
        for direction, rate in readings:
            tracker = self._trackers[direction.key]
            violated = rate is not None and rate >= self.threshold_bytes_per_second
            hit = self._consecutive_hit(tracker, direction.key, rate, violated, observation)
            if hit is None:
                continue
            results.append(
                self._build_result(
                    event_type=self.event_type,
                    classification=Classification.INFORMATIONAL,
                    confidence=sustained_confidence(tracker.run_length, tracker.required),
                    detected_at=observation.collected_at,
                    metric_key=direction.metric_key,
                    metric_value=hit[-1].value,
                    threshold_value=self.threshold_bytes_per_second,
                    telemetry_sample_id=observation.sample_id,
                    dedup_key=direction.key,
                    evidence=consecutive_evidence(
                        metric=direction.metric_key,
                        threshold=self.threshold_bytes_per_second,
                        tracker=tracker,
                        hit=hit,
                        extra={"direction": direction.key, "unit": "bytes_per_second"},
                    ),
                )
            )
        return results

    def _reset_state(self) -> None:
        for tracker in self._trackers.values():
            tracker.reset()
