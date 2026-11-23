"""
DET-PROC-001: abnormal process-count behaviour.

Uses only the safe process-count metric from telemetry (a headcount). It
never sees process names, command lines, environment variables, or file
contents.

Detection is deviation-based against a bounded rolling baseline:

    effective_threshold = max(mean * increase_ratio, mean + min_increase)

The ratio catches large relative jumps; the absolute floor stops tiny
baselines from alerting on a handful of new processes. The comparison uses the
baseline *before* the current sample is added, so a sample never inflates its
own baseline.

Violating samples are kept out of the baseline so an anomaly cannot quietly
raise the bar for itself. If a new level persists for more than a full window
it is accepted as the new normal and starts feeding the baseline again;
otherwise a permanent change would alert forever.
"""

from __future__ import annotations

from detection.rules.base import (
    DetectionRule,
    consecutive_evidence,
    sustained_confidence,
)
from detection.state import ConsecutiveTracker, RollingBaseline
from detection.types import DetectionResult, Evidence, TelemetryObservation
from models.enums import Classification, Severity


class ProcessCountAnomalyRule(DetectionRule):
    """DET-PROC-001: process count far above its recent baseline."""

    rule_id = "DET-PROC-001"
    name = "Abnormal process count"
    description = (
        "The number of running processes exceeded its rolling baseline by the configured "
        "ratio and absolute amount for the configured number of consecutive samples."
    )
    severity = Severity.LOW
    metric_key = "process_count"
    event_type = "process_count_anomaly"

    def __init__(
        self,
        *,
        window_samples: int,
        min_baseline_samples: int,
        increase_ratio: float,
        min_increase: int,
        consecutive_samples: int,
        cooldown_seconds: float,
        enabled: bool = True,
    ) -> None:
        if min_baseline_samples < 1 or min_baseline_samples > window_samples:
            raise ValueError("min_baseline_samples must be within [1, window_samples]")
        if increase_ratio <= 1.0:
            raise ValueError("increase_ratio must be > 1.0")
        if min_increase < 1:
            raise ValueError("min_increase must be >= 1")
        super().__init__(cooldown_seconds=cooldown_seconds, enabled=enabled)
        self.window_samples = window_samples
        self.min_baseline_samples = min_baseline_samples
        self.increase_ratio = increase_ratio
        self.min_increase = min_increase
        self._baseline = RollingBaseline(window_samples)
        self._tracker = ConsecutiveTracker(consecutive_samples)

    def evaluate_telemetry(self, observation: TelemetryObservation) -> list[DetectionResult]:
        count = observation.process_count
        if count is None:
            # A gap breaks the run; the baseline is left untouched.
            self._tracker.reset()
            return []

        mean = self._baseline.mean() if len(self._baseline) >= self.min_baseline_samples else None
        threshold: float | None = None
        violated = False
        if mean is not None:
            threshold = max(mean * self.increase_ratio, mean + self.min_increase)
            violated = count >= threshold

        hit = self._consecutive_hit(self._tracker, "default", float(count), violated, observation)

        # Feed the baseline *after* comparing. Violations stay out unless the
        # new level has persisted for more than a full window.
        if not violated or self._tracker.run_length > self.window_samples:
            self._baseline.add(float(count))

        if hit is None or mean is None or threshold is None:
            return []

        extra: Evidence = {
            "unit": "processes",
            "baseline_mean": mean,
            "baseline_samples": len(self._baseline),
            "increase_ratio": self.increase_ratio,
            "min_increase": self.min_increase,
            "increase": hit[-1].value - mean,
        }
        return [
            self._build_result(
                event_type=self.event_type,
                classification=Classification.INFORMATIONAL,
                confidence=sustained_confidence(self._tracker.run_length, self._tracker.required),
                detected_at=observation.collected_at,
                metric_key=self.metric_key,
                metric_value=hit[-1].value,
                threshold_value=threshold,
                telemetry_sample_id=observation.sample_id,
                evidence=consecutive_evidence(
                    metric=self.metric_key,
                    threshold=threshold,
                    tracker=self._tracker,
                    hit=hit,
                    extra=extra,
                ),
            )
        ]

    def _reset_state(self) -> None:
        self._baseline.clear()
        self._tracker.reset()
