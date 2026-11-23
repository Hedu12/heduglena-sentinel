"""
CPU and memory rules.

DET-CPU-001 and DET-MEM-001 detect *sustained* high utilisation: the metric
must be at or above the threshold for N consecutive observed samples. An
isolated spike never fires. A resource anomaly on its own is single-indicator
evidence, so these rules classify as INFORMATIONAL.

"At or above" matches the steering rule that an input at the exact threshold
is a detection (testing-requirements: boundary condition).
"""

from __future__ import annotations

from abc import abstractmethod

from detection.rules.base import (
    DetectionRule,
    consecutive_evidence,
    sustained_confidence,
)
from detection.state import ConsecutiveTracker
from detection.types import DetectionResult, TelemetryObservation
from models.enums import Classification, Severity


class _SustainedPercentRule(DetectionRule):
    """Shared implementation for percentage metrics in [0, 100]."""

    metric_key: str
    event_type: str

    def __init__(
        self,
        *,
        threshold_percent: float,
        consecutive_samples: int,
        cooldown_seconds: float,
        enabled: bool = True,
    ) -> None:
        if not 0.0 <= threshold_percent <= 100.0:
            raise ValueError("threshold_percent must be within [0, 100]")
        super().__init__(cooldown_seconds=cooldown_seconds, enabled=enabled)
        self.threshold_percent = threshold_percent
        self._tracker = ConsecutiveTracker(consecutive_samples)

    @abstractmethod
    def _read(self, observation: TelemetryObservation) -> float | None:
        """Return this rule's metric from the observation."""

    def evaluate_telemetry(self, observation: TelemetryObservation) -> list[DetectionResult]:
        value = self._read(observation)
        violated = value is not None and value >= self.threshold_percent
        hit = self._consecutive_hit(self._tracker, "default", value, violated, observation)
        if hit is None:
            return []
        return [
            self._build_result(
                event_type=self.event_type,
                classification=Classification.INFORMATIONAL,
                confidence=sustained_confidence(self._tracker.run_length, self._tracker.required),
                detected_at=observation.collected_at,
                metric_key=self.metric_key,
                metric_value=hit[-1].value,
                threshold_value=self.threshold_percent,
                telemetry_sample_id=observation.sample_id,
                evidence=consecutive_evidence(
                    metric=self.metric_key,
                    threshold=self.threshold_percent,
                    tracker=self._tracker,
                    hit=hit,
                    extra={"unit": "percent"},
                ),
            )
        ]

    def _reset_state(self) -> None:
        self._tracker.reset()


class CpuAnomalyRule(_SustainedPercentRule):
    """DET-CPU-001: sustained abnormal CPU utilisation."""

    rule_id = "DET-CPU-001"
    name = "Sustained high CPU utilization"
    description = (
        "CPU utilization stayed at or above the configured threshold for the configured "
        "number of consecutive samples."
    )
    severity = Severity.MEDIUM
    metric_key = "cpu_percent"
    event_type = "cpu_sustained_high"

    def _read(self, observation: TelemetryObservation) -> float | None:
        return observation.cpu_percent


class MemoryAnomalyRule(_SustainedPercentRule):
    """DET-MEM-001: sustained abnormal memory utilisation."""

    rule_id = "DET-MEM-001"
    name = "Sustained high memory utilization"
    description = (
        "Memory utilization stayed at or above the configured threshold for the configured "
        "number of consecutive samples."
    )
    severity = Severity.MEDIUM
    metric_key = "memory_percent"
    event_type = "memory_sustained_high"

    def _read(self, observation: TelemetryObservation) -> float | None:
        return observation.memory_percent
