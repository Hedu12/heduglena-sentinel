"""
DetectionRule: the base abstraction for all detection rules.

A rule is deterministic and side-effect free with respect to the host. It
consumes one observation (or one synthetic event) at a time, keeps only
bounded state, and returns zero or more structured DetectionResults.

Rules never persist anything and never call the engine. The engine owns
scheduling, isolation and persistence (P-01).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from detection.state import ConsecutiveTracker, Cooldown, Violation
from detection.synthetic import SyntheticEvent
from detection.types import (
    DetectionResult,
    Evidence,
    JsonValue,
    RuleInfo,
    TelemetryObservation,
)
from models.enums import Classification, Severity


class DetectionRule(ABC):
    """
    Base class for detection rules.

    Subclasses set the class attributes and override whichever of
    evaluate_telemetry / evaluate_synthetic they handle.
    """

    rule_id: str
    name: str
    description: str
    severity: Severity

    def __init__(self, *, cooldown_seconds: float, enabled: bool = True) -> None:
        self.enabled = enabled
        self._cooldown = Cooldown(cooldown_seconds)

    # ── Public API ─────────────────────────────────────────────────────────

    def info(self) -> RuleInfo:
        return RuleInfo(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            enabled=self.enabled,
        )

    def evaluate_telemetry(self, observation: TelemetryObservation) -> list[DetectionResult]:
        """Evaluate one telemetry observation. Default: not interested."""
        return []

    def evaluate_synthetic(self, event: SyntheticEvent) -> list[DetectionResult]:
        """Evaluate one synthetic security event. Default: not interested."""
        return []

    def on_emission_failed(self, result: DetectionResult) -> None:
        """Called by the engine if `result` could not be persisted."""
        self._cooldown.release(result.dedup_key)

    def reset(self) -> None:
        """Clear all state (cooldowns and rule-specific history)."""
        self._cooldown.clear()
        self._reset_state()

    # ── Subclass hooks ─────────────────────────────────────────────────────

    @abstractmethod
    def _reset_state(self) -> None:
        """Clear rule-specific bounded state."""

    # ── Helpers ────────────────────────────────────────────────────────────

    def _consecutive_hit(
        self,
        tracker: ConsecutiveTracker,
        key: str,
        value: float | None,
        violated: bool,
        observation: TelemetryObservation,
    ) -> tuple[Violation, ...] | None:
        """
        Advance a consecutive-violation tracker and apply debounce.

        A missing value (None) or a non-violating sample breaks the run, so
        "consecutive" always means consecutive *observed* violations; a gap in
        telemetry is never counted as evidence.

        Returns the contributing violations when the rule should fire, else
        None. Marks the cooldown only when returning a hit.
        """
        if value is None or not violated:
            tracker.reset()
            return None
        tracker.violate(value, observation.collected_at, observation.sample_id)
        if not tracker.satisfied:
            return None
        if not self._cooldown.ready(key, observation.collected_at):
            return None
        self._cooldown.mark(key, observation.collected_at)
        return tracker.recent

    def _build_result(
        self,
        *,
        event_type: str,
        classification: Classification,
        confidence: float,
        detected_at: datetime,
        metric_key: str,
        evidence: Evidence,
        severity: Severity | None = None,
        metric_value: float | None = None,
        threshold_value: float | None = None,
        is_synthetic: bool = False,
        telemetry_sample_id: int | None = None,
        dedup_key: str = "default",
    ) -> DetectionResult:
        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            event_type=event_type,
            severity=severity or self.severity,
            classification=classification,
            confidence=confidence,
            detected_at=detected_at,
            metric_key=metric_key,
            evidence=evidence,
            metric_value=metric_value,
            threshold_value=threshold_value,
            is_synthetic=is_synthetic,
            telemetry_sample_id=telemetry_sample_id,
            dedup_key=dedup_key,
        )


def iso(moment: datetime) -> str:
    """ISO-8601 string for evidence values."""
    return moment.isoformat()


def clamp_confidence(value: float, ceiling: float) -> float:
    """Clamp a confidence into [0.0, ceiling]."""
    return max(0.0, min(ceiling, value))


def consecutive_evidence(
    *,
    metric: str,
    threshold: float,
    tracker: ConsecutiveTracker,
    hit: tuple[Violation, ...],
    extra: Evidence | None = None,
) -> Evidence:
    """
    Structured evidence shared by every consecutive-sample rule.

    `observed` is the most recent violating value; `observed_values` are the
    last `required_samples` violating values, oldest first.
    """
    sample_ids: list[JsonValue] = [v.sample_id for v in hit if v.sample_id is not None]
    values: list[JsonValue] = [v.value for v in hit]
    evidence: Evidence = {
        "metric": metric,
        "observed": hit[-1].value,
        "threshold": threshold,
        "comparison": "gte",
        "consecutive_samples": tracker.run_length,
        "required_samples": tracker.required,
        "observed_values": values,
        "contributing_sample_ids": sample_ids,
        "window_start": iso(hit[0].at),
        "window_end": iso(hit[-1].at),
    }
    if extra:
        evidence.update(extra)
    return evidence


def sustained_confidence(run_length: int, required: int) -> float:
    """
    Confidence for a single-indicator resource anomaly.

    Starts at 0.3 and gains 0.05 per sample beyond the required run, capped at
    0.6: one metric alone is never high-confidence evidence of malice.
    """
    return clamp_confidence(0.3 + 0.05 * max(0, run_length - required), 0.6)
