"""
DET-SYN-001: synthetic security events.

Evaluates the controlled security events injected for demonstrations through
the same engine and rule pipeline as telemetry (P-10). Nothing here touches
the host; events are plain data.

Each event type has a SyntheticPolicy: how many events inside a time window
trigger a detection, and at what severity/classification. Reaching the base
threshold is SUSPICIOUS; reaching the escalation threshold is HIGH_CONFIDENCE.
An escalation bypasses the debounce so a worsening situation is always
reported, while plain repeats inside the cooldown are suppressed.

Windows are bounded (deque maxlen = the highest threshold) and judged by the
events' own timestamps, so the result is deterministic.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from detection.rules.base import DetectionRule, iso
from detection.synthetic import SyntheticEvent
from detection.types import DetectionResult, Evidence
from models.enums import Classification, Severity, SyntheticEventType


@dataclass(frozen=True, slots=True)
class SyntheticPolicy:
    """How one synthetic event type maps to detections."""

    detection_type: str
    threshold: int
    window_seconds: float
    severity: Severity
    classification: Classification
    escalation_threshold: int | None = None
    escalated_severity: Severity | None = None
    escalated_classification: Classification | None = None

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("threshold must be >= 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.escalation_threshold is not None:
            if self.escalation_threshold <= self.threshold:
                raise ValueError("escalation_threshold must exceed threshold")
            if self.escalated_severity is None or self.escalated_classification is None:
                raise ValueError("escalation requires escalated severity and classification")

    @property
    def capacity(self) -> int:
        """Maximum events retained: the highest threshold we need to reach."""
        return self.escalation_threshold or self.threshold


class SyntheticSecurityEventRule(DetectionRule):
    """DET-SYN-001: bursts of synthetic security events."""

    rule_id = "DET-SYN-001"
    name = "Synthetic security event"
    description = (
        "Repeated synthetic security events (authentication failures, access denials, "
        "connection bursts) or a simulated malicious process within a time window."
    )
    severity = Severity.HIGH

    def __init__(
        self,
        *,
        policies: Mapping[SyntheticEventType, SyntheticPolicy],
        cooldown_seconds: float,
        enabled: bool = True,
    ) -> None:
        super().__init__(cooldown_seconds=cooldown_seconds, enabled=enabled)
        self._policies = dict(policies)
        self._windows: dict[SyntheticEventType, deque[tuple[datetime, str | None]]] = {
            event_type: deque(maxlen=policy.capacity) for event_type, policy in policies.items()
        }

    def evaluate_synthetic(self, event: SyntheticEvent) -> list[DetectionResult]:
        policy = self._policies.get(event.event_type)
        if policy is None:
            return []

        window = self._windows[event.event_type]
        window.append((event.occurred_at, event.subject))
        latest = max(at for at, _ in window)
        cutoff = latest - timedelta(seconds=policy.window_seconds)
        kept = [(at, subject) for at, subject in window if at >= cutoff]
        window.clear()
        window.extend(kept)

        count = len(kept)
        level = self._level(policy, count)
        if level is None:
            return []

        key = event.event_type.value
        if not self._cooldown.ready(key, event.occurred_at, level):
            return []
        self._cooldown.mark(key, event.occurred_at, level)

        escalated = level == 1
        severity = (policy.escalated_severity if escalated else policy.severity) or policy.severity
        classification = (
            policy.escalated_classification if escalated else policy.classification
        ) or policy.classification
        subjects = {subject for _, subject in kept if subject is not None}
        evidence: Evidence = {
            "event_type": event.event_type.value,
            "observed_count": count,
            "observed_count_is_lower_bound": count >= policy.capacity,
            "threshold": policy.threshold,
            "escalation_threshold": policy.escalation_threshold,
            "escalated": escalated,
            "window_seconds": policy.window_seconds,
            "first_event_at": iso(min(at for at, _ in kept)),
            "last_event_at": iso(latest),
            "distinct_subjects": len(subjects),
            # Untrusted label: stored as data only, already sanitised.
            "latest_subject": event.subject,
            "source": event.source,
            "scenario_id": event.scenario_id,
            "synthetic": True,
        }
        return [
            self._build_result(
                event_type=policy.detection_type,
                classification=classification,
                severity=severity,
                confidence=self._confidence(policy, count, level),
                detected_at=event.occurred_at,
                metric_key=f"synthetic:{event.event_type.value}",
                metric_value=float(count),
                threshold_value=float(policy.threshold),
                is_synthetic=True,
                dedup_key=key,
                evidence=evidence,
            )
        ]

    @staticmethod
    def _level(policy: SyntheticPolicy, count: int) -> int | None:
        """0 = base threshold reached, 1 = escalation threshold reached."""
        if policy.escalation_threshold is not None and count >= policy.escalation_threshold:
            return 1
        if count >= policy.threshold:
            return 0
        return None

    @staticmethod
    def _confidence(policy: SyntheticPolicy, count: int, level: int) -> float:
        """
        Deterministic confidence.

        Policies with no escalation (a single decisive event) report 0.95.
        Otherwise 0.55 at the base threshold rising to 0.80 just below the
        escalation threshold, and 0.90 once escalated.
        """
        if policy.escalation_threshold is None:
            return 0.95
        if level == 1:
            return 0.90
        span = policy.escalation_threshold - policy.threshold
        progress = min(1.0, max(0.0, (count - policy.threshold) / span))
        return 0.55 + 0.25 * progress

    def _reset_state(self) -> None:
        for window in self._windows.values():
            window.clear()
