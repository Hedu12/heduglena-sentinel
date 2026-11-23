"""
Evidence: the scorer's view of a detection event.

EvidenceItem is a plain frozen value object derived from a persisted
DetectionEvent. The scorer never sees the event's free-form JSON, only typed
columns, so untrusted text cannot influence the score.

Signal categories identify *independent* kinds of evidence. Two events from
the same category are the same underlying signal for correlation purposes;
only distinct categories count as corroboration.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from models.enums import Classification, Severity

if TYPE_CHECKING:
    from database.models import DetectionEvent


class SignalCategory(StrEnum):
    CPU = "CPU"
    MEMORY = "MEMORY"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    AUTHENTICATION = "AUTHENTICATION"
    ACCESS = "ACCESS"
    CONNECTION = "CONNECTION"
    EXECUTION = "EXECUTION"
    OTHER = "OTHER"


# Host-resource anomalies versus security events. A resource anomaly together
# with a security event is stronger corroboration than two of the same domain.
RESOURCE_CATEGORIES: frozenset[SignalCategory] = frozenset(
    {
        SignalCategory.CPU,
        SignalCategory.MEMORY,
        SignalCategory.NETWORK,
        SignalCategory.PROCESS,
    }
)
SECURITY_CATEGORIES: frozenset[SignalCategory] = frozenset(
    {
        SignalCategory.AUTHENTICATION,
        SignalCategory.ACCESS,
        SignalCategory.CONNECTION,
        SignalCategory.EXECUTION,
    }
)

_CATEGORY_BY_EVENT_TYPE: dict[str, SignalCategory] = {
    "cpu_sustained_high": SignalCategory.CPU,
    "memory_sustained_high": SignalCategory.MEMORY,
    "network_throughput_high": SignalCategory.NETWORK,
    "process_count_anomaly": SignalCategory.PROCESS,
    "auth_failure_burst": SignalCategory.AUTHENTICATION,
    "access_denied_burst": SignalCategory.ACCESS,
    "connection_burst": SignalCategory.CONNECTION,
    "suspicious_process": SignalCategory.EXECUTION,
}

_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
_CLASSIFICATION_ORDER = (
    Classification.INFORMATIONAL,
    Classification.SUSPICIOUS,
    Classification.HIGH_CONFIDENCE,
)


MAX_EVENT_TYPE_LENGTH = 64


def clean_event_type(raw: str) -> str:
    """
    Reduce an event type read from the database to a short printable label.

    Event types are written by Sentinel's own rules, but the column is plain
    text. Anything else is untrusted: control characters are dropped and the
    length is capped, so a tampered row cannot bloat or corrupt the scorer's
    output. Known event types pass through unchanged.
    """
    printable = "".join(ch for ch in raw if not unicodedata.category(ch).startswith("C"))
    return printable[:MAX_EVENT_TYPE_LENGTH] or "unknown"


def category_for(event_type: str) -> SignalCategory:
    """Signal category for a detection event type (OTHER if unknown)."""
    return _CATEGORY_BY_EVENT_TYPE.get(event_type, SignalCategory.OTHER)


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER.index(severity)


def classification_rank(classification: Classification) -> int:
    return _CLASSIFICATION_ORDER.index(classification)


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One detection event as evidence."""

    event_type: str
    category: SignalCategory
    severity: Severity
    classification: Classification
    confidence: float
    detected_at: datetime
    event_id: int | None = None
    rule_id: str = ""
    is_synthetic: bool = False
    telemetry_sample_id: int | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")

    @property
    def rank(self) -> tuple[int, int, float]:
        """Ordering used to decide which observation is the strongest."""
        return (
            severity_rank(self.severity),
            classification_rank(self.classification),
            self.confidence,
        )

    @classmethod
    def from_event(cls, event: DetectionEvent, *, default_confidence: float) -> EvidenceItem:
        """Build evidence from a persisted DetectionEvent (typed columns only)."""
        detected_at = event.detected_at
        if detected_at.tzinfo is None:
            # SQLite returns naive datetimes; the database layer stores UTC.
            detected_at = detected_at.replace(tzinfo=UTC)
        event_type = clean_event_type(event.event_type)
        return cls(
            event_type=event_type,
            category=category_for(event_type),
            severity=Severity(event.severity),
            classification=Classification(event.classification),
            confidence=default_confidence if event.confidence is None else event.confidence,
            detected_at=detected_at,
            event_id=event.id,
            rule_id=event.rule_id,
            is_synthetic=event.is_synthetic,
            telemetry_sample_id=event.telemetry_sample_id,
        )
