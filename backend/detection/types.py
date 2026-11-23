"""
Detection domain types.

TelemetryObservation is the detection engine's view of one telemetry sample.
It is a plain frozen value object, so rules never touch ORM objects and never
see a value that is NaN, infinite, or outside its legal range.

DetectionResult is what every rule returns. All security-relevant facts live
in typed fields and in the structured `evidence` mapping; human-readable text
is generated separately (detection.describe) and is never the source of truth.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, TypeAlias

from models.enums import Classification, Severity

if TYPE_CHECKING:
    from database.models import TelemetrySample

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
Evidence: TypeAlias = dict[str, JsonValue]


def _finite_in_range(value: float | None, low: float, high: float | None = None) -> float | None:
    """Return value as float if finite and within [low, high], else None."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < low:
        return None
    if high is not None and number > high:
        return None
    return number


@dataclass(frozen=True, slots=True)
class TelemetryObservation:
    """
    One telemetry sample as seen by detection rules.

    Rates are bytes per second as derived in Phase 2. `None` always means
    "not available"; rules must never treat it as zero.
    """

    collected_at: datetime
    sample_id: int | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    net_sent_rate: float | None = None
    net_recv_rate: float | None = None
    process_count: int | None = None

    @classmethod
    def from_sample(cls, sample: TelemetrySample) -> TelemetryObservation:
        """Build a sanitised observation from a persisted TelemetrySample."""
        collected_at = sample.collected_at
        if collected_at.tzinfo is None:
            # SQLite returns naive datetimes; the database layer stores UTC.
            collected_at = collected_at.replace(tzinfo=UTC)
        process_count = sample.process_count
        if process_count is not None and process_count < 0:
            process_count = None
        return cls(
            collected_at=collected_at,
            sample_id=sample.id,
            cpu_percent=_finite_in_range(sample.cpu_percent, 0.0, 100.0),
            memory_percent=_finite_in_range(sample.memory_percent, 0.0, 100.0),
            net_sent_rate=_finite_in_range(sample.net_bytes_sent, 0.0),
            net_recv_rate=_finite_in_range(sample.net_bytes_recv, 0.0),
            process_count=process_count,
        )


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Static description of a rule, for listing rules in an API or UI."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    enabled: bool


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """
    A rule's structured finding. Persisted as a DetectionEvent by the engine.

    dedup_key identifies the debounce bucket (for example a network direction)
    so a failed persist can release exactly the cooldown it consumed.
    """

    rule_id: str
    rule_name: str
    event_type: str
    severity: Severity
    classification: Classification
    confidence: float
    detected_at: datetime
    metric_key: str
    evidence: Evidence
    metric_value: float | None = None
    threshold_value: float | None = None
    is_synthetic: bool = False
    telemetry_sample_id: int | None = None
    dedup_key: str = field(default="default")

    def __post_init__(self) -> None:
        if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {self.confidence!r}")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")
        for name in ("metric_value", "threshold_value"):
            value = getattr(self, name)
            if value is not None and not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
        # allow_nan=False rejects NaN/Infinity anywhere in the evidence tree.
        json.dumps(self.evidence, allow_nan=False)
