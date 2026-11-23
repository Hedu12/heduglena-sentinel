"""Shared builders for detection tests. Deterministic: no wall clock."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from detection.rules.base import DetectionRule
from detection.synthetic import SyntheticEvent
from detection.types import DetectionResult, TelemetryObservation
from models.enums import SyntheticEventType

T0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
STEP_SECONDS = 2.0


def at(index: int, step: float = STEP_SECONDS) -> datetime:
    """Timestamp of the index-th sample in a regular series starting at T0."""
    return T0 + timedelta(seconds=index * step)


def obs(index: int = 0, **metrics: float | int | None) -> TelemetryObservation:
    """Build an observation at series position `index`; sample_id is index + 1."""
    return TelemetryObservation(collected_at=at(index), sample_id=index + 1, **metrics)  # type: ignore[arg-type]


def feed(
    rule: DetectionRule, metric: str, values: Iterable[float | int | None], start: int = 0
) -> list[list[DetectionResult]]:
    """Feed a series of one metric to a rule; return the results per sample."""
    return [
        rule.evaluate_telemetry(obs(start + i, **{metric: value})) for i, value in enumerate(values)
    ]


def fired(outputs: list[list[DetectionResult]]) -> list[int]:
    """Indices of the samples that produced at least one result."""
    return [i for i, out in enumerate(outputs) if out]


def syn(
    event_type: SyntheticEventType,
    seconds: float = 0.0,
    subject: str | None = None,
    **kwargs: str,
) -> SyntheticEvent:
    """Build a synthetic event `seconds` after T0."""
    return SyntheticEvent(
        event_type=event_type,
        occurred_at=T0 + timedelta(seconds=seconds),
        subject=subject,
        **kwargs,
    )
