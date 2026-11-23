"""Shared builders for threat-scoring tests. Deterministic: no wall clock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from models.enums import Classification, Severity
from threat.config import ScoringConfig, StateConfig
from threat.evidence import EvidenceItem, category_for
from threat.scorer import ScoreBreakdown, ThreatScorer

T0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)

S = Severity
C = Classification

SCORING = ScoringConfig()
STATE = StateConfig()


def at(seconds: float) -> datetime:
    """A timestamp `seconds` after T0."""
    return T0 + timedelta(seconds=seconds)


_counter = {"n": 0}


def next_id() -> int:
    """Unique, deterministic-per-process event ids."""
    _counter["n"] += 1
    return _counter["n"]


def item(
    event_type: str = "cpu_sustained_high",
    severity: Severity = S.MEDIUM,
    classification: Classification = C.INFORMATIONAL,
    confidence: float = 0.5,
    t: float = 0.0,
    *,
    event_id: int | None = -1,
    synthetic: bool = False,
) -> EvidenceItem:
    """
    Build evidence at T0 + t. event_id=-1 (default) allocates a fresh unique id;
    pass None for an id-less item (never deduplicated) or an int to reuse an id.
    """
    return EvidenceItem(
        event_type=event_type,
        category=category_for(event_type),
        severity=severity,
        classification=classification,
        confidence=confidence,
        detected_at=at(t),
        event_id=next_id() if event_id == -1 else event_id,
        is_synthetic=synthetic,
    )


def scorer(config: ScoringConfig | None = None) -> ThreatScorer:
    return ThreatScorer(config or SCORING)


def score_of(items: list[EvidenceItem], now_s: float | None = None) -> ScoreBreakdown:
    """Score a set of items at `now_s` seconds (default: the latest item time)."""
    s = scorer()
    for it in items:
        s.observe(it)
    latest = max((it.detected_at for it in items), default=T0)
    return s.score(latest if now_s is None else at(now_s))


# Convenient canonical evidence ------------------------------------------------


def cpu(t: float = 0.0, confidence: float = 0.3) -> EvidenceItem:
    return item("cpu_sustained_high", S.MEDIUM, C.INFORMATIONAL, confidence, t)


def net(t: float = 0.0, confidence: float = 0.3) -> EvidenceItem:
    return item("network_throughput_high", S.MEDIUM, C.INFORMATIONAL, confidence, t)


def proc(t: float = 0.0, confidence: float = 0.3) -> EvidenceItem:
    return item("process_count_anomaly", S.LOW, C.INFORMATIONAL, confidence, t)


def auth_suspicious(t: float = 0.0) -> EvidenceItem:
    return item("auth_failure_burst", S.HIGH, C.SUSPICIOUS, 0.55, t, synthetic=True)


def auth_critical(t: float = 0.0) -> EvidenceItem:
    return item("auth_failure_burst", S.CRITICAL, C.HIGH_CONFIDENCE, 0.9, t, synthetic=True)


def malicious_process(t: float = 0.0) -> EvidenceItem:
    return item("suspicious_process", S.CRITICAL, C.HIGH_CONFIDENCE, 0.95, t, synthetic=True)


def connection_suspicious(t: float = 0.0) -> EvidenceItem:
    return item("connection_burst", S.MEDIUM, C.SUSPICIOUS, 0.55, t, synthetic=True)
