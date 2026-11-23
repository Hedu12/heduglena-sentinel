"""
ThreatScorer: a deterministic, explainable, bounded threat score.

    score = clamp( severity + confidence + repetition + escalation
                   + correlation + cross_domain , 0, 1 )

Evidence is grouped into *signals*: one per (category, event type). Duplicate
events from the same underlying signal strengthen that one signal; they are
never counted as independent corroboration.

For one piece of evidence observed `age` seconds ago:

    freshness = 0.5 ** (age / half_life)            (signal dropped past the TTL)
    strength  = level(severity) * freshness         in [0, 1]

Each signal's strength is the *maximum* over its evidence, and every term is
bounded by its configured weight:

    severity    = W_sev  * max(strength)
    confidence  = W_conf * max(confidence * strength)
    repetition  = W_rep  * max((1 - exp(-(n-1)/scale)) * strength)
    escalation  = W_esc  * max(strength of signals that escalated)
    correlation = min(W_corr, W_cat * (sum of category strengths - the largest))
    cross       = W_cross * min(strongest resource category, strongest security category)

Because every term is a maximum, a saturating function, or "sum minus max" of
non-negative values, the score is monotone in the evidence: adding an event
never lowers it, so a weaker event can never hide a stronger one.

A decaying maximum is kept exactly in O(1): since v * 0.5**((now - t)/H) =
2**(log2(v) + t/H) * 2**(-now/H), items rank by log2(v) + t/H regardless of
`now`. Each signal therefore stores one item per term, not its whole history.

The score is a pure function of (evidence, now): no wall clock, no
randomness, no I/O, no LLM.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from datetime import datetime

from models.enums import Classification, Severity
from threat.config import ScoringConfig
from threat.evidence import (
    RESOURCE_CATEGORIES,
    SECURITY_CATEGORIES,
    EvidenceItem,
    SignalCategory,
    classification_rank,
    severity_rank,
)
from threat.reasons import ReasonCode, reason_text

MAX_REPORTED_SIGNALS = 10
_PRECISION = 6

_DecayKey = tuple[float, float]


@dataclass(frozen=True, slots=True)
class SignalSummary:
    """How one signal contributed to the current score.

    severity, classification and event_id describe the strongest evidence;
    peak_confidence is the confidence of the evidence driving the confidence term.
    """

    category: SignalCategory
    event_type: str
    severity: Severity
    classification: Classification
    confidence: float
    peak_confidence: float
    strength: float
    freshness: float
    count: int
    escalated: bool
    is_synthetic: bool
    event_id: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category.value,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "classification": self.classification.value,
            "confidence": self.confidence,
            "peak_confidence": self.peak_confidence,
            "strength": self.strength,
            "freshness": self.freshness,
            "count": self.count,
            "escalated": self.escalated,
            "is_synthetic": self.is_synthetic,
            "event_id": self.event_id,
        }


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """A threat score and the exact arithmetic behind it."""

    calculated_at: datetime
    severity_contribution: float
    confidence_contribution: float
    repetition_contribution: float
    escalation_contribution: float
    correlation_contribution: float
    cross_domain_contribution: float
    raw_total: float
    score_before_decay: float
    decay: float
    final_score: float
    signals: tuple[SignalSummary, ...]
    signal_count: int
    active_categories: tuple[SignalCategory, ...]
    reason_codes: tuple[ReasonCode, ...]
    active_max_severity: Severity | None
    severe_active: bool
    # Independent categories whose current strength reaches the corroboration minimum.
    corroborating_categories: int = 0

    @property
    def reasons(self) -> list[str]:
        """Display text for the reason codes."""
        return reason_text(self.reason_codes)

    def to_dict(self) -> dict[str, object]:
        return {
            "calculated_at": self.calculated_at.isoformat(),
            "severity_contribution": self.severity_contribution,
            "confidence_contribution": self.confidence_contribution,
            "repetition_contribution": self.repetition_contribution,
            "escalation_contribution": self.escalation_contribution,
            "correlation_contribution": self.correlation_contribution,
            "cross_domain_contribution": self.cross_domain_contribution,
            "raw_total": self.raw_total,
            "score_before_decay": self.score_before_decay,
            "decay": self.decay,
            "final_score": self.final_score,
            "signal_count": self.signal_count,
            "active_categories": [c.value for c in self.active_categories],
            "reason_codes": [c.value for c in self.reason_codes],
            "reasons": self.reasons,
            "active_max_severity": self.active_max_severity.value
            if self.active_max_severity
            else None,
            "severe_active": self.severe_active,
            "corroborating_categories": self.corroborating_categories,
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass(slots=True)
class _Signal:
    """Bounded per-signal state: two evidence slots plus a few scalars."""

    category: SignalCategory
    event_type: str
    top_level: EvidenceItem  # greatest decayed level(severity)
    top_level_key: _DecayKey
    top_conf: EvidenceItem  # greatest decayed confidence * level(severity)
    top_conf_key: _DecayKey
    max_level: float  # undecayed maxima, for the "before decay" score
    max_conf_level: float
    max_level_key: tuple[int, int]  # (severity rank, classification rank) ever seen
    count: int
    first_seen: datetime
    last_seen: datetime
    escalated: bool = False
    last_by_severity: dict[Severity, datetime] = field(default_factory=dict)
    last_by_class: dict[Classification, datetime] = field(default_factory=dict)
    last_severe: datetime | None = None
    last_synthetic: datetime | None = None


@dataclass(frozen=True, slots=True)
class _Terms:
    severity: float
    confidence: float
    repetition: float
    escalation: float
    correlation: float
    cross_domain: float
    signals: tuple[SignalSummary, ...]
    categories: tuple[SignalCategory, ...]
    corroborating: int = 0

    @property
    def total(self) -> float:
        return round(
            self.severity
            + self.confidence
            + self.repetition
            + self.escalation
            + self.correlation
            + self.cross_domain,
            _PRECISION,
        )


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _level_key(item: EvidenceItem) -> tuple[int, int]:
    """(severity, classification) rank: confidence alone is not an escalation."""
    return (severity_rank(item.severity), classification_rank(item.classification))


class ThreatScorer:
    """Aggregates detection evidence into a bounded threat score."""

    def __init__(self, config: ScoringConfig) -> None:
        self._cfg = config
        self._signals: dict[tuple[SignalCategory, str], _Signal] = {}
        self._seen: dict[int, None] = {}
        self._latest_time: datetime | None = None

    # ── Evidence intake ────────────────────────────────────────────────────

    @property
    def signal_count(self) -> int:
        return len(self._signals)

    def observe(self, item: EvidenceItem, now: datetime | None = None) -> bool:
        """
        Add one piece of evidence. Returns False if it was a duplicate event.

        If `now` is given, evidence dated after it is clamped to `now`. An
        event cannot have happened in the future, and without this a
        far-future timestamp (for example on an injected synthetic event)
        would stay "fresh" and hold the score up indefinitely. Callers should
        use a non-decreasing `now`.

        Memory is bounded: at most `max_signals` signals, two evidence items
        per signal, and `dedup_window` remembered event ids.
        """
        if now is not None and item.detected_at > now:
            item = replace(item, detected_at=now)
        if item.event_id is not None:
            if item.event_id in self._seen:
                return False
            self._seen[item.event_id] = None
            while len(self._seen) > self._cfg.dedup_window:
                self._seen.pop(next(iter(self._seen)))

        if self._latest_time is None or item.detected_at > self._latest_time:
            self._latest_time = item.detected_at

        level = self._cfg.level(item.severity)
        conf_level = item.confidence * level
        level_key = self._decay_key(level, item.detected_at)
        conf_key = self._decay_key(conf_level, item.detected_at)

        key = (item.category, item.event_type)
        signal = self._signals.get(key)
        if signal is None:
            if len(self._signals) >= self._cfg.max_signals:
                self._evict_stalest()
            signal = _Signal(
                category=item.category,
                event_type=item.event_type,
                top_level=item,
                top_level_key=level_key,
                top_conf=item,
                top_conf_key=conf_key,
                max_level=level,
                max_conf_level=conf_level,
                max_level_key=_level_key(item),
                count=1,
                first_seen=item.detected_at,
                last_seen=item.detected_at,
            )
            self._signals[key] = signal
        else:
            signal.count = min(self._cfg.repetition_cap, signal.count + 1)
            if _level_key(item) > signal.max_level_key:
                signal.escalated = True
                signal.max_level_key = _level_key(item)
            if level_key >= signal.top_level_key:
                signal.top_level, signal.top_level_key = item, level_key
            if conf_key >= signal.top_conf_key:
                signal.top_conf, signal.top_conf_key = item, conf_key
            signal.max_level = max(signal.max_level, level)
            signal.max_conf_level = max(signal.max_conf_level, conf_level)
            signal.first_seen = min(signal.first_seen, item.detected_at)
            signal.last_seen = max(signal.last_seen, item.detected_at)

        self._record_recency(signal, item)
        self.prune(self._latest_time)
        return True

    @staticmethod
    def _record_recency(signal: _Signal, item: EvidenceItem) -> None:
        """Remember when each severity/classification was last seen (for the active window)."""
        at = item.detected_at
        previous = signal.last_by_severity.get(item.severity)
        if previous is None or at > previous:
            signal.last_by_severity[item.severity] = at
        previous_class = signal.last_by_class.get(item.classification)
        if previous_class is None or at > previous_class:
            signal.last_by_class[item.classification] = at
        if (
            item.severity is Severity.CRITICAL
            and item.classification is Classification.HIGH_CONFIDENCE
        ):
            if signal.last_severe is None or at > signal.last_severe:
                signal.last_severe = at
        if item.is_synthetic and item.category in SECURITY_CATEGORIES:
            if signal.last_synthetic is None or at > signal.last_synthetic:
                signal.last_synthetic = at

    def _decay_key(self, value: float, at: datetime) -> _DecayKey:
        """Rank of a decaying value; independent of `now` (see module docstring)."""
        stamp = at.timestamp()
        if value <= 0.0:
            return (-math.inf, stamp)
        return (math.log2(value) + stamp / self._cfg.half_life_seconds, stamp)

    def prune(self, now: datetime) -> None:
        """Drop signals whose latest evidence is older than the TTL."""
        ttl = self._cfg.evidence_ttl_seconds
        stale = [k for k, s in self._signals.items() if (now - s.last_seen).total_seconds() > ttl]
        for key in stale:
            del self._signals[key]

    def reset(self) -> None:
        self._signals.clear()
        self._seen.clear()
        self._latest_time = None

    def _evict_stalest(self) -> None:
        stalest = min(self._signals.values(), key=lambda s: (s.last_seen, s.category, s.event_type))
        del self._signals[(stalest.category, stalest.event_type)]

    # ── Scoring ────────────────────────────────────────────────────────────

    def score(self, now: datetime) -> ScoreBreakdown:
        """Score the active evidence at `now`. Pure: does not change state."""
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        active = self._active_signals(now)
        decayed = self._terms(active, now, decay=True)
        undecayed = self._terms(active, now, decay=False)
        final = _clamp01(decayed.total)
        before = _clamp01(undecayed.total)
        decay = round(max(0.0, before - final), _PRECISION)

        severities, classes, synthetic, severe = self._active_window(active, now)
        max_severity = max(severities, key=severity_rank, default=None)
        codes = self._reason_codes(active, severities, classes, synthetic, decayed, decay)
        return ScoreBreakdown(
            calculated_at=now,
            severity_contribution=decayed.severity,
            confidence_contribution=decayed.confidence,
            repetition_contribution=decayed.repetition,
            escalation_contribution=decayed.escalation,
            correlation_contribution=decayed.correlation,
            cross_domain_contribution=decayed.cross_domain,
            raw_total=decayed.total,
            score_before_decay=before,
            decay=decay,
            final_score=final,
            signals=decayed.signals,
            signal_count=len(active),
            active_categories=decayed.categories,
            reason_codes=codes,
            active_max_severity=max_severity,
            severe_active=severe,
            corroborating_categories=decayed.corroborating,
        )

    # ── Internals ──────────────────────────────────────────────────────────

    def _active_signals(self, now: datetime) -> list[_Signal]:
        ttl = self._cfg.evidence_ttl_seconds
        active = [s for s in self._signals.values() if (now - s.last_seen).total_seconds() <= ttl]
        return sorted(active, key=lambda s: (s.category.value, s.event_type))

    def _freshness(self, at: datetime, now: datetime) -> float:
        age = max(0.0, (now - at).total_seconds())
        return math.pow(0.5, age / self._cfg.half_life_seconds)

    def _active_window(
        self, active: list[_Signal], now: datetime
    ) -> tuple[set[Severity], set[Classification], bool, bool]:
        """Severities, classifications and flags seen within the active window."""
        cutoff = now.timestamp() - self._cfg.active_window_seconds
        severities: set[Severity] = set()
        classes: set[Classification] = set()
        synthetic = severe = False
        for s in active:
            severities.update(v for v, at in s.last_by_severity.items() if at.timestamp() >= cutoff)
            classes.update(c for c, at in s.last_by_class.items() if at.timestamp() >= cutoff)
            synthetic = synthetic or (
                s.last_synthetic is not None and s.last_synthetic.timestamp() >= cutoff
            )
            severe = severe or (s.last_severe is not None and s.last_severe.timestamp() >= cutoff)
        return severities, classes, synthetic, severe

    def _terms(self, active: list[_Signal], now: datetime, *, decay: bool) -> _Terms:
        cfg = self._cfg
        if not active:
            return _Terms(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, (), ())

        summaries: list[SignalSummary] = []
        conf_terms: list[float] = []
        rep_terms: list[float] = []
        esc_terms: list[float] = []
        category_strength: dict[SignalCategory, float] = {}

        for s in active:
            if decay:
                fresh = self._freshness(s.top_level.detected_at, now)
                strength = cfg.level(s.top_level.severity) * fresh
                conf_fresh = self._freshness(s.top_conf.detected_at, now)
                conf_term = s.top_conf.confidence * cfg.level(s.top_conf.severity) * conf_fresh
            else:
                fresh = 1.0
                strength = s.max_level
                conf_term = s.max_conf_level
            strength = _clamp01(strength)
            rep_factor = 1.0 - math.exp(-(s.count - 1) / cfg.repetition_scale)
            rep_terms.append(rep_factor * strength)
            conf_terms.append(conf_term)
            esc_terms.append(strength if s.escalated else 0.0)
            category_strength[s.category] = max(category_strength.get(s.category, 0.0), strength)
            summaries.append(
                SignalSummary(
                    category=s.category,
                    event_type=s.event_type,
                    severity=s.top_level.severity,
                    classification=s.top_level.classification,
                    confidence=s.top_level.confidence,
                    peak_confidence=s.top_conf.confidence,
                    strength=round(strength, _PRECISION),
                    freshness=round(fresh, _PRECISION),
                    count=s.count,
                    escalated=s.escalated,
                    is_synthetic=s.top_level.is_synthetic,
                    event_id=s.top_level.event_id,
                )
            )

        strengths = sorted(category_strength.values())
        correlation_raw = sum(strengths) - strengths[-1]
        resource = max(
            (v for c, v in category_strength.items() if c in RESOURCE_CATEGORIES), default=0.0
        )
        security = max(
            (v for c, v in category_strength.items() if c in SECURITY_CATEGORIES), default=0.0
        )

        summaries.sort(key=lambda x: (-x.strength, -x.confidence, x.category.value, x.event_type))
        return _Terms(
            severity=round(cfg.weight_severity * max(x.strength for x in summaries), _PRECISION),
            confidence=round(cfg.weight_confidence * max(conf_terms), _PRECISION),
            repetition=round(cfg.weight_repetition * max(rep_terms), _PRECISION),
            escalation=round(cfg.weight_escalation * max(esc_terms), _PRECISION),
            correlation=round(
                min(cfg.weight_correlation, cfg.correlation_per_category * correlation_raw),
                _PRECISION,
            ),
            cross_domain=round(cfg.weight_cross_domain * min(resource, security), _PRECISION),
            signals=tuple(summaries[:MAX_REPORTED_SIGNALS]),
            categories=tuple(sorted(category_strength, key=lambda c: c.value)),
            corroborating=sum(
                1 for v in category_strength.values() if v >= cfg.corroboration_min_strength
            ),
        )

    @staticmethod
    def _reason_codes(
        active: list[_Signal],
        severities: set[Severity],
        classes: set[Classification],
        synthetic: bool,
        terms: _Terms,
        decay: float,
    ) -> tuple[ReasonCode, ...]:
        if not active:
            return (ReasonCode.NO_ACTIVE_EVIDENCE,)
        codes: list[ReasonCode] = []
        if Severity.CRITICAL in severities:
            codes.append(ReasonCode.CRITICAL_EVENT)
        if Severity.HIGH in severities:
            codes.append(ReasonCode.HIGH_SEVERITY_EVENT)
        if Classification.HIGH_CONFIDENCE in classes:
            codes.append(ReasonCode.HIGH_CONFIDENCE_EVIDENCE)
        if Classification.SUSPICIOUS in classes:
            codes.append(ReasonCode.SUSPICIOUS_ACTIVITY)
        if Classification.INFORMATIONAL in classes:
            codes.append(ReasonCode.INFORMATIONAL_ANOMALY)
        if synthetic:
            codes.append(ReasonCode.SYNTHETIC_SECURITY_EVENT)
        if terms.repetition > 0:
            codes.append(ReasonCode.REPEATED_ACTIVITY)
        if terms.escalation > 0:
            codes.append(ReasonCode.ESCALATING_ACTIVITY)
        if terms.correlation > 0:
            codes.append(ReasonCode.CROSS_SIGNAL_CORRELATION)
        if terms.cross_domain > 0:
            codes.append(ReasonCode.CROSS_DOMAIN_CORRELATION)
        if decay > 0 or not codes:
            # Evidence outside the active window is, by definition, ageing.
            codes.append(ReasonCode.EVIDENCE_DECAYING)
        return tuple(codes)
