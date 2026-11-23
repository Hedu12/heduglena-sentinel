"""
Immutable scoring and state-machine configuration.

Built once from the validated Settings (the single configuration source,
P-02). The scorer and state machine receive these objects and never read
Settings or the environment themselves, so tests can construct any
configuration directly.

Every weight, threshold, window and bound that influences a decision lives
here. These values are policy: changing them changes how Sentinel behaves, so
they are reviewed by a human (see the Phase 4 review checklist).
"""

from __future__ import annotations

from dataclasses import dataclass

from core.config import Settings
from models.enums import DefenseState, Severity

# Fixed escalation order. Index = rank.
STATE_ORDER: tuple[DefenseState, ...] = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)


def state_rank(state: DefenseState) -> int:
    """0 (RELAXED) to 3 (AGGRESSIVE)."""
    return STATE_ORDER.index(state)


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    """Parameters of the threat-score formula. See threat.scorer for the formula."""

    weight_severity: float = 0.45
    weight_confidence: float = 0.15
    weight_repetition: float = 0.10
    weight_escalation: float = 0.10
    weight_correlation: float = 0.20
    weight_cross_domain: float = 0.10
    correlation_per_category: float = 0.15
    level_info: float = 0.10
    level_low: float = 0.20
    level_medium: float = 0.40
    level_high: float = 0.70
    level_critical: float = 1.00
    repetition_scale: float = 3.0
    repetition_cap: int = 100
    half_life_seconds: float = 60.0
    evidence_ttl_seconds: float = 300.0
    active_window_seconds: float = 60.0
    max_signals: int = 64
    dedup_window: int = 1024
    default_confidence: float = 0.5
    # A signal category counts as corroborating once its strength reaches this.
    corroboration_min_strength: float = 0.15

    def __post_init__(self) -> None:
        if not 0.0 < self.corroboration_min_strength <= 1.0:
            raise ValueError("corroboration_min_strength must be within (0, 1]")
        unit = (
            "weight_severity",
            "weight_confidence",
            "weight_repetition",
            "weight_escalation",
            "weight_correlation",
            "weight_cross_domain",
            "correlation_per_category",
            "level_info",
            "level_low",
            "level_medium",
            "level_high",
            "level_critical",
            "default_confidence",
        )
        for name in unit:
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        levels = (
            self.level_info,
            self.level_low,
            self.level_medium,
            self.level_high,
            self.level_critical,
        )
        if list(levels) != sorted(levels):
            raise ValueError("severity levels must be non-decreasing")
        for name in ("repetition_scale", "half_life_seconds", "evidence_ttl_seconds"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")
        if self.active_window_seconds <= 0:
            raise ValueError("active_window_seconds must be > 0")
        if self.repetition_cap < 2 or self.max_signals < 1 or self.dedup_window < 1:
            raise ValueError("repetition_cap >= 2, max_signals >= 1, dedup_window >= 1 required")

    def level(self, severity: Severity) -> float:
        """Risk level in [0, 1] for a severity."""
        return {
            Severity.INFO: self.level_info,
            Severity.LOW: self.level_low,
            Severity.MEDIUM: self.level_medium,
            Severity.HIGH: self.level_high,
            Severity.CRITICAL: self.level_critical,
        }[severity]


@dataclass(frozen=True, slots=True)
class StateConfig:
    """Thresholds and timers of the defense state machine."""

    threshold_alert: float = 0.25
    threshold_defensive: float = 0.55
    threshold_aggressive: float = 0.80
    hysteresis_margin: float = 0.05
    bypass_margin: float = 0.10
    dwell_seconds: float = 10.0
    cooldown_seconds: float = 30.0
    floor_critical: DefenseState = DefenseState.DEFENSIVE
    floor_high: DefenseState = DefenseState.ALERT
    # Independent signal categories required for the bypass into AGGRESSIVE.
    aggressive_min_categories: int = 2

    def __post_init__(self) -> None:
        if self.aggressive_min_categories < 1:
            raise ValueError("aggressive_min_categories must be >= 1")
        for floor in (self.floor_critical, self.floor_high):
            if floor is DefenseState.AGGRESSIVE:
                # AGGRESSIVE is reachable only through the score, never a floor.
                raise ValueError("a state floor must not be AGGRESSIVE")
        entries = (self.threshold_alert, self.threshold_defensive, self.threshold_aggressive)
        if not (0.0 < entries[0] < entries[1] < entries[2] <= 1.0):
            raise ValueError("thresholds must satisfy 0 < alert < defensive < aggressive <= 1")
        gaps = (entries[0], entries[1] - entries[0], entries[2] - entries[1])
        if not 0.0 <= self.hysteresis_margin < min(gaps):
            raise ValueError("hysteresis_margin must be >= 0 and below every threshold gap")
        if self.bypass_margin < 0 or self.dwell_seconds < 0 or self.cooldown_seconds < 0:
            raise ValueError("bypass_margin, dwell_seconds and cooldown_seconds must be >= 0")
        if state_rank(self.floor_critical) < state_rank(self.floor_high):
            raise ValueError("floor_critical must not be below floor_high")

    def entry(self, state: DefenseState) -> float:
        """Score at or above which `state` is entered (RELAXED has no entry)."""
        return {
            DefenseState.RELAXED: 0.0,
            DefenseState.ALERT: self.threshold_alert,
            DefenseState.DEFENSIVE: self.threshold_defensive,
            DefenseState.AGGRESSIVE: self.threshold_aggressive,
        }[state]

    def exit(self, state: DefenseState) -> float:
        """Score below which `state` may be left (entry minus the hysteresis margin)."""
        return max(0.0, self.entry(state) - self.hysteresis_margin)

    def state_for_score(self, score: float) -> DefenseState:
        """Highest state whose entry threshold the score meets (no timers applied)."""
        for state in reversed(STATE_ORDER):
            if score >= self.entry(state):
                return state
        return DefenseState.RELAXED


@dataclass(frozen=True, slots=True)
class ThreatConfig:
    """Everything the decision layer needs."""

    scoring: ScoringConfig
    state: StateConfig
    persist_min_delta: float = 0.01
    incident_reopen_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.incident_reopen_seconds < 0:
            raise ValueError("incident_reopen_seconds must be >= 0")

    @classmethod
    def from_settings(cls, settings: Settings) -> ThreatConfig:
        s = settings
        return cls(
            scoring=ScoringConfig(
                weight_severity=s.threat_weight_severity,
                weight_confidence=s.threat_weight_confidence,
                weight_repetition=s.threat_weight_repetition,
                weight_escalation=s.threat_weight_escalation,
                weight_correlation=s.threat_weight_correlation,
                weight_cross_domain=s.threat_weight_cross_domain,
                correlation_per_category=s.threat_correlation_per_category,
                level_info=s.threat_level_info,
                level_low=s.threat_level_low,
                level_medium=s.threat_level_medium,
                level_high=s.threat_level_high,
                level_critical=s.threat_level_critical,
                repetition_scale=s.threat_repetition_scale,
                repetition_cap=s.threat_repetition_cap,
                half_life_seconds=s.threat_half_life_seconds,
                evidence_ttl_seconds=s.threat_evidence_ttl_seconds,
                active_window_seconds=s.threat_active_window_seconds,
                max_signals=s.threat_max_signals,
                dedup_window=s.threat_dedup_window,
                default_confidence=s.threat_default_confidence,
                corroboration_min_strength=s.threat_corroboration_min_strength,
            ),
            state=StateConfig(
                threshold_alert=s.threshold_relaxed_alert,
                threshold_defensive=s.threshold_alert_defensive,
                threshold_aggressive=s.threshold_defensive_aggressive,
                hysteresis_margin=s.threat_hysteresis_margin,
                bypass_margin=s.threat_escalation_bypass_margin,
                dwell_seconds=s.dwell_seconds,
                cooldown_seconds=s.cooldown_seconds,
                floor_critical=s.threat_floor_critical,
                floor_high=s.threat_floor_high,
                aggressive_min_categories=s.threat_aggressive_min_categories,
            ),
            persist_min_delta=s.threat_score_persist_min_delta,
            incident_reopen_seconds=s.threat_incident_reopen_seconds,
        )
