"""Unit tests for threat configuration objects and their Settings validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.config import Settings
from models.enums import DefenseState, Severity
from threat.config import STATE_ORDER, ScoringConfig, StateConfig, ThreatConfig, state_rank


class TestDefaultsMatchSettings:
    """The dataclass defaults and Settings defaults are one policy; they must not drift."""

    def test_scoring_defaults_equal_settings_defaults(self) -> None:
        assert ThreatConfig.from_settings(Settings()).scoring == ScoringConfig()

    def test_state_defaults_equal_settings_defaults(self) -> None:
        assert ThreatConfig.from_settings(Settings()).state == StateConfig()

    def test_thresholds_follow_the_specification(self) -> None:
        # sentinel-spec section 4 F-04 / section 9.3.
        state = StateConfig()
        assert (state.threshold_alert, state.threshold_defensive, state.threshold_aggressive) == (
            0.25,
            0.55,
            0.80,
        )
        assert (state.dwell_seconds, state.cooldown_seconds) == (10.0, 30.0)

    def test_settings_overrides_flow_into_config(self) -> None:
        cfg = ThreatConfig.from_settings(
            Settings(dwell_seconds=3, cooldown_seconds=7, threat_weight_severity=0.3)
        )
        assert cfg.state.dwell_seconds == 3
        assert cfg.state.cooldown_seconds == 7
        assert cfg.scoring.weight_severity == 0.3


class TestStateConfigDerivedValues:
    def test_state_order_is_the_four_states_in_escalation_order(self) -> None:
        assert STATE_ORDER == (
            DefenseState.RELAXED,
            DefenseState.ALERT,
            DefenseState.DEFENSIVE,
            DefenseState.AGGRESSIVE,
        )
        assert [state_rank(s) for s in STATE_ORDER] == [0, 1, 2, 3]

    def test_exit_is_entry_minus_margin(self) -> None:
        cfg = StateConfig()
        assert cfg.exit(DefenseState.DEFENSIVE) == pytest.approx(0.50)
        assert cfg.exit(DefenseState.ALERT) == pytest.approx(0.20)
        assert cfg.exit(DefenseState.AGGRESSIVE) == pytest.approx(0.75)

    def test_relaxed_has_no_entry_and_never_negative_exit(self) -> None:
        cfg = StateConfig()
        assert cfg.entry(DefenseState.RELAXED) == 0.0
        assert cfg.exit(DefenseState.RELAXED) == 0.0

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, DefenseState.RELAXED),
            (0.2499, DefenseState.RELAXED),
            (0.25, DefenseState.ALERT),
            (0.5499, DefenseState.ALERT),
            (0.55, DefenseState.DEFENSIVE),
            (0.7999, DefenseState.DEFENSIVE),
            (0.80, DefenseState.AGGRESSIVE),
            (1.0, DefenseState.AGGRESSIVE),
        ],
    )
    def test_state_for_score_boundaries(self, score: float, expected: DefenseState) -> None:
        assert StateConfig().state_for_score(score) is expected


class TestScoringConfigValidation:
    def test_level_lookup(self) -> None:
        cfg = ScoringConfig()
        assert cfg.level(Severity.INFO) < cfg.level(Severity.LOW) < cfg.level(Severity.MEDIUM)
        assert cfg.level(Severity.MEDIUM) < cfg.level(Severity.HIGH) < cfg.level(Severity.CRITICAL)
        assert cfg.level(Severity.CRITICAL) == 1.0

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"weight_severity": -0.1},
            {"weight_confidence": 1.1},
            {"correlation_per_category": 2.0},
            {"default_confidence": -1.0},
            {"level_info": 0.9},  # info above low breaks non-decreasing order
            {"level_critical": 0.1},
            {"repetition_scale": 0},
            {"half_life_seconds": 0},
            {"evidence_ttl_seconds": -5},
            {"active_window_seconds": 0},
            {"repetition_cap": 1},
            {"max_signals": 0},
            {"dedup_window": 0},
            {"corroboration_min_strength": 0.0},
            {"corroboration_min_strength": 1.1},
        ],
    )
    def test_invalid_scoring_config_rejected(self, kwargs: dict[str, float]) -> None:
        with pytest.raises(ValueError):
            ScoringConfig(**kwargs)  # type: ignore[arg-type]

    def test_negative_incident_reopen_window_rejected(self) -> None:
        with pytest.raises(ValueError):
            ThreatConfig(ScoringConfig(), StateConfig(), incident_reopen_seconds=-1)


class TestStateConfigValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"threshold_alert": 0.6},  # not below defensive
            {"threshold_defensive": 0.25},  # equal to alert
            {"threshold_aggressive": 1.5},
            {"threshold_alert": 0.0},
            {"hysteresis_margin": 0.25},  # equals the first gap
            {"hysteresis_margin": -0.01},
            {"bypass_margin": -0.1},
            {"dwell_seconds": -1},
            {"cooldown_seconds": -1},
            {"floor_critical": DefenseState.ALERT, "floor_high": DefenseState.DEFENSIVE},
            {"floor_critical": DefenseState.AGGRESSIVE},  # a floor may never be AGGRESSIVE
            {"floor_high": DefenseState.AGGRESSIVE, "floor_critical": DefenseState.AGGRESSIVE},
            {"aggressive_min_categories": 0},
        ],
    )
    def test_invalid_state_config_rejected(self, kwargs: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            StateConfig(**kwargs)  # type: ignore[arg-type]

    def test_zero_margin_and_timers_are_allowed(self) -> None:
        cfg = StateConfig(hysteresis_margin=0.0, dwell_seconds=0, cooldown_seconds=0)
        assert cfg.exit(DefenseState.DEFENSIVE) == cfg.entry(DefenseState.DEFENSIVE)


class TestSettingsValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"threat_level_high": 0.1},  # below medium
            {"threshold_alert_defensive": 0.2},  # below alert threshold
            {"threshold_defensive_aggressive": 0.5},
            {"threat_hysteresis_margin": 0.3},  # larger than the gaps
            {"threat_floor_critical": "ALERT", "threat_floor_high": "DEFENSIVE"},
            {"threat_weight_severity": 1.5},
            {"threat_half_life_seconds": 0},
            {"threat_floor_critical": "PANIC"},
        ],
    )
    def test_invalid_settings_rejected(self, kwargs: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            Settings(**kwargs)  # type: ignore[arg-type]

    def test_floor_strings_become_defense_states(self) -> None:
        s = Settings(threat_floor_critical="DEFENSIVE", threat_floor_high="DEFENSIVE")
        assert s.threat_floor_critical is DefenseState.DEFENSIVE
        assert s.threat_floor_high is DefenseState.DEFENSIVE

    @pytest.mark.parametrize("field", ["threat_floor_critical", "threat_floor_high"])
    def test_a_floor_can_never_be_aggressive(self, field: str) -> None:
        # AGGRESSIVE is reachable only through the score, never through a floor.
        with pytest.raises(ValidationError):
            Settings(**{field: "AGGRESSIVE"})  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"threat_aggressive_min_categories": 0},
            {"threat_corroboration_min_strength": 0.0},
            {"threat_corroboration_min_strength": 1.5},
            {"threat_incident_reopen_seconds": -1},
        ],
    )
    def test_invalid_bypass_and_situation_settings_rejected(self, kwargs: dict[str, float]) -> None:
        with pytest.raises(ValidationError):
            Settings(**kwargs)  # type: ignore[arg-type]

    def test_bypass_and_situation_settings_flow_into_config(self) -> None:
        cfg = ThreatConfig.from_settings(
            Settings(
                threat_aggressive_min_categories=3,
                threat_corroboration_min_strength=0.3,
                threat_incident_reopen_seconds=42,
            )
        )
        assert cfg.state.aggressive_min_categories == 3
        assert cfg.scoring.corroboration_min_strength == 0.3
        assert cfg.incident_reopen_seconds == 42
