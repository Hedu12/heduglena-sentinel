"""Unit tests for synthetic security events and DET-SYN-001."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from core.config import Settings
from detection.registry import build_synthetic_policies
from detection.rules.synthetic_rule import SyntheticPolicy, SyntheticSecurityEventRule
from detection.synthetic import MAX_LABEL_LENGTH, SyntheticEvent, sanitize_label
from models.enums import Classification, Severity, SyntheticEventType
from tests.detection_helpers import T0, syn

AUTH = SyntheticEventType.AUTH_FAILURE


def make_rule(cooldown: float = 60.0, **setting_overrides: object) -> SyntheticSecurityEventRule:
    settings = Settings(**setting_overrides)  # type: ignore[arg-type]
    return SyntheticSecurityEventRule(
        policies=build_synthetic_policies(settings), cooldown_seconds=cooldown
    )


def run(rule: SyntheticSecurityEventRule, events: list[SyntheticEvent]) -> list[list]:  # type: ignore[type-arg]
    return [rule.evaluate_synthetic(e) for e in events]


def burst(event_type: SyntheticEventType, n: int, gap: float = 1.0) -> list[SyntheticEvent]:
    return [syn(event_type, seconds=i * gap) for i in range(n)]


class TestSyntheticEventModel:
    def test_valid_event(self) -> None:
        e = SyntheticEvent(event_type=AUTH, subject="alice")
        assert e.event_type == AUTH
        assert e.subject == "alice"
        assert e.source == "demo"
        assert e.occurred_at.tzinfo is not None

    def test_defaults_to_utc_now(self) -> None:
        e = SyntheticEvent(event_type=AUTH)
        assert abs((datetime.now(UTC) - e.occurred_at).total_seconds()) < 5

    def test_unknown_event_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SyntheticEvent(event_type="drop_tables")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "telemetry_type",
        [
            SyntheticEventType.CPU_SPIKE,
            SyntheticEventType.MEMORY_PRESSURE,
            SyntheticEventType.NETWORK_SURGE,
            SyntheticEventType.DISK_IO_SPIKE,
        ],
    )
    def test_telemetry_style_types_are_not_security_events(
        self, telemetry_type: SyntheticEventType
    ) -> None:
        with pytest.raises(ValidationError):
            SyntheticEvent(event_type=telemetry_type)

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SyntheticEvent(event_type=AUTH, occurred_at=datetime(2025, 1, 1))

    def test_non_utc_timestamp_normalised_to_utc(self) -> None:
        plus2 = datetime(2025, 1, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
        e = SyntheticEvent(event_type=AUTH, occurred_at=plus2)
        assert e.occurred_at.utcoffset() == timedelta(0)
        assert e.occurred_at == datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SyntheticEvent(event_type=AUTH, command="rm -rf /")  # type: ignore[call-arg]

    def test_oversized_label_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SyntheticEvent(event_type=AUTH, subject="x" * 257)

    def test_model_is_immutable(self) -> None:
        e = SyntheticEvent(event_type=AUTH)
        with pytest.raises(ValidationError):
            e.subject = "changed"  # type: ignore[misc]


class TestSanitizeLabel:
    def test_plain_text_unchanged(self) -> None:
        assert sanitize_label("alice") == "alice"

    def test_control_characters_removed(self) -> None:
        assert sanitize_label("a\x00b\x07c") == "a b c"

    def test_newlines_cannot_forge_log_lines(self) -> None:
        label = sanitize_label("alice\nINFO forged log entry\r\n")
        assert label is not None
        assert "\n" not in label
        assert "\r" not in label

    def test_ansi_escape_neutralised(self) -> None:
        label = sanitize_label("\x1b[31mred\x1b[0m")
        assert label is not None
        assert "\x1b" not in label

    def test_unicode_line_separators_removed(self) -> None:
        label = sanitize_label("a\u2028b\u2029c")
        assert label == "a b c"

    def test_zero_width_and_bidi_controls_removed(self) -> None:
        label = sanitize_label("pay\u200bload\u202e")
        assert label is not None
        assert "\u200b" not in label
        assert "\u202e" not in label

    def test_whitespace_collapsed(self) -> None:
        assert sanitize_label("  a   b \t c  ") == "a b c"

    def test_truncated_to_max(self) -> None:
        assert len(sanitize_label("x" * 200) or "") == MAX_LABEL_LENGTH

    def test_empty_or_unprintable_becomes_none(self) -> None:
        assert sanitize_label("") is None
        assert sanitize_label("   \n\t ") is None
        assert sanitize_label("\x00\x01") is None

    def test_shell_and_sql_text_is_kept_as_inert_data(self) -> None:
        assert sanitize_label("'; DROP TABLE x;--") == "'; DROP TABLE x;--"

    def test_model_applies_sanitisation(self) -> None:
        e = SyntheticEvent(event_type=AUTH, subject="bob\nadmin", scenario_id="\x1b[1mdemo")
        assert e.subject == "bob admin"
        assert e.scenario_id is not None and "\x1b" not in e.scenario_id


class TestAuthFailureBurst:
    """Defaults: threshold 5 failures / 60s, escalation at 10."""

    def test_below_threshold_is_normal(self) -> None:
        out = run(make_rule(), burst(AUTH, 4))
        assert all(not r for r in out)

    def test_threshold_is_suspicious_not_high_confidence(self) -> None:
        out = run(make_rule(), burst(AUTH, 5))
        result = out[4][0]
        assert result.classification == Classification.SUSPICIOUS
        assert result.severity == Severity.HIGH
        assert result.event_type == "auth_failure_burst"
        assert result.is_synthetic is True
        assert result.telemetry_sample_id is None
        assert out[:4] == [[], [], [], []]

    def test_repeated_activity_escalates_to_high_confidence_critical(self) -> None:
        out = run(make_rule(), burst(AUTH, 10))
        first, escalated = out[4][0], out[9][0]
        assert (first.classification, first.severity) == (Classification.SUSPICIOUS, Severity.HIGH)
        assert (escalated.classification, escalated.severity) == (
            Classification.HIGH_CONFIDENCE,
            Severity.CRITICAL,
        )
        assert escalated.confidence > first.confidence

    def test_escalation_bypasses_cooldown_but_plain_repeats_do_not(self) -> None:
        out = run(make_rule(), burst(AUTH, 15))
        fired = [i for i, r in enumerate(out) if r]
        # Fires at 5th (base) and 10th (escalation); 6th-9th and 11th-15th suppressed.
        assert fired == [4, 9]

    def test_fires_again_after_cooldown_expires(self) -> None:
        # Window 60s keeps all 15 events; 20s cooldown allows a re-report.
        out = run(make_rule(cooldown=5.0), burst(AUTH, 15, gap=1.0))
        assert [i for i, r in enumerate(out) if r] == [4, 9, 14]

    def test_events_outside_window_do_not_count(self) -> None:
        # 4 events, then a 2-minute gap, then 4 more: never 5 inside 60s.
        events = burst(AUTH, 4) + [syn(AUTH, seconds=200 + i) for i in range(4)]
        assert all(not r for r in run(make_rule(), events))

    def test_window_boundary_is_inclusive(self) -> None:
        # 5 events spanning exactly 60s still count together.
        events = [syn(AUTH, seconds=s) for s in (0, 15, 30, 45, 60)]
        out = run(make_rule(), events)
        assert out[4]

    def test_out_of_order_events_are_handled(self) -> None:
        events = [syn(AUTH, seconds=s) for s in (4, 2, 3, 0, 1)]
        out = run(make_rule(), events)
        assert out[4]
        assert out[4][0].evidence["observed_count"] == 5

    def test_evidence_is_structured(self) -> None:
        out = run(make_rule(), [syn(AUTH, seconds=i, subject=f"user{i % 2}") for i in range(5)])
        e = out[4][0].evidence
        assert e["event_type"] == "auth_failure"
        assert e["observed_count"] == 5
        assert e["threshold"] == 5
        assert e["escalation_threshold"] == 10
        assert e["window_seconds"] == 60
        assert e["distinct_subjects"] == 2
        assert e["latest_subject"] == "user0"
        assert e["escalated"] is False
        assert e["synthetic"] is True
        assert e["first_event_at"] == T0.isoformat()

    def test_metric_fields(self) -> None:
        result = run(make_rule(), burst(AUTH, 5))[4][0]
        assert result.metric_key == "synthetic:auth_failure"
        assert result.metric_value == 5.0
        assert result.threshold_value == 5.0

    def test_confidence_rises_between_threshold_and_escalation(self) -> None:
        rule = make_rule(cooldown=0.0)
        out = run(rule, burst(AUTH, 9))
        confidences = [r[0].confidence for r in out if r]
        assert confidences[0] == pytest.approx(0.55)
        assert confidences == sorted(confidences)
        assert confidences[-1] < 0.9

    def test_thresholds_come_from_settings(self) -> None:
        rule = make_rule(rule_auth_failure_count=2)
        assert [bool(r) for r in run(rule, burst(AUTH, 2))] == [False, True]

    def test_memory_is_bounded(self) -> None:
        rule = make_rule(cooldown=0.0)
        run(rule, burst(AUTH, 5000, gap=0.001))
        assert len(rule._windows[AUTH]) <= 10  # type: ignore[attr-defined]

    def test_count_is_flagged_as_lower_bound_when_capped(self) -> None:
        out = run(make_rule(cooldown=0.0), burst(AUTH, 30, gap=0.1))
        assert out[-1][0].evidence["observed_count_is_lower_bound"] is True

    def test_deterministic(self) -> None:
        events = burst(AUTH, 12)
        assert run(make_rule(), events) == run(make_rule(), events)

    def test_reset_clears_state(self) -> None:
        rule = make_rule()
        run(rule, burst(AUTH, 4))
        rule.reset()
        assert not run(rule, [syn(AUTH, seconds=10)])[0]


class TestOtherSyntheticTypes:
    def test_suspicious_process_is_immediate_critical_high_confidence(self) -> None:
        result = make_rule().evaluate_synthetic(
            syn(SyntheticEventType.SUSPICIOUS_PROCESS, subject="evil.exe")
        )[0]
        assert result.event_type == "suspicious_process"
        assert result.severity == Severity.CRITICAL
        assert result.classification == Classification.HIGH_CONFIDENCE
        assert result.confidence == pytest.approx(0.95)
        assert result.evidence["latest_subject"] == "evil.exe"

    def test_suspicious_process_repeats_are_debounced(self) -> None:
        events = [syn(SyntheticEventType.SUSPICIOUS_PROCESS, seconds=i) for i in range(5)]
        out = run(make_rule(), events)
        assert [i for i, r in enumerate(out) if r] == [0]

    def test_access_denied_severity_is_medium_then_high(self) -> None:
        out = run(make_rule(), burst(SyntheticEventType.ACCESS_DENIED, 10))
        assert out[4][0].severity == Severity.MEDIUM
        assert out[9][0].severity == Severity.HIGH
        assert out[9][0].classification == Classification.HIGH_CONFIDENCE

    def test_connection_burst_thresholds(self) -> None:
        out = run(make_rule(), burst(SyntheticEventType.CONNECTION_BURST, 20, gap=0.5))
        assert [i for i, r in enumerate(out) if r] == [19]
        assert out[19][0].event_type == "connection_burst"

    def test_event_types_are_counted_separately(self) -> None:
        events = [
            syn(AUTH, seconds=0),
            syn(SyntheticEventType.ACCESS_DENIED, seconds=1),
            syn(AUTH, seconds=2),
            syn(SyntheticEventType.ACCESS_DENIED, seconds=3),
        ]
        assert all(not r for r in run(make_rule(rule_auth_failure_count=3), events))

    def test_each_type_has_its_own_cooldown(self) -> None:
        rule = make_rule(rule_auth_failure_count=1, det_access_denied_count=1)
        assert rule.evaluate_synthetic(syn(AUTH, seconds=0))
        assert rule.evaluate_synthetic(syn(SyntheticEventType.ACCESS_DENIED, seconds=1))

    def test_unhandled_type_returns_nothing(self) -> None:
        rule = SyntheticSecurityEventRule(policies={}, cooldown_seconds=60)
        assert rule.evaluate_synthetic(syn(AUTH)) == []

    def test_telemetry_is_ignored(self) -> None:
        from tests.detection_helpers import obs

        assert make_rule().evaluate_telemetry(obs(0, cpu_percent=99.0)) == []


class TestSyntheticPolicyValidation:
    def _policy(self, **kw: object) -> SyntheticPolicy:
        base: dict[str, object] = {
            "detection_type": "t",
            "threshold": 3,
            "window_seconds": 10.0,
            "severity": Severity.LOW,
            "classification": Classification.SUSPICIOUS,
        }
        base.update(kw)
        return SyntheticPolicy(**base)  # type: ignore[arg-type]

    def test_valid(self) -> None:
        assert self._policy().capacity == 3

    def test_capacity_is_highest_threshold(self) -> None:
        p = self._policy(
            escalation_threshold=6,
            escalated_severity=Severity.HIGH,
            escalated_classification=Classification.HIGH_CONFIDENCE,
        )
        assert p.capacity == 6

    @pytest.mark.parametrize(
        "kw",
        [
            {"threshold": 0},
            {"window_seconds": 0},
            {"escalation_threshold": 3},
            {"escalation_threshold": 5},  # missing escalated severity/classification
        ],
    )
    def test_invalid_rejected(self, kw: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            self._policy(**kw)
