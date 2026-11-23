"""
Unit tests for ORM model construction.

Verifies that every model can be instantiated with valid data, that
default values are correct, and that field-level constraints are
enforced. These tests do NOT use the database — they test the Python
objects directly.
"""

from __future__ import annotations

from datetime import UTC, datetime

from database.base import utc_now
from database.models import (
    AIExplanationRecord,
    Baseline,
    DefenseStateChange,
    DetectionEvent,
    Incident,
    ResponseAction,
    TelemetrySample,
    ThreatScore,
)


def _now() -> datetime:
    return datetime.now(UTC)


class TestTelemetrySample:
    def test_create_full(self) -> None:
        s = TelemetrySample(
            collected_at=_now(),
            cpu_percent=45.2,
            memory_percent=62.1,
            disk_read_rate=1024.0,
            disk_write_rate=512.0,
            net_bytes_sent=8192.0,
            net_bytes_recv=4096.0,
            process_count=120,
            raw_json='{"cpu": 45.2}',
        )
        assert s.cpu_percent == 45.2
        assert s.process_count == 120

    def test_nullable_metrics_allowed(self) -> None:
        """AC-F01-4: collection continues if one metric fails (nulls allowed)."""
        s = TelemetrySample(collected_at=_now(), cpu_percent=None)
        assert s.cpu_percent is None

    def test_all_metrics_nullable(self) -> None:
        """Every metric field is independently nullable."""
        s = TelemetrySample(
            collected_at=_now(),
            cpu_percent=None,
            memory_percent=None,
            disk_read_rate=None,
            disk_write_rate=None,
            net_bytes_sent=None,
            net_bytes_recv=None,
            process_count=None,
        )
        assert s.memory_percent is None

    def test_collected_at_timezone_aware(self) -> None:
        ts = _now()
        s = TelemetrySample(collected_at=ts)
        assert s.collected_at.tzinfo is not None


class TestDetectionEvent:
    def test_create_real_event(self) -> None:
        e = DetectionEvent(
            detected_at=_now(),
            rule_id="cpu-spike",
            rule_name="CPU Spike",
            severity="HIGH",
            metric_key="cpu_percent",
            metric_value=91.5,
            threshold_value=85.0,
            is_synthetic=False,
        )
        assert e.rule_id == "cpu-spike"
        assert e.severity == "HIGH"
        assert e.is_synthetic is False

    def test_create_synthetic_event(self) -> None:
        e = DetectionEvent(
            detected_at=_now(),
            rule_id="auth-failure-burst",
            rule_name="Auth Failure Burst",
            severity="HIGH",
            metric_key="synthetic:auth_failure",
            metric_value=6.0,
            threshold_value=5.0,
            is_synthetic=True,
            event_data='{"source": "demo"}',
        )
        assert e.is_synthetic is True

    def test_default_is_synthetic_false(self) -> None:
        """is_synthetic must default to False — real telemetry is the base case."""
        e = DetectionEvent(
            detected_at=_now(),
            rule_id="cpu-spike",
            rule_name="CPU Spike",
            severity="MEDIUM",
            metric_key="cpu_percent",
        )
        assert e.is_synthetic is False

    def test_severity_values(self) -> None:
        for severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            e = DetectionEvent(
                detected_at=_now(),
                rule_id="test",
                rule_name="Test",
                severity=severity,
                metric_key="cpu_percent",
            )
            assert e.severity == severity


class TestIncident:
    def test_create_incident(self) -> None:
        inc = Incident(
            incident_id="inc-001",
            created_at=_now(),
            status="open",
            defense_state="ALERT",
            threat_score_at_creation=0.42,
            event_ids="[1, 2, 3]",
            summary="CPU spike detected.",
        )
        assert inc.incident_id == "inc-001"
        assert inc.status == "open"

    def test_default_status_open(self) -> None:
        inc = Incident(
            incident_id="inc-002",
            created_at=_now(),
            defense_state="RELAXED",
            threat_score_at_creation=0.1,
        )
        assert inc.status == "open"

    def test_threat_score_stored_as_float(self) -> None:
        inc = Incident(
            incident_id="inc-003",
            created_at=_now(),
            defense_state="DEFENSIVE",
            threat_score_at_creation=0.75,
        )
        assert isinstance(inc.threat_score_at_creation, float)


class TestThreatScore:
    def test_create_score(self) -> None:
        ts = ThreatScore(
            calculated_at=_now(),
            score=0.65,
            contributing_events="[1, 2]",
        )
        assert ts.score == 0.65

    def test_score_zero(self) -> None:
        ts = ThreatScore(calculated_at=_now(), score=0.0)
        assert ts.score == 0.0

    def test_score_one(self) -> None:
        ts = ThreatScore(calculated_at=_now(), score=1.0)
        assert ts.score == 1.0

    def test_contributing_events_optional(self) -> None:
        ts = ThreatScore(calculated_at=_now(), score=0.5)
        assert ts.contributing_events is None


class TestDefenseStateChange:
    def test_create_ascending_transition(self) -> None:
        c = DefenseStateChange(
            changed_at=_now(),
            from_state="RELAXED",
            to_state="ALERT",
            trigger_score=0.30,
            trigger_event_ids="[5]",
        )
        assert c.from_state == "RELAXED"
        assert c.to_state == "ALERT"

    def test_all_state_values_accepted(self) -> None:
        states = ["RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE"]
        for s in states:
            c = DefenseStateChange(
                changed_at=_now(),
                from_state=states[0],
                to_state=s,
                trigger_score=0.5,
            )
            assert c.to_state == s


class TestResponseAction:
    def test_default_is_simulated_true(self) -> None:
        """P-05: is_simulated must default to True. Never default to live."""
        a = ResponseAction(
            executed_at=_now(),
            action_type="SIMULATE_IP_BLOCK",
            defense_state="DEFENSIVE",
            triggering_event_id=None,
            dry_run_description="Would have blocked 192.168.1.100 on port 22.",
        )
        assert a.is_simulated is True

    def test_simulated_action(self) -> None:
        a = ResponseAction(
            executed_at=_now(),
            action_type="SIMULATE_IP_BLOCK",
            is_simulated=True,
            defense_state="DEFENSIVE",
            triggering_event_id=None,
            parameters='{"ip": "10.0.0.1"}',
            result="logged",
            dry_run_description="Would have blocked 10.0.0.1 via iptables.",
        )
        assert a.is_simulated is True
        assert "10.0.0.1" in a.dry_run_description

    def test_dry_run_description_always_required(self) -> None:
        """Every action must document what it would have done live (spec §11.3)."""
        a = ResponseAction(
            executed_at=_now(),
            action_type="GENERATE_ALERT",
            is_simulated=True,
            defense_state="RELAXED",
            triggering_event_id=None,
            dry_run_description="Alert written to dashboard and log.",
        )
        assert len(a.dry_run_description) > 0

    def test_triggering_event_id_optional(self) -> None:
        """State-transition-triggered actions have no specific triggering event."""
        a = ResponseAction(
            executed_at=_now(),
            action_type="INCREASE_MONITORING",
            is_simulated=False,
            defense_state="ALERT",
            triggering_event_id=None,
            dry_run_description="Would have halved poll interval.",
        )
        assert a.triggering_event_id is None


class TestAIExplanationRecord:
    def test_create_record(self) -> None:
        r = AIExplanationRecord(
            generated_at=_now(),
            incident_id="inc-010",
            provider="null",
            model="none",
            explanation="CPU spike detected. Score: 0.72.",
            recommendations='["Review process activity"]',
            raw_response="CPU spike detected. Score: 0.72.",
        )
        assert r.provider == "null"
        assert r.incident_id == "inc-010"

    def test_tokens_optional(self) -> None:
        """NullAdapter does not return token counts."""
        r = AIExplanationRecord(
            generated_at=_now(),
            incident_id="inc-011",
            provider="null",
            explanation="Fallback explanation.",
        )
        assert r.prompt_tokens is None
        assert r.response_tokens is None

    def test_raw_response_stored_separately(self) -> None:
        """Sanitised and raw responses can differ (AS-07)."""
        r = AIExplanationRecord(
            generated_at=_now(),
            incident_id="inc-012",
            provider="ollama",
            explanation="Sanitised explanation.",
            raw_response="Unsafe explanation with rm -rf /.",
        )
        assert r.explanation != r.raw_response


class TestBaseline:
    def test_create_baseline(self) -> None:
        b = Baseline(
            metric_key="cpu_percent",
            sample_count=60,
            mean=42.3,
            std_dev=8.1,
            updated_at=_now(),
        )
        assert b.metric_key == "cpu_percent"
        assert b.sample_count == 60

    def test_default_mean_std(self) -> None:
        b = Baseline(
            metric_key="memory_percent",
            sample_count=0,
            updated_at=_now(),
        )
        assert b.mean == 0.0
        assert b.std_dev == 0.0


class TestUtcNow:
    def test_utc_now_is_aware(self) -> None:
        t = utc_now()
        assert t.tzinfo is not None
        assert t.tzinfo.utcoffset(t).total_seconds() == 0  # type: ignore[union-attr]
