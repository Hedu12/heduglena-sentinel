"""Unit tests for ThreatScorer: boundaries, severity, confidence, repetition,
correlation, decay, escalation, deduplication, memory bounds and determinism."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from database.models import DetectionEvent
from models.enums import Classification, Severity
from tests.threat_helpers import (
    T0,
    C,
    S,
    at,
    auth_critical,
    auth_suspicious,
    connection_suspicious,
    cpu,
    item,
    malicious_process,
    net,
    proc,
    score_of,
    scorer,
)
from threat.config import ScoringConfig
from threat.evidence import EvidenceItem, SignalCategory, category_for
from threat.reasons import ReasonCode
from threat.scorer import MAX_REPORTED_SIGNALS, ThreatScorer

HALF_LIFE = ScoringConfig().half_life_seconds


class TestBoundaries:
    def test_no_evidence_scores_zero_with_reason(self) -> None:
        b = scorer().score(T0)
        assert b.final_score == 0.0
        assert b.signal_count == 0
        assert b.reason_codes == (ReasonCode.NO_ACTIVE_EVIDENCE,)
        assert b.decay == 0.0

    def test_score_is_exactly_zero_once_evidence_expires(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        assert s.score(at(10)).final_score > 0
        assert s.score(at(ScoringConfig().evidence_ttl_seconds + 1)).final_score == 0.0

    def test_score_can_reach_exactly_one(self) -> None:
        # Saturating evidence: critical, certain, escalated, repeated, correlated.
        s = scorer()
        for i in range(30):
            s.observe(item("auth_failure_burst", S.HIGH, C.SUSPICIOUS, 1.0, i, synthetic=True))
        s.observe(
            item("auth_failure_burst", S.CRITICAL, C.HIGH_CONFIDENCE, 1.0, 30, synthetic=True)
        )
        for build in (cpu, net, proc):
            s.observe(item(build().event_type, S.CRITICAL, C.HIGH_CONFIDENCE, 1.0, 30))
        b = s.score(at(30))
        assert b.raw_total >= 1.0
        assert b.final_score == 1.0

    def test_score_never_leaves_unit_interval_even_with_extreme_weights(self) -> None:
        cfg = ScoringConfig(
            weight_severity=1.0,
            weight_confidence=1.0,
            weight_repetition=1.0,
            weight_escalation=1.0,
            weight_correlation=1.0,
            weight_cross_domain=1.0,
            correlation_per_category=1.0,
        )
        s = ThreatScorer(cfg)
        for it in (auth_suspicious(0), auth_critical(1), malicious_process(2), cpu(2), net(2)):
            s.observe(it)
        b = s.score(at(2))
        assert b.raw_total > 1.0
        assert b.final_score == 1.0

    def test_isolated_informational_anomaly_stays_low(self) -> None:
        assert score_of([cpu()]).final_score < 0.25  # below the ALERT threshold

    def test_naive_now_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            scorer().score(datetime(2025, 1, 1))


class TestSeverity:
    def test_higher_severity_scores_strictly_higher(self) -> None:
        scores = [
            score_of([item("x_event", sev, C.INFORMATIONAL, 0.5)]).final_score
            for sev in (S.INFO, S.LOW, S.MEDIUM, S.HIGH, S.CRITICAL)
        ]
        assert scores == sorted(scores)
        assert len(set(scores)) == 5

    def test_severity_contribution_scales_with_the_configured_level(self) -> None:
        cfg = ScoringConfig()
        b = score_of([item("x_event", S.HIGH, C.INFORMATIONAL, 0.0)])
        assert b.severity_contribution == pytest.approx(cfg.weight_severity * cfg.level_high)

    def test_critical_event_is_flagged(self) -> None:
        b = score_of([malicious_process()])
        assert ReasonCode.CRITICAL_EVENT in b.reason_codes
        assert b.active_max_severity is S.CRITICAL
        assert b.severe_active is True

    def test_critical_without_high_confidence_is_not_severe(self) -> None:
        b = score_of([item("x_event", S.CRITICAL, C.SUSPICIOUS, 0.9)])
        assert b.severe_active is False

    def test_a_lone_critical_high_confidence_event_reaches_defensive_not_aggressive(self) -> None:
        score = score_of([malicious_process()]).final_score
        assert 0.55 <= score < 0.80


class TestConfidence:
    def test_low_confidence_contributes_less_than_high_confidence(self) -> None:
        low = score_of([item("x_event", S.HIGH, C.INFORMATIONAL, 0.1)])
        high = score_of([item("x_event", S.HIGH, C.INFORMATIONAL, 0.9)])
        assert low.confidence_contribution < high.confidence_contribution
        assert low.final_score < high.final_score

    def test_zero_confidence_contributes_nothing_but_severity_remains(self) -> None:
        b = score_of([item("x_event", S.HIGH, C.INFORMATIONAL, 0.0)])
        assert b.confidence_contribution == 0.0
        assert b.severity_contribution > 0

    def test_confidence_is_scaled_by_severity(self) -> None:
        trivial = score_of([item("x_event", S.INFO, C.INFORMATIONAL, 1.0)])
        severe = score_of([item("x_event", S.CRITICAL, C.INFORMATIONAL, 1.0)])
        assert trivial.confidence_contribution < severe.confidence_contribution

    def test_missing_confidence_uses_the_configured_default(self) -> None:
        event = DetectionEvent(
            detected_at=T0,
            rule_id="R",
            rule_name="n",
            severity="HIGH",
            metric_key="m",
            event_type="x_event",
            confidence=None,
        )
        assert EvidenceItem.from_event(event, default_confidence=0.42).confidence == 0.42

    def test_confidence_outside_unit_interval_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            item(confidence=1.5)


class TestRepetition:
    def _repeat(self, n: int) -> float:
        s = scorer()
        for _ in range(n):
            s.observe(item("cpu_sustained_high", S.MEDIUM, C.INFORMATIONAL, 0.3, 0))
        return s.score(at(0)).repetition_contribution

    def test_repeats_increase_the_contribution(self) -> None:
        values = [self._repeat(n) for n in (1, 2, 5, 20)]
        assert values[0] == 0.0
        assert values == sorted(values)
        assert values[1] > 0

    def test_contribution_is_bounded_by_its_weight(self) -> None:
        cfg = ScoringConfig()
        assert self._repeat(10_000) <= cfg.weight_repetition * cfg.level_medium + 1e-9

    def test_the_hundredth_event_barely_moves_the_score(self) -> None:
        assert self._repeat(100) - self._repeat(99) < 1e-4

    def test_score_with_a_thousand_repeats_is_valid_and_close_to_a_hundred(self) -> None:
        def total(n: int) -> float:
            s = scorer()
            for _ in range(n):
                s.observe(cpu(0))
            return s.score(at(0)).final_score

        assert 0.0 <= total(1000) <= 1.0
        assert total(1000) == pytest.approx(total(100), abs=1e-6)

    def test_repeat_count_is_capped(self) -> None:
        cfg = ScoringConfig(repetition_cap=5)
        s = ThreatScorer(cfg)
        for _ in range(50):
            s.observe(cpu(0))
        assert s.score(at(0)).signals[0].count == 5

    def test_repetition_is_flagged(self) -> None:
        s = scorer()
        s.observe(cpu(0))
        s.observe(cpu(1))
        assert ReasonCode.REPEATED_ACTIVITY in s.score(at(1)).reason_codes


class TestEscalation:
    def test_upgrade_in_severity_and_classification_is_an_escalation(self) -> None:
        s = scorer()
        s.observe(auth_suspicious(0))
        before = s.score(at(0))
        s.observe(auth_critical(5))
        after = s.score(at(5))
        assert before.escalation_contribution == 0.0
        assert after.escalation_contribution > 0.0
        assert ReasonCode.ESCALATING_ACTIVITY in after.reason_codes
        assert after.signals[0].escalated is True

    def test_confidence_change_alone_is_not_an_escalation(self) -> None:
        s = scorer()
        s.observe(item("cpu_sustained_high", S.MEDIUM, C.INFORMATIONAL, 0.30, 0))
        s.observe(item("cpu_sustained_high", S.MEDIUM, C.INFORMATIONAL, 0.55, 1))
        assert s.score(at(1)).escalation_contribution == 0.0

    def test_a_weaker_repeat_does_not_unescalate_or_replace_the_strongest(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        s.observe(auth_suspicious(1))
        sig = s.score(at(1)).signals[0]
        assert sig.severity is S.CRITICAL
        assert sig.classification is C.HIGH_CONFIDENCE


class TestCorrelation:
    def test_independent_categories_add_risk(self) -> None:
        one = score_of([cpu()]).final_score
        two = score_of([cpu(), net()]).final_score
        three = score_of([cpu(), net(), proc()]).final_score
        assert one < two < three

    def test_correlation_requires_a_second_category(self) -> None:
        b = score_of([cpu()])
        assert b.correlation_contribution == 0.0
        assert ReasonCode.CROSS_SIGNAL_CORRELATION not in b.reason_codes

    def test_duplicate_events_from_one_signal_are_not_independent_evidence(self) -> None:
        b = score_of([cpu(0), cpu(1), cpu(2), cpu(3)])
        assert b.correlation_contribution == 0.0
        assert b.signal_count == 1
        assert b.active_categories == (SignalCategory.CPU,)

    def test_different_event_types_in_one_category_count_once(self) -> None:
        # Two unknown event types both map to OTHER: one category, so no correlation.
        a = item("mystery_a", S.HIGH, C.SUSPICIOUS, 0.6)
        b_ = item("mystery_b", S.HIGH, C.SUSPICIOUS, 0.6)
        assert category_for("mystery_a") is category_for("mystery_b") is SignalCategory.OTHER
        b = score_of([a, b_])
        assert b.correlation_contribution == 0.0
        assert b.active_categories == (SignalCategory.OTHER,)

    def test_correlation_contribution_is_capped(self) -> None:
        cfg = ScoringConfig()
        s = scorer()
        for it in (
            malicious_process(0),
            auth_critical(0),
            connection_suspicious(0),
            cpu(0),
            net(0),
        ):
            s.observe(it)
        assert s.score(at(0)).correlation_contribution <= cfg.weight_correlation + 1e-9

    def test_resource_plus_security_adds_cross_domain_risk(self) -> None:
        both = score_of([cpu(), auth_suspicious()])
        resource_only = score_of([cpu(), net()])
        security_only = score_of([auth_suspicious(), connection_suspicious()])
        assert both.cross_domain_contribution > 0
        assert ReasonCode.CROSS_DOMAIN_CORRELATION in both.reason_codes
        assert resource_only.cross_domain_contribution == 0.0
        assert security_only.cross_domain_contribution == 0.0

    def test_cross_domain_is_limited_by_the_weaker_side(self) -> None:
        weak = score_of([item("cpu_sustained_high", S.INFO, C.INFORMATIONAL, 0.3), auth_critical()])
        strong = score_of([cpu(), auth_critical()])
        assert weak.cross_domain_contribution < strong.cross_domain_contribution

    def test_correlated_attack_outscores_the_same_attack_alone(self) -> None:
        alone = score_of([auth_critical(10)]).final_score
        correlated = score_of([cpu(0), net(5), auth_critical(10)]).final_score
        assert correlated > alone


class TestDecay:
    def test_evidence_loses_half_its_weight_per_half_life(self) -> None:
        s = scorer()
        s.observe(auth_suspicious(0))
        fresh = s.score(at(0)).severity_contribution
        later = s.score(at(HALF_LIFE)).severity_contribution
        assert later == pytest.approx(fresh / 2, rel=1e-4)

    def test_score_decreases_monotonically_without_new_evidence(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        scores = [s.score(at(t)).final_score for t in range(0, 400, 10)]
        assert scores == sorted(scores, reverse=True)
        assert scores[-1] == 0.0

    def test_decay_is_reported_and_undecayed_score_is_unchanged(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        fresh = s.score(at(0))
        old = s.score(at(HALF_LIFE))
        assert fresh.decay == 0.0
        assert old.decay > 0.0
        assert old.score_before_decay == pytest.approx(fresh.final_score)
        assert old.decay == pytest.approx(old.score_before_decay - old.final_score, abs=1e-5)
        assert ReasonCode.EVIDENCE_DECAYING in old.reason_codes

    def test_decay_never_produces_a_negative_or_out_of_range_score(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        for t in (0, 1, 59.9, 60, 61, 299, 300, 301, 10_000, 1e9):
            assert 0.0 <= s.score(at(t)).final_score <= 1.0

    def test_evidence_from_the_future_is_treated_as_fresh_not_amplified(self) -> None:
        s = scorer()
        s.observe(auth_critical(100))
        assert s.score(at(0)).final_score == s.score(at(100)).final_score

    def test_fresh_weak_evidence_can_outweigh_stale_strong_evidence(self) -> None:
        s = scorer()
        s.observe(malicious_process(0))
        s.observe(cpu(280))
        b = s.score(at(280))
        assert b.signals[0].event_type == "cpu_sustained_high"

    def test_expired_signals_are_dropped_from_memory(self) -> None:
        s = scorer()
        s.observe(cpu(0))
        s.observe(net(1000))  # far beyond the TTL of the cpu signal
        assert s.signal_count == 1

    def test_scoring_does_not_mutate_state(self) -> None:
        s = scorer()
        s.observe(auth_critical(0))
        first = s.score(at(30)).to_dict()
        for _ in range(5):
            assert s.score(at(30)).to_dict() == first
        assert s.signal_count == 1


class TestDeduplication:
    def test_the_same_event_id_is_counted_once(self) -> None:
        s = scorer()
        first = item(event_id=77)
        again = item(event_id=77)
        assert s.observe(first) is True
        assert s.observe(again) is False
        assert s.score(at(0)).signals[0].count == 1

    def test_events_without_ids_are_never_deduplicated(self) -> None:
        s = scorer()
        assert s.observe(item(event_id=None)) is True
        assert s.observe(item(event_id=None)) is True
        assert s.score(at(0)).signals[0].count == 2

    def test_dedup_memory_is_bounded(self) -> None:
        s = ThreatScorer(ScoringConfig(dedup_window=10))
        for i in range(1, 101):
            s.observe(item(event_id=i))
        assert len(s._seen) == 10  # type: ignore[attr-defined]


class TestBoundedMemory:
    def test_signal_table_never_exceeds_the_configured_maximum(self) -> None:
        s = ThreatScorer(ScoringConfig(max_signals=8))
        for i in range(500):
            s.observe(item(f"unknown_type_{i}", S.LOW, C.INFORMATIONAL, 0.2, i * 0.01))
        assert s.signal_count <= 8

    def test_eviction_removes_the_stalest_signal(self) -> None:
        s = ThreatScorer(ScoringConfig(max_signals=2))
        s.observe(cpu(0))
        s.observe(net(10))
        s.observe(proc(20))
        kinds = {sig.event_type for sig in s.score(at(20)).signals}
        assert kinds == {"network_throughput_high", "process_count_anomaly"}

    def test_report_size_is_bounded(self) -> None:
        s = ThreatScorer(ScoringConfig(max_signals=64))
        for i in range(40):
            s.observe(item(f"unknown_type_{i}", S.LOW, C.INFORMATIONAL, 0.2, 0))
        assert len(s.score(at(0)).signals) == MAX_REPORTED_SIGNALS


class TestExplainability:
    def test_components_sum_to_the_raw_total(self) -> None:
        b = score_of([cpu(0), net(2), auth_suspicious(5), auth_critical(9)])
        parts = (
            b.severity_contribution
            + b.confidence_contribution
            + b.repetition_contribution
            + b.escalation_contribution
            + b.correlation_contribution
            + b.cross_domain_contribution
        )
        assert b.raw_total == pytest.approx(parts, abs=1e-5)
        assert b.final_score == pytest.approx(min(1.0, b.raw_total), abs=1e-5)

    def test_reason_codes_describe_the_evidence(self) -> None:
        b = score_of([cpu(0), auth_suspicious(5), auth_critical(9)])
        codes = set(b.reason_codes)
        assert {
            ReasonCode.CRITICAL_EVENT,
            ReasonCode.HIGH_CONFIDENCE_EVIDENCE,
            ReasonCode.SYNTHETIC_SECURITY_EVENT,
            ReasonCode.ESCALATING_ACTIVITY,
            ReasonCode.REPEATED_ACTIVITY,
            ReasonCode.CROSS_SIGNAL_CORRELATION,
            ReasonCode.CROSS_DOMAIN_CORRELATION,
        } <= codes

    def test_an_informational_anomaly_is_explained_as_such(self) -> None:
        b = score_of([cpu()])
        assert b.final_score > 0
        assert b.reason_codes == (ReasonCode.INFORMATIONAL_ANOMALY,)

    def test_stale_evidence_outside_the_active_window_still_has_a_reason(self) -> None:
        s = scorer()
        s.observe(cpu(0))
        b = s.score(at(200))  # beyond the 60 s active window, inside the 300 s TTL
        assert b.final_score > 0
        assert b.reason_codes == (ReasonCode.EVIDENCE_DECAYING,)

    def test_reason_text_is_derived_from_codes(self) -> None:
        b = score_of([malicious_process()])
        assert len(b.reasons) == len(b.reason_codes)
        assert all(isinstance(r, str) and r for r in b.reasons)

    def test_breakdown_is_json_serialisable_with_the_documented_fields(self) -> None:
        d = score_of([cpu(0), auth_critical(5)]).to_dict()
        restored = json.loads(json.dumps(d, allow_nan=False))
        for key in (
            "severity_contribution",
            "confidence_contribution",
            "repetition_contribution",
            "escalation_contribution",
            "correlation_contribution",
            "cross_domain_contribution",
            "decay",
            "final_score",
            "reason_codes",
            "reasons",
            "signals",
            "active_categories",
        ):
            assert key in restored
        assert restored["signals"][0]["event_type"] == "auth_failure_burst"

    def test_signals_are_ordered_strongest_first(self) -> None:
        b = score_of([cpu(0), auth_critical(0), net(0)])
        strengths = [s.strength for s in b.signals]
        assert strengths == sorted(strengths, reverse=True)
        assert b.signals[0].event_type == "auth_failure_burst"


class TestDeterminism:
    SEQUENCE = (cpu(0), net(3), auth_suspicious(20), auth_critical(26), connection_suspicious(30))

    def _run(self) -> list[dict[str, object]]:
        s = scorer()
        out = []
        for it in self.SEQUENCE:
            s.observe(it)
            out.append(s.score(it.detected_at).to_dict())
        out.append(s.score(at(200)).to_dict())
        return out

    def test_same_sequence_gives_identical_breakdowns(self) -> None:
        assert self._run() == self._run()

    def test_independent_scorers_agree_at_any_chosen_time(self) -> None:
        # The scorer takes `now` explicitly and never reads a clock (also enforced
        # statically in the security tests), so the chosen time fully determines it.
        a, b = scorer(), scorer()
        evidence = auth_critical(0)
        for s in (a, b):
            s.observe(evidence)
        for now in (0, 17, 60, 123.456, 299):
            assert a.score(at(now)).to_dict() == b.score(at(now)).to_dict()


class TestFutureDatedEvidence:
    def test_future_evidence_is_clamped_to_now_when_now_is_known(self) -> None:
        s = scorer()
        s.observe(auth_critical(10_000_000), now=at(0))
        # Treated as having happened at t=0, so it decays and expires normally.
        assert s.score(at(HALF_LIFE)).decay > 0
        assert s.score(at(ScoringConfig().evidence_ttl_seconds + 1)).final_score == 0.0

    def test_unclamped_future_evidence_would_never_decay(self) -> None:
        # Documents why clamping matters: without `now`, a future event stays fresh.
        s = scorer()
        s.observe(auth_critical(10_000_000))
        assert s.score(at(HALF_LIFE * 5)).decay == 0.0

    def test_past_evidence_is_unchanged_by_clamping(self) -> None:
        a, b = scorer(), scorer()
        evidence = auth_critical(0)
        a.observe(evidence, now=at(50))
        b.observe(evidence)
        assert a.score(at(50)).to_dict() == b.score(at(50)).to_dict()


class TestMonotonicity:
    """A weaker event never lowers the risk implied by stronger evidence."""

    def test_adding_a_weaker_event_never_reduces_the_score(self) -> None:
        base = [auth_critical(0)]
        weaker = [
            cpu(1),
            item("x_event", S.INFO, C.INFORMATIONAL, 0.0, 1),
            item("auth_failure_burst", S.LOW, C.INFORMATIONAL, 0.0, 1),
        ]
        reference = score_of(base, 1).final_score
        for extra in weaker:
            assert score_of([*base, extra], 1).final_score >= reference

    def test_regression_hypothesis_counterexample_for_one_signal(self) -> None:
        # Found by Hypothesis: a later item with a higher classification but zero
        # confidence used to replace a fully-confident item and lower the score.
        s = scorer()
        steps = [
            item("cpu_sustained_high", S.INFO, C.INFORMATIONAL, 0.0, 0),
            item("cpu_sustained_high", S.INFO, C.INFORMATIONAL, 1.0, 0),
            item("cpu_sustained_high", S.INFO, C.SUSPICIOUS, 0.0, 0),
        ]
        previous = 0.0
        for it in steps:
            s.observe(it)
            current = s.score(at(0)).final_score
            assert current >= previous
            previous = current

    def test_a_lower_severity_event_cannot_hide_a_critical_one(self) -> None:
        s = scorer()
        s.observe(malicious_process(0))
        before = s.score(at(1))
        s.observe(item("x_event", S.INFO, C.INFORMATIONAL, 1.0, 1))
        after = s.score(at(1))
        assert after.final_score >= before.final_score
        assert after.active_max_severity is S.CRITICAL
        assert after.severe_active is True


class TestEvidenceFromEvent:
    def _event(self, **kw: object) -> DetectionEvent:
        base: dict[str, object] = {
            "detected_at": T0.replace(tzinfo=None),
            "rule_id": "DET-X-001",
            "rule_name": "x",
            "severity": "HIGH",
            "metric_key": "m",
            "event_type": "auth_failure_burst",
            "classification": "SUSPICIOUS",
            "confidence": 0.55,
            "is_synthetic": True,
            "telemetry_sample_id": None,
        }
        base.update(kw)
        return DetectionEvent(**base)  # type: ignore[arg-type]

    def test_maps_typed_columns(self) -> None:
        e = EvidenceItem.from_event(self._event(), default_confidence=0.5)
        assert e.category is SignalCategory.AUTHENTICATION
        assert e.severity is Severity.HIGH
        assert e.classification is Classification.SUSPICIOUS
        assert e.confidence == 0.55
        assert e.is_synthetic is True

    def test_naive_sqlite_timestamp_becomes_utc(self) -> None:
        e = EvidenceItem.from_event(self._event(), default_confidence=0.5)
        assert e.detected_at.tzinfo is not None

    def test_invalid_severity_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            EvidenceItem.from_event(self._event(severity="BOGUS"), default_confidence=0.5)

    @pytest.mark.parametrize(
        ("event_type", "category"),
        [
            ("cpu_sustained_high", SignalCategory.CPU),
            ("memory_sustained_high", SignalCategory.MEMORY),
            ("network_throughput_high", SignalCategory.NETWORK),
            ("process_count_anomaly", SignalCategory.PROCESS),
            ("auth_failure_burst", SignalCategory.AUTHENTICATION),
            ("access_denied_burst", SignalCategory.ACCESS),
            ("connection_burst", SignalCategory.CONNECTION),
            ("suspicious_process", SignalCategory.EXECUTION),
            ("something_new", SignalCategory.OTHER),
        ],
    )
    def test_every_detection_event_type_has_a_category(
        self, event_type: str, category: SignalCategory
    ) -> None:
        assert category_for(event_type) is category


class TestSyntheticEscalationSequence:
    """normal -> auth failures -> repeated -> connection burst -> critical escalation."""

    def test_score_increases_along_the_demo_sequence(self) -> None:
        s = scorer()
        steps = [
            (0, None),
            (10, auth_suspicious(10)),
            (20, auth_critical(20)),
            (25, connection_suspicious(25)),
            (30, malicious_process(30)),
        ]
        scores = []
        for t, it in steps:
            if it is not None:
                s.observe(it)
            scores.append(s.score(at(t)).final_score)
        assert scores[0] == 0.0
        assert scores == sorted(scores)
        assert scores[-1] > scores[1] > scores[0]
        assert scores[-1] >= 0.80
