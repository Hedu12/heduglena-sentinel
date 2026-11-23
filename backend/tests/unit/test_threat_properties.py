"""
Property-based tests (Hypothesis) for the scorer and the state machine.

For every generated valid event sequence these must hold:

  * 0 <= threat_score <= 1, and every contribution is >= 0
  * the breakdown is internally consistent and JSON-serialisable
  * the same sequence always produces the same result (determinism)
  * adding evidence never lowers the score (monotone)
  * letting time pass never raises the score, and never makes it invalid
  * the defense state is always one of the four valid states
  * the state machine never goes below the floor, climbs only as far as the
    score or floor justifies, and descends one level at a time, never sooner
    than the cooldown after the previous transition.
"""

from __future__ import annotations

import json
from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from models.enums import Classification, DefenseState, Severity
from tests.threat_helpers import T0, at
from threat.config import STATE_ORDER, ScoringConfig, StateConfig, state_rank
from threat.evidence import EvidenceItem, category_for
from threat.scorer import ThreatScorer
from threat.state_machine import DefenseStateMachine

PROFILE = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

EVENT_TYPES = [
    "cpu_sustained_high",
    "memory_sustained_high",
    "network_throughput_high",
    "process_count_anomaly",
    "auth_failure_burst",
    "access_denied_burst",
    "connection_burst",
    "suspicious_process",
    "unknown_kind",
]

step_strategy = st.tuples(
    st.floats(min_value=0.0, max_value=400.0, allow_nan=False, allow_infinity=False),  # dt
    st.sampled_from(EVENT_TYPES),
    st.sampled_from(list(Severity)),
    st.sampled_from(list(Classification)),
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),  # confidence
    st.booleans(),  # synthetic
)
sequence_strategy = st.lists(step_strategy, max_size=40)


def build(sequence: list[tuple[float, str, Severity, Classification, float, bool]]):  # type: ignore[no-untyped-def]
    """Turn generated tuples into time-ordered evidence with unique ids."""
    items: list[EvidenceItem] = []
    t = 0.0
    for i, (dt, etype, sev, cls, conf, synthetic) in enumerate(sequence, start=1):
        t += dt
        items.append(
            EvidenceItem(
                event_type=etype,
                category=category_for(etype),
                severity=sev,
                classification=cls,
                confidence=conf,
                detected_at=at(t),
                event_id=i,
                is_synthetic=synthetic,
            )
        )
    return items


def run(items: list[EvidenceItem]) -> list[dict[str, object]]:
    scorer = ThreatScorer(ScoringConfig())
    out = []
    for it in items:
        scorer.observe(it)
        out.append(scorer.score(it.detected_at).to_dict())
    return out


class TestScoreProperties:
    @PROFILE
    @given(sequence_strategy)
    def test_score_is_always_within_the_unit_interval(self, sequence) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        for it in build(sequence):
            scorer.observe(it)
            b = scorer.score(it.detected_at)
            assert 0.0 <= b.final_score <= 1.0
            assert 0.0 <= b.score_before_decay <= 1.0
            assert b.decay >= 0.0

    @PROFILE
    @given(sequence_strategy)
    def test_every_contribution_is_non_negative_and_within_its_weight(self, sequence) -> None:  # type: ignore[no-untyped-def]
        cfg = ScoringConfig()
        scorer = ThreatScorer(cfg)
        for it in build(sequence):
            scorer.observe(it)
            b = scorer.score(it.detected_at)
            assert 0.0 <= b.severity_contribution <= cfg.weight_severity + 1e-9
            assert 0.0 <= b.confidence_contribution <= cfg.weight_confidence + 1e-9
            assert 0.0 <= b.repetition_contribution <= cfg.weight_repetition + 1e-9
            assert 0.0 <= b.escalation_contribution <= cfg.weight_escalation + 1e-9
            assert 0.0 <= b.correlation_contribution <= cfg.weight_correlation + 1e-9
            assert 0.0 <= b.cross_domain_contribution <= cfg.weight_cross_domain + 1e-9

    @PROFILE
    @given(sequence_strategy)
    def test_breakdown_is_consistent_and_serialisable(self, sequence) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        for it in build(sequence):
            scorer.observe(it)
            b = scorer.score(it.detected_at)
            parts = (
                b.severity_contribution
                + b.confidence_contribution
                + b.repetition_contribution
                + b.escalation_contribution
                + b.correlation_contribution
                + b.cross_domain_contribution
            )
            assert abs(b.raw_total - parts) < 1e-4
            assert b.final_score == min(1.0, max(0.0, b.raw_total))
            json.dumps(b.to_dict(), allow_nan=False)

    @PROFILE
    @given(sequence_strategy, st.floats(0.0, 400.0, allow_nan=False))
    def test_any_active_evidence_is_always_explained(self, sequence, wait) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        items = build(sequence)
        for it in items:
            scorer.observe(it)
        if not items:
            return
        b = scorer.score(items[-1].detected_at + timedelta(seconds=wait))
        assert b.reason_codes, "a decision must always say why"
        if b.signal_count == 0:
            assert b.final_score == 0.0

    @PROFILE
    @given(sequence_strategy)
    def test_scoring_is_deterministic(self, sequence) -> None:  # type: ignore[no-untyped-def]
        items = build(sequence)
        assert run(items) == run(items)

    @PROFILE
    @given(sequence_strategy)
    def test_adding_evidence_never_lowers_the_score(self, sequence) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        for it in build(sequence):
            before = scorer.score(it.detected_at).final_score
            scorer.observe(it)
            after = scorer.score(it.detected_at).final_score
            assert after >= before - 1e-9

    @PROFILE
    @given(sequence_strategy, st.lists(st.floats(0.0, 500.0, allow_nan=False), max_size=30))
    def test_repeated_decay_is_non_increasing_and_always_valid(self, sequence, gaps) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        items = build(sequence)
        for it in items:
            scorer.observe(it)
        t = (items[-1].detected_at - T0).total_seconds() if items else 0.0
        previous = scorer.score(at(t)).final_score
        for gap in gaps:
            t += gap
            current = scorer.score(at(t)).final_score
            assert 0.0 <= current <= 1.0
            assert current <= previous + 1e-9
            previous = current

    @PROFILE
    @given(sequence_strategy)
    def test_memory_stays_bounded(self, sequence) -> None:  # type: ignore[no-untyped-def]
        cfg = ScoringConfig(max_signals=5, dedup_window=7)
        scorer = ThreatScorer(cfg)
        for it in build(sequence):
            scorer.observe(it)
            assert scorer.signal_count <= 5
            assert len(scorer._seen) <= 7  # type: ignore[attr-defined]


state_step = st.tuples(
    st.floats(min_value=0.0, max_value=120.0, allow_nan=False, allow_infinity=False),  # dt
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),  # score
    st.sampled_from(STATE_ORDER),  # floor
    st.booleans(),  # severe
)


# Timer logic fails at the edges, so this generator is dense and clustered: short gaps
# (so cooldown and dwell windows contain several evaluations) and scores that sit just
# above and just below each entry and exit threshold.
_NEAR_THRESHOLDS = [0.0, 0.05, 0.19, 0.21, 0.24, 0.26, 0.34, 0.37, 0.49, 0.51, 0.54, 0.56]
_NEAR_THRESHOLDS += [0.64, 0.66, 0.74, 0.76, 0.79, 0.81, 0.89, 0.91, 1.0]
dense_step = st.tuples(
    st.floats(min_value=0.0, max_value=20.0, allow_nan=False, allow_infinity=False),
    st.sampled_from(_NEAR_THRESHOLDS),
    st.sampled_from([DefenseState.RELAXED] * 4 + [DefenseState.ALERT, DefenseState.DEFENSIVE]),
    st.booleans(),
)
dense_sequence = st.lists(dense_step, min_size=1, max_size=120)


class TestStateMachineProperties:
    @PROFILE
    @given(st.lists(state_step, max_size=60))
    def test_state_is_always_valid_and_respects_the_floor(self, steps) -> None:  # type: ignore[no-untyped-def]
        cfg = StateConfig()
        m = DefenseStateMachine(cfg)
        t = 0.0
        for dt, score, floor, severe in steps:
            t += dt
            ev = m.evaluate(now=at(t), score=score, floor=floor, severe=severe)
            assert ev.new_state in set(DefenseState)
            assert state_rank(ev.new_state) >= state_rank(floor)

    @PROFILE
    @given(st.lists(state_step, max_size=60))
    def test_climbing_is_only_as_high_as_score_or_floor_justify(self, steps) -> None:  # type: ignore[no-untyped-def]
        cfg = StateConfig()
        m = DefenseStateMachine(cfg)
        t = 0.0
        for dt, score, floor, severe in steps:
            t += dt
            ev = m.evaluate(now=at(t), score=score, floor=floor, severe=severe)
            if ev.escalated:
                ceiling = max(state_rank(cfg.state_for_score(score)), state_rank(floor))
                assert state_rank(ev.new_state) <= ceiling

    @PROFILE
    @given(st.lists(state_step, max_size=80))
    def test_descent_is_one_level_below_exit_and_never_before_the_cooldown(self, steps) -> None:  # type: ignore[no-untyped-def]
        cfg = StateConfig()
        m = DefenseStateMachine(cfg)
        t = 0.0
        last_transition: float | None = None
        for dt, score, floor, severe in steps:
            t += dt
            ev = m.evaluate(now=at(t), score=score, floor=floor, severe=severe)
            if not ev.changed:
                continue
            if not ev.escalated:
                assert state_rank(ev.previous_state) - state_rank(ev.new_state) == 1
                assert score < cfg.exit(ev.previous_state)
                if last_transition is not None:
                    assert t - last_transition >= cfg.cooldown_seconds - 1e-9
            last_transition = t

    @PROFILE
    @given(dense_sequence)
    def test_a_descent_means_the_score_stayed_below_the_exit_threshold_for_the_whole_cooldown(  # type: ignore[no-untyped-def]
        self, steps
    ) -> None:
        # The hysteresis contract: a state is left only after the score has stayed below
        # that state's exit threshold for a full cooldown WHILE IN THAT STATE. Time spent
        # inside its hysteresis band (at or above exit) must never count toward leaving.
        cfg = StateConfig()
        m = DefenseStateMachine(cfg)
        t = 0.0
        entered_at = 0.0  # when the current state was entered
        history: list[tuple[float, float]] = []  # (time, score) since entering it
        for dt, score, floor, severe in steps:
            t += dt
            history.append((t, score))
            ev = m.evaluate(now=at(t), score=score, floor=floor, severe=severe)
            if ev.changed and not ev.escalated:
                exit_threshold = cfg.exit(ev.previous_state)
                # Start of the trailing run of evaluations below the exit threshold,
                # never earlier than the moment this state was entered.
                run_start = t
                for ts, s in reversed(history):
                    if s >= exit_threshold:
                        break
                    run_start = ts
                run_start = max(run_start, entered_at)
                assert t - run_start >= cfg.cooldown_seconds - 1e-9, (
                    f"left {ev.previous_state.value} at t={t}, but the score had been below "
                    f"{exit_threshold} in that state only since t={run_start} "
                    f"({t - run_start:.1f}s < {cfg.cooldown_seconds}s)"
                )
            if ev.changed:
                entered_at = t
                history = [(t, score)]

    @PROFILE
    @given(st.lists(st.floats(0.0, 1.0, allow_nan=False), min_size=1, max_size=200))
    def test_without_severity_or_floor_a_one_second_cadence_never_skips_a_dwell(
        self, scores
    ) -> None:  # type: ignore[no-untyped-def]
        # With bypass disabled and no floor/severe flag, every climb needs the dwell.
        cfg = StateConfig(bypass_margin=1.0, dwell_seconds=10)
        m = DefenseStateMachine(cfg)
        above_since: dict[DefenseState, float | None] = dict.fromkeys(STATE_ORDER[1:])
        for i, score in enumerate(scores):
            t = float(i)
            for state in STATE_ORDER[1:]:
                if score >= cfg.entry(state):
                    if above_since[state] is None:
                        above_since[state] = t
                else:
                    above_since[state] = None
            ev = m.evaluate(now=at(t), score=score)
            if ev.escalated:
                since = above_since[ev.new_state]
                assert since is not None
                assert t - since >= cfg.dwell_seconds

    @PROFILE
    @given(sequence_strategy)
    def test_scorer_and_machine_together_always_yield_valid_output(self, sequence) -> None:  # type: ignore[no-untyped-def]
        scorer = ThreatScorer(ScoringConfig())
        m = DefenseStateMachine(StateConfig())
        for it in build(sequence):
            scorer.observe(it)
            b = scorer.score(it.detected_at)
            floor = (
                StateConfig().floor_critical
                if b.active_max_severity is Severity.CRITICAL
                else StateConfig().floor_high
                if b.active_max_severity is Severity.HIGH
                else DefenseState.RELAXED
            )
            ev = m.evaluate(
                now=it.detected_at + timedelta(0),
                score=b.final_score,
                floor=floor,
                severe=b.severe_active,
            )
            assert ev.new_state in set(DefenseState)
            assert 0.0 <= ev.score <= 1.0
