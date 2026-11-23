"""Unit tests for DefenseStateMachine: transitions, hysteresis, dwell, cooldown,
severe-escalation bypass, the active-threat floor, and rollback."""

from __future__ import annotations

from datetime import datetime

import pytest

from models.enums import DefenseState
from tests.threat_helpers import T0, at
from threat.config import StateConfig
from threat.reasons import ReasonCode
from threat.state_machine import DefenseStateMachine, StateEvaluation

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)
CFG = StateConfig()  # 0.25 / 0.55 / 0.80, margin 0.05, bypass 0.10, dwell 10 s, cooldown 30 s


def machine(state: DefenseState = R, cfg: StateConfig = CFG) -> DefenseStateMachine:
    return DefenseStateMachine(cfg, initial=state)


def step(
    m: DefenseStateMachine,
    t: float,
    score: float,
    *,
    floor: DefenseState = R,
    severe: bool = False,
    corroborated: bool = False,
) -> StateEvaluation:
    return m.evaluate(now=at(t), score=score, floor=floor, severe=severe, corroborated=corroborated)


class TestInitialState:
    def test_starts_relaxed(self) -> None:
        assert DefenseStateMachine(CFG).state is R

    def test_zero_score_keeps_relaxed(self) -> None:
        m = machine()
        for t in range(0, 100, 10):
            assert step(m, t, 0.0).new_state is R


class TestEscalationWithDwell:
    def test_relaxed_to_alert_after_dwell(self) -> None:
        m = machine()
        pending = step(m, 0, 0.30)
        assert pending.new_state is R
        assert ReasonCode.DWELL_PENDING in pending.reason_codes
        assert step(m, 9.9, 0.30).new_state is R
        ev = step(m, 10, 0.30)
        assert (ev.previous_state, ev.new_state) == (R, A)
        assert ev.reason_codes == (ReasonCode.DWELL_SATISFIED,)
        assert ev.changed and ev.escalated

    def test_alert_to_defensive_after_dwell(self) -> None:
        m = machine(A)
        step(m, 0, 0.58)
        assert step(m, 9, 0.58).new_state is A
        assert step(m, 10, 0.58).new_state is D

    def test_defensive_to_aggressive_after_dwell(self) -> None:
        m = machine(D)
        step(m, 0, 0.82)
        assert step(m, 9, 0.82).new_state is D
        # 0.82 is below entry+bypass (0.90) so only dwell can promote it.
        assert step(m, 10, 0.82).new_state is G

    def test_dwell_restarts_if_the_score_dips_below_the_entry_threshold(self) -> None:
        m = machine()
        step(m, 0, 0.30)
        step(m, 6, 0.10)  # dips: the dwell clock resets
        step(m, 7, 0.30)
        assert step(m, 16, 0.30).new_state is R  # only 9 s since the restart
        assert step(m, 17, 0.30).new_state is A

    def test_zero_dwell_promotes_immediately(self) -> None:
        m = machine(cfg=StateConfig(dwell_seconds=0))
        assert step(m, 0, 0.30).new_state is A

    def test_all_three_upward_transitions_in_sequence(self) -> None:
        m = machine()
        path = [R]
        for t, score in [(0, 0.30), (10, 0.30), (11, 0.58), (21, 0.58), (22, 0.82), (32, 0.82)]:
            step(m, t, score)
            if m.state is not path[-1]:
                path.append(m.state)
        assert path == [R, A, D, G]


class TestSevereEscalationBypass:
    def test_score_well_above_the_threshold_skips_the_dwell(self) -> None:
        m = machine()
        ev = step(m, 0, 0.36)  # 0.25 entry + 0.10 bypass margin
        assert ev.new_state is A
        assert ev.reason_codes == (ReasonCode.SEVERE_ESCALATION_BYPASS,)

    def test_score_just_below_the_bypass_margin_still_waits(self) -> None:
        m = machine()
        assert step(m, 0, 0.349).new_state is R

    def test_severe_event_skips_the_dwell(self) -> None:
        m = machine()
        ev = step(m, 0, 0.30, severe=True)
        assert ev.new_state is A
        assert ReasonCode.SEVERE_ESCALATION_BYPASS in ev.reason_codes

    def test_severe_flag_cannot_exceed_what_the_score_supports(self) -> None:
        m = machine()
        # Severe, but the score only justifies ALERT: it must not jump to AGGRESSIVE.
        assert step(m, 0, 0.30, severe=True).new_state is A

    def test_even_a_severe_escalation_climbs_only_one_level_per_evaluation(self) -> None:
        m = machine()
        path = [step(m, 0, 0.90, severe=True, corroborated=True).new_state for _ in range(3)]
        assert path == [A, D, G]  # every level is visited, and each is its own transition

    def test_escalation_is_faster_than_de_escalation(self) -> None:
        up = machine()
        # Three back-to-back evaluations (no waiting) reach the top ...
        assert [step(up, 0, 0.95, corroborated=True).new_state for _ in range(3)] == [A, D, G]
        down = machine(G)
        assert step(down, 0, 0.0).new_state is G
        assert step(down, 29, 0.0).new_state is G
        assert step(down, 30, 0.0).new_state is D  # needs the full cooldown, one level only


class TestAggressiveBypassIsGuarded:
    """AGGRESSIVE is the most disruptive posture, so it is the hardest to reach quickly."""

    def test_bypass_into_aggressive_needs_corroboration(self) -> None:
        m = machine(D)
        ev = step(m, 0, 0.95, severe=True, corroborated=False)
        assert ev.new_state is D
        assert ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION in ev.reason_codes

    def test_corroborated_bypass_enters_aggressive_immediately(self) -> None:
        m = machine(D)
        ev = step(m, 0, 0.95, severe=True, corroborated=True)
        assert ev.new_state is G
        assert ev.reason_codes == (ReasonCode.SEVERE_ESCALATION_BYPASS,)

    def test_a_severe_flag_with_a_score_below_the_threshold_is_not_enough(self) -> None:
        m = machine(D)
        assert step(m, 0, 0.78, severe=True, corroborated=True).new_state is D

    def test_without_corroboration_the_full_dwell_still_works(self) -> None:
        m = machine(D)
        step(m, 0, 0.85)
        assert step(m, 9, 0.85).new_state is D
        ev = step(m, 10, 0.85)
        assert ev.new_state is G
        assert ev.reason_codes == (ReasonCode.DWELL_SATISFIED,)

    def test_a_withheld_bypass_is_only_reported_when_it_is_what_blocks_the_climb(self) -> None:
        m = machine(D)
        assert ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION not in step(m, 0, 0.82).reason_codes
        assert (
            ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION
            not in step(machine(D), 0, 0.50, severe=True).reason_codes
        )

    def test_other_bypasses_do_not_need_corroboration(self) -> None:
        # Only AGGRESSIVE is guarded; earlier levels keep their fast path.
        assert step(machine(), 0, 0.40, severe=True).new_state is A
        assert step(machine(A), 0, 0.70, severe=True).new_state is D

    def test_aggressive_cannot_be_reached_from_relaxed_in_one_evaluation(self) -> None:
        m = machine()
        ev = step(m, 0, 1.0, severe=True, corroborated=True)
        assert ev.new_state is A

    def test_the_floor_can_raise_the_state_but_never_to_aggressive(self) -> None:
        m = machine()
        assert step(m, 0, 0.0, floor=D).new_state is D
        assert step(machine(), 0, 0.0, floor=D, severe=True, corroborated=True).new_state is D
        with pytest.raises(ValueError):
            StateConfig(floor_critical=G)

    def test_aggressive_is_left_normally_after_a_bypass(self) -> None:
        m = machine(D)
        step(m, 0, 0.95, severe=True, corroborated=True)
        assert m.state is G
        step(m, 1, 0.0)
        assert step(m, 31, 0.0).new_state is D


class TestActiveThreatFloor:
    def test_floor_raises_the_state_immediately(self) -> None:
        m = machine()
        ev = step(m, 0, 0.0, floor=D)
        assert ev.new_state is D
        assert ev.reason_codes == (ReasonCode.ACTIVE_THREAT_FLOOR,)

    def test_state_cannot_descend_below_the_floor(self) -> None:
        m = machine(G)
        for t in (0, 40, 80, 200, 1000):
            assert step(m, t, 0.0, floor=D).new_state.value in {"AGGRESSIVE", "DEFENSIVE"}
        assert m.state is D

    def test_state_descends_normally_once_the_floor_is_lifted(self) -> None:
        m = machine(D)
        step(m, 0, 0.0, floor=D)
        step(m, 100, 0.0, floor=D)
        step(m, 101, 0.0)  # floor lifted: cooldown starts now
        assert m.state is D
        assert step(m, 131, 0.0).new_state is A

    def test_floor_does_not_lower_a_higher_state(self) -> None:
        m = machine(G)
        assert step(m, 0, 0.95, floor=A).new_state is G


class TestDeEscalation:
    def test_one_level_per_cooldown(self) -> None:
        m = machine(G)
        assert step(m, 0, 0.0).new_state is G  # below exit: timer starts
        assert step(m, 29.9, 0.0).new_state is G
        ev = step(m, 30, 0.0)
        assert (ev.previous_state, ev.new_state) == (G, D)
        assert ev.reason_codes == (ReasonCode.DE_ESCALATION_COOLDOWN_ELAPSED,)
        # A transition restarts the cooldown: the next step needs another full 30 s.
        assert step(m, 31, 0.0).new_state is D
        assert step(m, 59.9, 0.0).new_state is D
        assert step(m, 60, 0.0).new_state is A
        assert step(m, 90, 0.0).new_state is R

    def test_never_drops_two_levels_in_one_evaluation(self) -> None:
        m = machine(G)
        step(m, 0, 0.0)
        ev = step(m, 10_000, 0.0)  # a huge gap still yields exactly one step
        assert (ev.previous_state, ev.new_state) == (G, D)

    def test_relaxed_never_descends(self) -> None:
        m = machine()
        for t in (0, 100, 1000):
            assert step(m, t, 0.0).new_state is R

    def test_pending_cooldown_is_explained(self) -> None:
        m = machine(D)
        ev = step(m, 0, 0.0)
        assert ReasonCode.COOLDOWN_PENDING in ev.reason_codes

    def test_a_score_recovery_resets_the_cooldown_timer(self) -> None:
        m = machine(D)
        step(m, 0, 0.30)  # below exit (0.50): timer starts
        step(m, 20, 0.53)  # back inside the band: timer cleared
        step(m, 21, 0.30)  # timer restarts
        assert step(m, 50, 0.30).new_state is D  # only 29 s
        assert step(m, 51, 0.30).new_state is A

    def test_time_in_the_new_states_hysteresis_band_does_not_count_toward_leaving(
        self,
    ) -> None:
        # Regression: after DEFENSIVE -> ALERT the score sat inside ALERT's band
        # (0.20 <= score < 0.25). That time used to count toward ALERT's cooldown, so the
        # state reached RELAXED one evaluation too early, before the score had been below
        # 0.20 for the full 30 s.
        # The bug only shows when the descent reading is in the band and the very next
        # reading is already below the exit threshold (no in-band reading clears the timer).
        m = machine(D)
        step(m, 0, 0.30)  # below DEFENSIVE's exit (0.50): cooldown starts
        assert step(m, 30, 0.22).new_state is A  # lands inside ALERT's band [0.20, 0.25)
        step(m, 35, 0.19)  # first reading below ALERT's exit: the cooldown starts HERE
        assert step(m, 60, 0.19).new_state is A  # 30 s after the descent, only 25 s below
        assert step(m, 64, 0.19).new_state is A
        assert step(m, 65, 0.19).new_state is R  # 30 s below: now it may leave

    def test_zero_cooldown_descends_on_the_second_low_reading(self) -> None:
        m = machine(D, StateConfig(cooldown_seconds=0))
        assert step(m, 0, 0.0).new_state is A


class TestHysteresis:
    def test_state_is_held_between_exit_and_entry(self) -> None:
        m = machine(D)
        for t in range(0, 600, 30):
            ev = step(m, t, 0.52)  # < 0.55 entry but >= 0.50 exit
            assert ev.new_state is D
        assert ReasonCode.HYSTERESIS_HOLD in ev.reason_codes

    def test_score_exactly_at_the_exit_threshold_holds(self) -> None:
        m = machine(D)
        step(m, 0, 0.50)
        assert step(m, 1000, 0.50).new_state is D

    def test_score_just_below_the_exit_threshold_eventually_descends(self) -> None:
        m = machine(D)
        step(m, 0, 0.499)
        assert step(m, 30, 0.499).new_state is A

    def test_a_noisy_score_around_the_entry_threshold_does_not_oscillate(self) -> None:
        m = machine()
        states = []
        for i in range(120):
            score = 0.56 if i % 2 == 0 else 0.54  # straddles the 0.55 entry
            step(m, i, score)
            states.append(m.state)
        transitions = sum(1 for a, b in zip(states, states[1:], strict=False) if a is not b)
        assert transitions <= 2  # climbs once; never flaps back and forth

    def test_enter_at_entry_threshold_leave_only_below_exit(self) -> None:
        m = machine(A)
        step(m, 0, 0.55)
        step(m, 10, 0.55)
        assert m.state is D
        step(m, 11, 0.51)  # inside the band
        step(m, 100, 0.51)
        assert m.state is D
        step(m, 101, 0.49)  # below exit
        step(m, 131, 0.49)
        assert m.state is A


class TestValidationAndHelpers:
    def test_naive_time_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            machine().evaluate(now=datetime(2025, 1, 1), score=0.1)

    @pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan")])
    def test_invalid_score_is_rejected(self, bad: float) -> None:
        with pytest.raises(ValueError):
            machine().evaluate(now=T0, score=bad)

    def test_evaluation_records_previous_and_current_score(self) -> None:
        m = machine()
        first = step(m, 0, 0.1)
        second = step(m, 1, 0.4)
        assert first.previous_score is None
        assert second.previous_score == 0.1
        assert second.score == 0.4

    def test_unchanged_evaluation_reports_not_changed(self) -> None:
        ev = step(machine(), 0, 0.0)
        assert not ev.changed and not ev.escalated

    def test_state_is_always_one_of_the_four_states(self) -> None:
        m = machine()
        for i in range(200):
            step(m, i * 3, (i * 37 % 101) / 100.0, severe=i % 17 == 0)
            assert m.state in {R, A, D, G}


class TestSnapshotAndRestore:
    def test_rollback_undoes_a_transition_and_its_timers(self) -> None:
        m = machine()
        step(m, 0, 0.30)
        snap = m.snapshot()
        assert step(m, 10, 0.30).new_state is A
        m.rollback(snap)
        assert m.state is R
        # The dwell clock is back as it was, so the transition re-derives.
        assert step(m, 10, 0.30).new_state is A

    def test_restore_resumes_a_persisted_state(self) -> None:
        m = machine()
        m.restore(D, at(5))
        assert m.state is D
        assert m.last_transition_at == at(5)
        # Resumed machines still obey cooldown from a clean timer.
        step(m, 100, 0.0)
        assert step(m, 130, 0.0).new_state is A
