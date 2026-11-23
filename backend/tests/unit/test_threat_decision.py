"""Unit tests for the Decision object and its relationship to ResponseGuard.

The decision layer only recommends. These tests check that what it recommends
is exactly what the existing, unmodified ResponseGuard would authorise for the
same state, and that every protective recommendation is a simulated action.
"""

from __future__ import annotations

import json

import pytest

from core.config import Settings
from models.enums import ActionClass, ActionType, DefenseState
from response.guard import ResponseGuard
from tests.threat_helpers import SCORING, STATE, at, auth_critical
from threat.decision import Decision, merge_reasons, recommended_actions_for
from threat.reasons import ReasonCode
from threat.scorer import ThreatScorer
from threat.state_machine import DefenseStateMachine

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)

PROTECTIVE = {
    ActionType.SIMULATE_IP_BLOCK,
    ActionType.SIMULATE_PROCESS_ISOLATE,
    ActionType.SIMULATE_QUARANTINE,
}


class TestRecommendedActions:
    def test_relaxed_without_evidence_recommends_nothing(self) -> None:
        assert recommended_actions_for(R, new_evidence=False) == ()

    def test_relaxed_with_evidence_recommends_only_an_alert(self) -> None:
        assert recommended_actions_for(R, new_evidence=True) == (ActionType.GENERATE_ALERT,)

    def test_alert_adds_monitoring(self) -> None:
        assert set(recommended_actions_for(A, new_evidence=True)) == {
            ActionType.GENERATE_ALERT,
            ActionType.INCREASE_MONITORING,
        }

    def test_incident_recording_is_recommended_only_when_a_new_situation_opens(self) -> None:
        for state in (A, D, G):
            steady = recommended_actions_for(state, new_evidence=True)
            opening = recommended_actions_for(state, new_evidence=True, record_incident=True)
            assert ActionType.RECORD_INCIDENT not in steady
            assert ActionType.RECORD_INCIDENT in opening
            assert set(opening) - set(steady) == {ActionType.RECORD_INCIDENT}

    def test_relaxed_never_recommends_an_incident(self) -> None:
        assert ActionType.RECORD_INCIDENT not in recommended_actions_for(
            R, new_evidence=True, record_incident=True
        )

    def test_the_default_is_never_to_record_an_incident(self) -> None:
        for state in (R, A, D, G):
            assert ActionType.RECORD_INCIDENT not in recommended_actions_for(
                state, new_evidence=True
            )

    def test_defensive_adds_simulated_block_and_isolation(self) -> None:
        actions = set(recommended_actions_for(D, new_evidence=True))
        assert {ActionType.SIMULATE_IP_BLOCK, ActionType.SIMULATE_PROCESS_ISOLATE} <= actions
        assert ActionType.SIMULATE_QUARANTINE not in actions

    def test_aggressive_adds_simulated_quarantine(self) -> None:
        assert ActionType.SIMULATE_QUARANTINE in recommended_actions_for(G, new_evidence=True)

    def test_recommendations_are_cumulative_and_have_no_duplicates(self) -> None:
        sets = [set(recommended_actions_for(s, new_evidence=True)) for s in (R, A, D, G)]
        assert sets[0] < sets[1] < sets[2] < sets[3]
        for s in (R, A, D, G):
            actions = recommended_actions_for(s, new_evidence=True)
            assert len(actions) == len(set(actions))

    @pytest.mark.parametrize("state", [A, D, G])
    def test_evidence_flag_does_not_change_raised_states(self, state: DefenseState) -> None:
        assert recommended_actions_for(state, new_evidence=False) == recommended_actions_for(
            state, new_evidence=True
        )


class TestAgreementWithTheUnmodifiedResponseGuard:
    """The guard stays the gate; the decision layer must stay inside what it allows."""

    @pytest.mark.parametrize("state", [R, A, D, G])
    def test_every_recommended_action_is_allowed_by_the_guard_in_that_state(
        self, state: DefenseState
    ) -> None:
        guard = ResponseGuard(settings=Settings(live_actions=False))
        for action in recommended_actions_for(state, new_evidence=True, record_incident=True):
            verdict = guard.evaluate(action, state)
            assert verdict.allowed, f"{action} not allowed at {state}: {verdict.reason}"

    @pytest.mark.parametrize("state", [R, A, D, G])
    def test_every_protective_recommendation_is_simulated(self, state: DefenseState) -> None:
        guard = ResponseGuard(settings=Settings(live_actions=False))
        for action in recommended_actions_for(state, new_evidence=True, record_incident=True):
            verdict = guard.evaluate(action, state)
            if action in PROTECTIVE:
                assert verdict.action_class is ActionClass.SIMULATED_PROTECTIVE
                assert verdict.is_simulated is True

    def test_recommendations_never_exceed_the_state_the_guard_requires(self) -> None:
        guard = ResponseGuard(settings=Settings(live_actions=False))
        for state in (R, A, D):
            higher = recommended_actions_for(G, new_evidence=True)
            not_recommended = set(higher) - set(recommended_actions_for(state, new_evidence=True))
            for action in not_recommended:
                # What we withhold at this state, the guard would also refuse.
                assert not guard.evaluate(action, state).allowed

    def test_recommendations_use_only_the_guard_vocabulary(self) -> None:
        for state in (R, A, D, G):
            for action in recommended_actions_for(state, new_evidence=True):
                assert isinstance(action, ActionType)


class TestDecisionObject:
    def _decision(self) -> Decision:
        scorer = ThreatScorer(SCORING)
        machine = DefenseStateMachine(STATE)
        scorer.observe(auth_critical(0))
        breakdown = scorer.score(at(0))
        evaluation = machine.evaluate(now=at(0), score=breakdown.final_score, floor=D, severe=True)
        return Decision(
            calculated_at=at(0),
            threat_score=breakdown.final_score,
            defense_state=evaluation.new_state,
            previous_state=evaluation.previous_state,
            state_changed=evaluation.changed,
            reason_codes=merge_reasons(breakdown.reason_codes, evaluation.reason_codes),
            recommended_actions=recommended_actions_for(evaluation.new_state, new_evidence=True),
            breakdown=breakdown,
            evaluation=evaluation,
        )

    def test_to_dict_is_json_serialisable_and_matches_the_documented_shape(self) -> None:
        d = json.loads(json.dumps(self._decision().to_dict(), allow_nan=False))
        assert 0.0 <= d["threat_score"] <= 1.0
        assert d["defense_state"] in {"RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE"}
        assert d["state_changed"] is True
        assert "CRITICAL_EVENT" in d["reason_codes"]
        assert all(a in {x.value for x in ActionType} for a in d["recommended_actions"])
        assert d["breakdown"]["final_score"] == d["threat_score"]

    def test_decision_is_immutable(self) -> None:
        decision = self._decision()
        with pytest.raises(AttributeError):
            decision.threat_score = 0.0  # type: ignore[misc]

    def test_decision_has_no_execution_surface(self) -> None:
        public = {n for n in dir(Decision) if not n.startswith("_")}
        assert not {n for n in public if n in {"execute", "run", "apply", "block", "kill"}}


class TestMergeReasons:
    def test_keeps_first_occurrence_order_and_removes_duplicates(self) -> None:
        a = (ReasonCode.CRITICAL_EVENT, ReasonCode.REPEATED_ACTIVITY)
        b = (ReasonCode.REPEATED_ACTIVITY, ReasonCode.DWELL_SATISFIED)
        assert merge_reasons(a, b) == (
            ReasonCode.CRITICAL_EVENT,
            ReasonCode.REPEATED_ACTIVITY,
            ReasonCode.DWELL_SATISFIED,
        )

    def test_empty(self) -> None:
        assert merge_reasons() == ()
