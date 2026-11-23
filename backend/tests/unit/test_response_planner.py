"""Unit tests for ResponsePlanner: scopes, dedup keys, idempotency keys, preconditions."""

from __future__ import annotations

import pytest

from models.enums import ActionType
from response.actions import Scope
from response.planner import ALLOWED_WITHOUT_SITUATION, POLICIES, ResponsePlanner
from tests.response_helpers import A, D, G, R, decision
from tests.threat_helpers import at
from threat.reasons import ReasonCode

PLANNER = ResponsePlanner()


def plan_for(**kwargs: object):  # type: ignore[no-untyped-def]
    return {e.action.action_type: e for e in PLANNER.plan(decision(**kwargs))}  # type: ignore[arg-type]


class TestPolicies:
    def test_every_action_type_has_a_policy(self) -> None:
        assert set(POLICIES) == set(ActionType)

    def test_protective_simulations_and_incidents_are_once_per_situation(self) -> None:
        for action in (
            ActionType.RECORD_INCIDENT,
            ActionType.SIMULATE_IP_BLOCK,
            ActionType.SIMULATE_PROCESS_ISOLATE,
            ActionType.SIMULATE_QUARANTINE,
        ):
            assert POLICIES[action] is Scope.PER_SITUATION

    def test_alerts_and_monitoring_are_once_per_state(self) -> None:
        assert POLICIES[ActionType.GENERATE_ALERT] is Scope.PER_SITUATION_STATE
        assert POLICIES[ActionType.INCREASE_MONITORING] is Scope.PER_SITUATION_STATE

    def test_only_alerts_may_happen_outside_a_situation(self) -> None:
        assert ALLOWED_WITHOUT_SITUATION == {ActionType.GENERATE_ALERT}


class TestKeys:
    def test_per_situation_keys_ignore_the_state(self) -> None:
        defensive = plan_for(t=0, state=D, situation_id=4)
        aggressive = plan_for(t=5, state=G, situation_id=4)
        key = "s4:SIMULATE_IP_BLOCK"
        assert defensive[ActionType.SIMULATE_IP_BLOCK].action.scope_key == key
        assert aggressive[ActionType.SIMULATE_IP_BLOCK].action.scope_key == key
        assert defensive[ActionType.SIMULATE_IP_BLOCK].action.once_key == key

    def test_per_state_keys_include_the_state(self) -> None:
        alert = plan_for(t=0, state=A, situation_id=4)[ActionType.GENERATE_ALERT].action
        defensive = plan_for(t=0, state=D, situation_id=4)[ActionType.GENERATE_ALERT].action
        assert alert.scope_key == "s4:GENERATE_ALERT:ALERT"
        assert defensive.scope_key == "s4:GENERATE_ALERT:DEFENSIVE"
        assert alert.once_key == alert.scope_key

    def test_different_situations_never_share_a_key(self) -> None:
        a = plan_for(t=0, state=D, situation_id=1)[ActionType.SIMULATE_IP_BLOCK].action
        b = plan_for(t=0, state=D, situation_id=2)[ActionType.SIMULATE_IP_BLOCK].action
        assert a.scope_key != b.scope_key
        assert a.once_key != b.once_key

    def test_idempotency_key_identifies_the_scope_and_the_decision(self) -> None:
        first = plan_for(t=0, state=D, situation_id=1)[ActionType.SIMULATE_IP_BLOCK].action
        again = plan_for(t=0, state=D, situation_id=1)[ActionType.SIMULATE_IP_BLOCK].action
        later = plan_for(t=5, state=D, situation_id=1)[ActionType.SIMULATE_IP_BLOCK].action
        assert first.idempotency_key == again.idempotency_key
        assert first.idempotency_key != later.idempotency_key
        assert first.idempotency_key == f"s1:SIMULATE_IP_BLOCK@{at(0).isoformat()}"

    def test_relaxed_alerts_use_the_cooldown_scope_without_a_once_key(self) -> None:
        entry = plan_for(t=0, state=R, situation_id=None)[ActionType.GENERATE_ALERT]
        assert entry.action.scope is Scope.COOLDOWN
        assert entry.action.scope_key == "global:GENERATE_ALERT"
        assert entry.action.once_key is None
        assert entry.precondition_error is None


class TestPreconditions:
    @pytest.mark.parametrize(
        "action",
        [
            ActionType.RECORD_INCIDENT,
            ActionType.SIMULATE_IP_BLOCK,
            ActionType.SIMULATE_PROCESS_ISOLATE,
            ActionType.SIMULATE_QUARANTINE,
            ActionType.INCREASE_MONITORING,
        ],
    )
    def test_situation_scoped_actions_without_a_situation_are_planned_to_be_blocked(
        self, action: ActionType
    ) -> None:
        entry = plan_for(t=0, state=G, situation_id=None, actions=[action])[action]
        assert entry.precondition_error is not None
        assert "requires a security situation" in entry.precondition_error
        assert entry.action.once_key is None

    def test_an_action_without_a_policy_is_planned_to_be_blocked(self) -> None:
        planner = ResponsePlanner(policies={})
        (entry,) = planner.plan(
            decision(0, D, situation_id=1, actions=[ActionType.SIMULATE_IP_BLOCK])
        )
        assert entry.precondition_error is not None


class TestContent:
    def test_plan_follows_the_recommendations_in_order(self) -> None:
        d = decision(0, D, situation_id=1)
        assert [e.action.action_type for e in PLANNER.plan(d)] == list(d.recommended_actions)

    def test_nothing_is_planned_when_nothing_is_recommended(self) -> None:
        assert PLANNER.plan(decision(0, R, actions=[])) == []

    def test_triggering_event_is_the_strongest_signal(self) -> None:
        entry = plan_for(t=0, state=D, situation_id=1, event_ids=[11, 12])[
            ActionType.SIMULATE_IP_BLOCK
        ]
        assert entry.action.triggering_event_id == 11
        assert entry.action.evidence_event_ids == (11, 12)

    def test_no_signal_means_no_triggering_event(self) -> None:
        entry = plan_for(t=0, state=D, situation_id=1)[ActionType.SIMULATE_IP_BLOCK]
        assert entry.action.triggering_event_id is None

    def test_plan_carries_the_decision_facts(self) -> None:
        d = decision(7, G, situation_id=3, score=0.91, reasons=(ReasonCode.CRITICAL_EVENT,))
        (entry, *_) = PLANNER.plan(d)
        assert entry.action.planned_at == at(7)
        assert entry.action.defense_state is G
        assert entry.action.threat_score == 0.91
        assert entry.action.reason_codes == ("CRITICAL_EVENT",)

    def test_planning_is_deterministic(self) -> None:
        d = decision(0, G, situation_id=9, event_ids=[1], new_situation=True)
        assert PLANNER.plan(d) == PLANNER.plan(d)
