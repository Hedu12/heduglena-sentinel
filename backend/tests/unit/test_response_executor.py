"""Unit tests for SimulatedActionExecutor and its refusal to execute anything live."""

from __future__ import annotations

import pytest

from core.config import Settings
from models.enums import ActionClass, ActionType, DefenseState
from response.actions import PlannedAction, Scope
from response.executor import (
    DEFAULT_HANDLERS,
    LIVE_EXECUTION_SUPPORTED,
    LiveExecutionRefused,
    SimulatedActionExecutor,
    SimulationResult,
)
from response.guard import GuardVerdict, ResponseGuard
from tests.threat_helpers import at

EXECUTOR = SimulatedActionExecutor()


def planned(
    action: ActionType,
    *,
    situation_id: int | None = 5,
    state: DefenseState = DefenseState.AGGRESSIVE,
) -> PlannedAction:
    return PlannedAction(
        action_type=action,
        defense_state=state,
        planned_at=at(0),
        situation_id=situation_id,
        scope=Scope.PER_SITUATION,
        scope_key=f"s{situation_id}:{action.value}",
        once_key=None,
        idempotency_key="k",
        triggering_event_id=None,
        threat_score=0.87,
        reason_codes=("CRITICAL_EVENT", "CROSS_SIGNAL_CORRELATION"),
        evidence_event_ids=(3, 4),
    )


def verdict_for(action: ActionType, state: DefenseState = DefenseState.AGGRESSIVE) -> GuardVerdict:
    return ResponseGuard(settings=Settings()).evaluate(action, state, cooldown_seconds=0.0)


class TestCoverage:
    def test_live_execution_is_not_supported(self) -> None:
        assert LIVE_EXECUTION_SUPPORTED is False

    def test_every_action_type_has_a_simulated_handler(self) -> None:
        assert set(DEFAULT_HANDLERS) == set(ActionType)

    def test_a_handler_table_missing_an_action_is_rejected(self) -> None:
        partial = {
            k: v for k, v in DEFAULT_HANDLERS.items() if k is not ActionType.SIMULATE_QUARANTINE
        }
        with pytest.raises(ValueError, match="SIMULATE_QUARANTINE"):
            SimulatedActionExecutor(partial)


class TestSimulation:
    @pytest.mark.parametrize("action", list(ActionType))
    def test_every_action_simulates_and_describes_itself(self, action: ActionType) -> None:
        result = EXECUTOR.execute(planned(action), verdict_for(action))
        assert isinstance(result, SimulationResult)
        assert result.result
        assert result.dry_run_description
        assert "situation 5" in result.dry_run_description

    @pytest.mark.parametrize(
        "action",
        [
            ActionType.SIMULATE_IP_BLOCK,
            ActionType.SIMULATE_PROCESS_ISOLATE,
            ActionType.SIMULATE_QUARANTINE,
        ],
    )
    def test_protective_actions_say_they_made_no_host_change(self, action: ActionType) -> None:
        result = EXECUTOR.execute(planned(action), verdict_for(action))
        assert result.result == "simulated: no host change made"
        assert "Simulation only" in result.dry_run_description
        assert result.incident is None

    def test_monitoring_change_is_only_recommended(self) -> None:
        result = EXECUTOR.execute(
            planned(ActionType.INCREASE_MONITORING), verdict_for(ActionType.INCREASE_MONITORING)
        )
        assert "not changed" in result.dry_run_description

    def test_record_incident_specifies_a_stable_incident_for_the_situation(self) -> None:
        result = EXECUTOR.execute(
            planned(ActionType.RECORD_INCIDENT), verdict_for(ActionType.RECORD_INCIDENT)
        )
        assert result.incident is not None
        assert result.incident.incident_id == "SIT-5"
        assert result.incident.event_ids == (3, 4)
        assert result.incident.threat_score == 0.87
        assert "critical-severity" in result.incident.summary

    def test_record_incident_without_a_situation_fails(self) -> None:
        with pytest.raises(ValueError):
            EXECUTOR.execute(
                planned(ActionType.RECORD_INCIDENT, situation_id=None),
                verdict_for(ActionType.RECORD_INCIDENT),
            )

    @pytest.mark.parametrize("action", list(ActionType))
    def test_simulation_is_pure(self, action: ActionType) -> None:
        p, v = planned(action), verdict_for(action)
        assert EXECUTOR.execute(p, v) == EXECUTOR.execute(p, v)


class TestSimulationResultIsExplicit:
    EXPECTED_OUTCOMES = {
        ActionType.GENERATE_ALERT: "WOULD_ALERT_OPERATOR",
        ActionType.INCREASE_MONITORING: "WOULD_INCREASE_MONITORING",
        ActionType.RECORD_INCIDENT: "INCIDENT_RECORDED",
        ActionType.SIMULATE_IP_BLOCK: "WOULD_BLOCK_SOURCE",
        ActionType.SIMULATE_PROCESS_ISOLATE: "WOULD_CONTAIN_PROCESS",
        ActionType.SIMULATE_QUARANTINE: "WOULD_QUARANTINE",
    }

    @pytest.mark.parametrize("action", list(ActionType))
    def test_every_result_is_simulated_with_no_side_effects(self, action: ActionType) -> None:
        result = EXECUTOR.execute(planned(action), verdict_for(action))
        assert result.simulated is True
        assert result.side_effects == ()
        assert result.outcome == self.EXPECTED_OUTCOMES[action]
        assert result.target

    def test_outcome_table_covers_every_action(self) -> None:
        assert set(self.EXPECTED_OUTCOMES) == set(ActionType)

    def test_a_non_simulated_result_cannot_be_constructed(self) -> None:
        with pytest.raises(ValueError):
            SimulationResult(
                result="r", dry_run_description="d", outcome="o", target="t", simulated=False
            )

    def test_a_result_with_side_effects_cannot_be_constructed(self) -> None:
        with pytest.raises(ValueError):
            SimulationResult(
                result="r", dry_run_description="d", outcome="o", target="t", side_effects=("fw",)
            )


class TestLiveExecutionIsRefused:
    def test_a_live_protective_verdict_is_refused_even_when_allowed(self) -> None:
        live = GuardVerdict(
            allowed=True,
            is_simulated=False,
            reason="Authorized",
            action_class=ActionClass.LIVE_PROTECTIVE,
        )
        with pytest.raises(LiveExecutionRefused):
            EXECUTOR.execute(planned(ActionType.SIMULATE_IP_BLOCK), live)

    def test_a_non_simulated_verdict_of_any_class_is_refused(self) -> None:
        for action_class in ActionClass:
            verdict = GuardVerdict(
                allowed=True, is_simulated=False, reason="x", action_class=action_class
            )
            with pytest.raises(LiveExecutionRefused):
                EXECUTOR.ensure_simulated(verdict)

    def test_a_simulated_live_protective_verdict_is_still_refused(self) -> None:
        verdict = GuardVerdict(
            allowed=True, is_simulated=True, reason="x", action_class=ActionClass.LIVE_PROTECTIVE
        )
        with pytest.raises(LiveExecutionRefused):
            EXECUTOR.ensure_simulated(verdict)

    @pytest.mark.parametrize("action", list(ActionType))
    def test_real_guard_verdicts_are_simulated_even_with_live_actions_enabled(
        self, action: ActionType
    ) -> None:
        guard = ResponseGuard(settings=Settings(live_actions=True))
        verdict = guard.evaluate(action, DefenseState.AGGRESSIVE, cooldown_seconds=0.0)
        EXECUTOR.ensure_simulated(verdict)  # must not raise: no live action type exists
