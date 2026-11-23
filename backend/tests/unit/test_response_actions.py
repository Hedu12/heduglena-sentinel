"""Unit tests for response action models: lifecycle validation and results."""

from __future__ import annotations

import json

import pytest

from models.enums import ActionStatus, ActionType, DefenseState
from response.actions import (
    TERMINAL_STATUSES,
    ActionLifecycle,
    ActionOutcome,
    LifecycleError,
    PlannedAction,
    ResponseResult,
    Scope,
    SkipReason,
)
from tests.threat_helpers import at

P, AU, EX, OK, FA, BL = (
    ActionStatus.PLANNED,
    ActionStatus.AUTHORIZED,
    ActionStatus.EXECUTING,
    ActionStatus.SUCCEEDED,
    ActionStatus.FAILED,
    ActionStatus.BLOCKED,
)


def planned(action: ActionType = ActionType.SIMULATE_IP_BLOCK) -> PlannedAction:
    return PlannedAction(
        action_type=action,
        defense_state=DefenseState.DEFENSIVE,
        planned_at=at(0),
        situation_id=1,
        scope=Scope.PER_SITUATION,
        scope_key=f"s1:{action.value}",
        once_key=f"s1:{action.value}",
        idempotency_key=f"s1:{action.value}@x",
        triggering_event_id=7,
        threat_score=0.6,
        reason_codes=("CRITICAL_EVENT",),
    )


class TestLifecycle:
    @pytest.mark.parametrize(
        "path",
        [
            [AU, EX, OK],
            [AU, EX, FA],
            [BL],
            [AU, BL],
        ],
    )
    def test_legal_paths_reach_a_terminal_status(self, path: list[ActionStatus]) -> None:
        life = ActionLifecycle.planned(at(0))
        for status in path:
            life.advance(status, at(0))
        assert life.is_terminal
        assert life.status is path[-1]
        assert [s.status for s in life.steps] == [P, *path]

    @pytest.mark.parametrize(
        ("path", "illegal"),
        [
            ([], OK),  # cannot succeed without being authorised and executed
            ([], EX),
            ([], FA),
            ([AU], OK),  # cannot succeed without executing
            ([AU], FA),
            ([AU, EX], BL),  # once executing, it either succeeds or fails
            ([AU, EX, OK], FA),  # terminal statuses are final
            ([BL], AU),
            ([AU, EX, FA], OK),
        ],
    )
    def test_illegal_transitions_are_rejected(
        self, path: list[ActionStatus], illegal: ActionStatus
    ) -> None:
        life = ActionLifecycle.planned(at(0))
        for status in path:
            life.advance(status, at(0))
        with pytest.raises(LifecycleError):
            life.advance(illegal, at(0))

    def test_terminal_statuses(self) -> None:
        assert TERMINAL_STATUSES == {OK, FA, BL}
        assert not ActionLifecycle.planned(at(0)).is_terminal

    def test_lifecycle_serialises_with_times_and_details(self) -> None:
        life = ActionLifecycle.planned(at(0), "PER_SITUATION")
        life.advance(AU, at(0), "Authorized")
        steps = json.loads(life.to_json())
        assert [s["status"] for s in steps] == ["PLANNED", "AUTHORIZED"]
        assert steps[1]["detail"] == "Authorized"
        assert steps[0]["at"] == at(0).isoformat()


class TestPlannedAction:
    def test_parameters_are_structured_and_contain_no_free_text(self) -> None:
        params = planned().parameters()
        assert params == {
            "situation_id": 1,
            "scope": "PER_SITUATION",
            "threat_score": 0.6,
            "reason_codes": ["CRITICAL_EVENT"],
            "triggering_event_id": 7,
        }
        json.dumps(params)

    def test_planned_action_is_immutable(self) -> None:
        with pytest.raises(AttributeError):
            planned().situation_id = 2  # type: ignore[misc]


class TestOutcomesAndResults:
    def test_outcome_flags(self) -> None:
        done = ActionOutcome(planned(), status=OK, record_id=3)
        skipped = ActionOutcome(planned(), skip_reason=SkipReason.DUPLICATE)
        assert done.recorded and done.succeeded
        assert not skipped.recorded and not skipped.succeeded

    def test_result_is_incomplete_only_when_a_record_could_not_be_saved(self) -> None:
        ok = ResponseResult(at(0), 1, (ActionOutcome(planned(), status=OK, record_id=1),))
        skipped = ResponseResult(
            at(0), 1, (ActionOutcome(planned(), skip_reason=SkipReason.COOLDOWN),)
        )
        lost = ResponseResult(
            at(0), 1, (ActionOutcome(planned(), skip_reason=SkipReason.PERSIST_FAILED),)
        )
        assert ok.complete and skipped.complete
        assert not lost.complete

    def test_by_action_indexes_outcomes(self) -> None:
        outcome = ActionOutcome(planned(), status=OK, record_id=1)
        result = ResponseResult(at(0), 1, (outcome,))
        assert result.by_action() == {ActionType.SIMULATE_IP_BLOCK: outcome}
