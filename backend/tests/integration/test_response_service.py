"""
Integration tests for ResponseService against a real (in-memory) database.

Covers: ResponseGuard authority, idempotency, deduplication by situation_id,
cooldowns, lifecycle records, failure and rollback, races, cancellation, and the
refusal to execute anything live.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import Settings
from database.repositories import (
    DetectionEventRepository,
    IncidentRepository,
    ResponseActionRepository,
)
from models.enums import ActionClass, ActionStatus, ActionType, DefenseState
from response.actions import PlannedAction, SkipReason
from response.executor import DEFAULT_HANDLERS, SimulatedActionExecutor, SimulationResult
from response.guard import GuardVerdict, ResponseGuard
from response.service import GUARD_COOLDOWN_SECONDS, ResponseService
from tests.response_helpers import (
    A,
    D,
    G,
    R,
    actions,
    database,
    decision,
    incidents,
    persisted_event,
)

BLOCK = ActionType.SIMULATE_IP_BLOCK
SETTINGS = Settings()


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with database() as f:
        yield f


@dataclass
class SpyGuard:
    """Delegates to the real, unmodified ResponseGuard and records every call."""

    real: ResponseGuard = field(default_factory=lambda: ResponseGuard(settings=SETTINGS))
    evaluations: list[tuple[ActionType, DefenseState, float]] = field(default_factory=list)
    fired: list[ActionType] = field(default_factory=list)
    override: GuardVerdict | None = None

    def evaluate(
        self, action: ActionType, current_state: DefenseState, cooldown_seconds: float = 60.0
    ) -> GuardVerdict:
        self.evaluations.append((action, current_state, cooldown_seconds))
        if self.override is not None:
            return self.override
        return self.real.evaluate(action, current_state, cooldown_seconds)

    def record_fired(self, action: ActionType) -> None:
        self.fired.append(action)
        self.real.record_fired(action)


def service(
    factory: async_sessionmaker[AsyncSession],
    *,
    guard: Any = None,
    executor: SimulatedActionExecutor | None = None,
    settings: Settings = SETTINGS,
) -> ResponseService:
    return ResponseService(settings, factory, guard=guard, executor=executor)


def failing_executor(*failing: ActionType) -> SimulatedActionExecutor:
    def boom(_p: PlannedAction) -> SimulationResult:
        raise RuntimeError("simulated handler crashed with details that must not be stored")

    handlers = {k: (boom if k in failing else v) for k, v in DEFAULT_HANDLERS.items()}
    return SimulatedActionExecutor(handlers)


def statuses(rows: list[Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in rows:
        out.setdefault(row.action_type, []).append(row.status)
    return out


class TestHappyPath:
    async def test_a_new_situation_runs_every_recommended_action_once(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        event = await persisted_event(factory)
        result = await service(factory).handle(
            decision(0, D, situation_id=1, previous=R, new_situation=True, event_ids=[event])
        )
        assert result.complete
        assert {o.planned.action_type for o in result.outcomes} == {
            ActionType.GENERATE_ALERT,
            ActionType.INCREASE_MONITORING,
            ActionType.RECORD_INCIDENT,
            ActionType.SIMULATE_IP_BLOCK,
            ActionType.SIMULATE_PROCESS_ISOLATE,
        }
        assert all(o.status is ActionStatus.SUCCEEDED for o in result.outcomes)
        rows = await actions(factory)
        assert len(rows) == 5
        assert all(r.status == "SUCCEEDED" for r in rows)
        assert all(r.is_simulated is True for r in rows)
        assert all(r.situation_id == 1 for r in rows)
        assert all(r.triggering_event_id == event for r in rows)

    async def test_the_record_is_a_complete_audit_entry(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await service(factory).handle(decision(3, D, situation_id=1, actions=[BLOCK]))
        (row,) = await actions(factory)
        assert row.action_type == "SIMULATE_IP_BLOCK"
        assert row.defense_state == "DEFENSIVE"
        assert row.executed_at.replace(tzinfo=None) == decision(3, D).calculated_at.replace(
            tzinfo=None
        )
        assert row.action_class == "SIMULATED_PROTECTIVE"
        assert row.guard_reason == "Authorized"
        assert row.scope_key == row.once_key == "s1:SIMULATE_IP_BLOCK"
        assert row.idempotency_key.startswith("s1:SIMULATE_IP_BLOCK@")
        assert row.result == "simulated: no host change made"
        assert "Simulation only" in row.dry_run_description
        assert json.loads(row.parameters)["situation_id"] == 1
        assert [s["status"] for s in json.loads(row.lifecycle)] == [
            "PLANNED",
            "AUTHORIZED",
            "EXECUTING",
            "SUCCEEDED",
        ]

    async def test_record_incident_creates_exactly_one_incident_for_the_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        event = await persisted_event(factory)
        first = await svc.handle(
            decision(0, A, situation_id=7, actions=[ActionType.RECORD_INCIDENT], event_ids=[event])
        )
        again = await svc.handle(
            decision(5, D, situation_id=7, actions=[ActionType.RECORD_INCIDENT], event_ids=[event])
        )
        assert first.outcomes[0].incident_id == "SIT-7"
        assert again.outcomes[0].skip_reason is SkipReason.DUPLICATE
        (incident,) = await incidents(factory)
        assert incident.incident_id == "SIT-7"
        assert incident.status == "open"
        assert incident.defense_state == "ALERT"
        assert json.loads(incident.event_ids) == [event]
        assert incident.summary


class TestGuardAuthority:
    async def test_every_action_is_evaluated_by_the_guard(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        spy = SpyGuard()
        await service(factory, guard=spy).handle(decision(0, G, situation_id=1, new_situation=True))
        evaluated = [a for a, _, _ in spy.evaluations]
        assert set(evaluated) == set(ActionType)
        assert all(state is G for _, state, _ in spy.evaluations)
        assert all(cd == GUARD_COOLDOWN_SECONDS == 0.0 for _, _, cd in spy.evaluations)

    async def test_an_action_the_guard_refuses_is_blocked_and_never_executed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        executor = failing_executor(BLOCK)  # would fail loudly if it were ever executed
        result = await service(factory, executor=executor).handle(
            decision(0, A, situation_id=1, actions=[BLOCK])  # needs DEFENSIVE
        )
        assert result.outcomes[0].status is ActionStatus.BLOCKED
        (row,) = await actions(factory)
        assert row.status == "BLOCKED"
        assert "requires state" in row.guard_reason
        assert [s["status"] for s in json.loads(row.lifecycle)] == ["PLANNED", "BLOCKED"]
        assert row.result == row.guard_reason  # the refusal reason, not a simulation result
        assert row.dry_run_description.startswith("Not executed:")
        assert row.action_class == "SIMULATED_PROTECTIVE"

    async def test_record_fired_is_reported_to_the_guard_only_after_a_success(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        spy = SpyGuard()
        svc = service(
            factory, guard=spy, executor=failing_executor(ActionType.SIMULATE_PROCESS_ISOLATE)
        )
        await svc.handle(
            decision(
                0,
                D,
                situation_id=1,
                actions=[
                    BLOCK,
                    ActionType.SIMULATE_PROCESS_ISOLATE,
                    ActionType.SIMULATE_QUARANTINE,
                ],
            )
        )
        assert spy.fired == [BLOCK]  # isolate FAILED, quarantine BLOCKED (needs AGGRESSIVE)

    async def test_the_guards_wall_clock_cooldown_never_affects_responses(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Two situations, handled back to back in real time. With the guard's default
        # 60 s wall-clock cooldown the second block would be refused.
        svc = service(factory)
        await svc.handle(decision(0, D, situation_id=1, actions=[BLOCK]))
        second = await svc.handle(decision(1, D, situation_id=2, actions=[BLOCK]))
        assert second.outcomes[0].status is ActionStatus.SUCCEEDED


class TestIdempotency:
    async def test_handling_the_same_decision_twice_records_nothing_new(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        d = decision(0, G, situation_id=1, new_situation=True)
        first = await svc.handle(d)
        second = await svc.handle(d)
        assert all(o.recorded for o in first.outcomes)
        assert all(o.skip_reason is SkipReason.ALREADY_PROCESSED for o in second.outcomes)
        assert [o.record_id for o in second.outcomes] == [o.record_id for o in first.outcomes]
        assert len(await actions(factory)) == len(first.outcomes)
        assert len(await incidents(factory)) == 1

    async def test_a_new_service_instance_is_still_idempotent(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        d = decision(0, D, situation_id=1, new_situation=True)
        await service(factory).handle(d)
        restarted = await service(factory).handle(d)  # e.g. after a restart
        assert all(o.skip_reason is SkipReason.ALREADY_PROCESSED for o in restarted.outcomes)
        assert len(await incidents(factory)) == 1

    async def test_a_lost_race_is_classified_as_already_processed(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = decision(0, D, situation_id=1, actions=[BLOCK])
        await service(factory).handle(d)
        # Simulate a concurrent writer: the pre-check misses the row, the insert collides.
        real = ResponseActionRepository.get_by_idempotency_key
        calls = {"n": 0}

        async def stale_once(self: ResponseActionRepository, key: str) -> Any:
            calls["n"] += 1
            return None if calls["n"] == 1 else await real(self, key)

        async def no_success(self: ResponseActionRepository, key: str) -> bool:
            return False

        monkeypatch.setattr(ResponseActionRepository, "get_by_idempotency_key", stale_once)
        monkeypatch.setattr(ResponseActionRepository, "has_success", no_success)
        result = await service(factory).handle(d)
        assert result.outcomes[0].skip_reason is SkipReason.ALREADY_PROCESSED
        assert len(await actions(factory)) == 1


class TestDeduplicationBySituation:
    async def test_protective_actions_run_once_per_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        for t in range(0, 300, 5):
            await svc.handle(decision(t, G, situation_id=1))
        counts = statuses(await actions(factory))
        for action in (BLOCK, ActionType.SIMULATE_PROCESS_ISOLATE, ActionType.SIMULATE_QUARANTINE):
            assert counts[action.value] == ["SUCCEEDED"]

    async def test_alerts_and_monitoring_run_once_per_state_entered(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        path = [(0, A), (5, A), (10, D), (15, D), (20, G), (60, D), (100, A), (105, A)]
        for t, state in path:
            await svc.handle(decision(t, state, situation_id=1))
        rows = await actions(factory)
        alerts = [r.scope_key for r in rows if r.action_type == "GENERATE_ALERT"]
        monitoring = [r.scope_key for r in rows if r.action_type == "INCREASE_MONITORING"]
        expected = ["s1:{a}:ALERT", "s1:{a}:DEFENSIVE", "s1:{a}:AGGRESSIVE"]
        assert alerts == [k.format(a="GENERATE_ALERT") for k in expected]
        assert monitoring == [k.format(a="INCREASE_MONITORING") for k in expected]

    async def test_a_new_situation_gets_its_own_actions(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.handle(decision(0, D, situation_id=1, new_situation=True))
        await svc.handle(decision(900, D, situation_id=2, new_situation=True))
        rows = await actions(factory)
        assert {r.situation_id for r in rows} == {1, 2}
        assert [i.incident_id for i in await incidents(factory)] == ["SIT-1", "SIT-2"]
        assert statuses(rows)[BLOCK.value] == ["SUCCEEDED", "SUCCEEDED"]


class TestCooldown:
    async def test_a_failed_action_is_retried_only_after_the_retry_cooldown(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        broken = service(factory, executor=failing_executor(BLOCK))
        first = await broken.handle(decision(0, D, situation_id=1, actions=[BLOCK]))
        too_soon = await broken.handle(decision(29, D, situation_id=1, actions=[BLOCK]))
        fixed = service(factory)
        retried = await fixed.handle(decision(30, D, situation_id=1, actions=[BLOCK]))
        after = await fixed.handle(decision(60, D, situation_id=1, actions=[BLOCK]))

        assert first.outcomes[0].status is ActionStatus.FAILED
        assert too_soon.outcomes[0].skip_reason is SkipReason.COOLDOWN
        assert retried.outcomes[0].status is ActionStatus.SUCCEEDED
        assert after.outcomes[0].skip_reason is SkipReason.DUPLICATE
        assert statuses(await actions(factory))[BLOCK.value] == ["FAILED", "SUCCEEDED"]

    async def test_a_blocked_action_is_retried_after_the_cooldown_when_allowed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        blocked = await svc.handle(decision(0, A, situation_id=1, actions=[BLOCK]))
        cooling = await svc.handle(decision(10, D, situation_id=1, actions=[BLOCK]))
        allowed = await svc.handle(decision(30, D, situation_id=1, actions=[BLOCK]))
        assert blocked.outcomes[0].status is ActionStatus.BLOCKED
        assert cooling.outcomes[0].skip_reason is SkipReason.COOLDOWN
        assert allowed.outcomes[0].status is ActionStatus.SUCCEEDED

    async def test_alerts_outside_a_situation_are_rate_limited(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        outcomes = []
        for t in range(0, 181, 10):
            result = await svc.handle(
                decision(t, R, situation_id=None, actions=[ActionType.GENERATE_ALERT])
            )
            outcomes.append((t, result.outcomes[0]))
        sent = [t for t, o in outcomes if o.succeeded]
        assert sent == [0, 60, 120, 180]
        assert all(o.skip_reason is SkipReason.COOLDOWN for t, o in outcomes if t not in sent)

    async def test_out_of_order_decisions_are_judged_as_if_in_order(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Regression: the cooldown used to compare against the latest attempt only, so
        # an older decision redelivered later (negative elapsed time) bypassed it.
        svc = service(factory)
        alert = [ActionType.GENERATE_ALERT]
        in_order = [await svc.handle(decision(t, R, actions=alert)) for t in (0, 30, 60, 90)]
        redelivered = [await svc.handle(decision(t, R, actions=alert)) for t in (30, 90, 0, 60)]
        assert [r.outcomes[0].succeeded for r in in_order] == [True, False, True, False]
        assert all(not r.outcomes[0].succeeded for r in redelivered)
        assert len(await actions(factory)) == 2

    async def test_a_late_arriving_decision_is_suppressed_by_a_later_alert(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        alert = [ActionType.GENERATE_ALERT]
        await svc.handle(decision(100, R, actions=alert))
        late = await svc.handle(decision(70, R, actions=alert))  # 30 s before the sent alert
        early_enough = await svc.handle(decision(40, R, actions=alert))  # 60 s before it
        assert late.outcomes[0].skip_reason is SkipReason.COOLDOWN
        assert early_enough.outcomes[0].succeeded

    async def test_cooldown_is_measured_on_decision_time_not_the_wall_clock(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Real time barely advances here, yet decision time does: the retry is allowed.
        broken = service(factory, executor=failing_executor(BLOCK))
        await broken.handle(decision(0, D, situation_id=1, actions=[BLOCK]))
        later = await service(factory).handle(decision(10_000, D, situation_id=1, actions=[BLOCK]))
        assert later.outcomes[0].status is ActionStatus.SUCCEEDED


class TestPreconditions:
    async def test_a_missing_triggering_event_blocks_the_action(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        result = await service(factory).handle(
            decision(0, D, situation_id=1, actions=[BLOCK], event_ids=[999])
        )
        assert result.outcomes[0].status is ActionStatus.BLOCKED
        (row,) = await actions(factory)
        assert "999 not found" in row.guard_reason
        assert row.action_class is None  # never reached the guard

    async def test_situation_scoped_actions_without_a_situation_are_blocked(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        spy = SpyGuard()
        result = await service(factory, guard=spy).handle(
            decision(0, G, situation_id=None, actions=[BLOCK, ActionType.RECORD_INCIDENT])
        )
        assert [o.status for o in result.outcomes] == [ActionStatus.BLOCKED, ActionStatus.BLOCKED]
        assert spy.evaluations == []  # blocked before the guard, never executed
        assert await incidents(factory) == []


class TestFailureAndRollback:
    async def test_a_simulation_failure_is_recorded_without_exception_details(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await service(factory, executor=failing_executor(BLOCK)).handle(
            decision(0, D, situation_id=1, actions=[BLOCK])
        )
        (row,) = await actions(factory)
        assert row.status == "FAILED"
        assert row.result == "simulation failed: RuntimeError"
        assert "details that must not be stored" not in (row.result + row.lifecycle)
        assert [s["status"] for s in json.loads(row.lifecycle)] == [
            "PLANNED",
            "AUTHORIZED",
            "EXECUTING",
            "FAILED",
        ]

    async def test_one_failing_action_does_not_stop_the_others(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, executor=failing_executor(ActionType.SIMULATE_PROCESS_ISOLATE))
        await svc.handle(decision(0, D, situation_id=1, new_situation=True))
        counts = statuses(await actions(factory))
        assert counts["SIMULATE_PROCESS_ISOLATE"] == ["FAILED"]
        assert counts["SIMULATE_IP_BLOCK"] == ["SUCCEEDED"]
        assert counts["RECORD_INCIDENT"] == ["SUCCEEDED"]

    async def test_a_write_failure_saves_nothing_and_reports_it(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken_insert(self: ResponseActionRepository, action: Any) -> Any:
            raise RuntimeError("disk full")

        monkeypatch.setattr(ResponseActionRepository, "insert", broken_insert)
        spy = SpyGuard()
        result = await service(factory, guard=spy).handle(
            decision(0, D, situation_id=1, new_situation=True)
        )
        assert not result.complete
        assert all(o.skip_reason is SkipReason.PERSIST_FAILED for o in result.outcomes)
        assert await actions(factory) == []
        assert await incidents(factory) == []  # the incident insert was rolled back too
        assert spy.fired == []

    async def test_a_partial_write_failure_is_repaired_by_resubmitting_the_decision(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_insert = ResponseActionRepository.insert

        async def fail_isolate(self: ResponseActionRepository, action: Any) -> Any:
            if action.action_type == "SIMULATE_PROCESS_ISOLATE":
                raise RuntimeError("transient write failure")
            return await real_insert(self, action)

        d = decision(0, D, situation_id=1, new_situation=True)
        monkeypatch.setattr(ResponseActionRepository, "insert", fail_isolate)
        first = await service(factory).handle(d)
        monkeypatch.setattr(ResponseActionRepository, "insert", real_insert)
        retry = await service(factory).handle(d)

        by_first = first.by_action()
        by_retry = retry.by_action()
        assert (
            by_first[ActionType.SIMULATE_PROCESS_ISOLATE].skip_reason is SkipReason.PERSIST_FAILED
        )
        assert by_retry[ActionType.SIMULATE_PROCESS_ISOLATE].status is ActionStatus.SUCCEEDED
        for action in (ActionType.SIMULATE_IP_BLOCK, ActionType.RECORD_INCIDENT):
            assert by_retry[action].skip_reason is SkipReason.ALREADY_PROCESSED
        counts = statuses(await actions(factory))
        assert all(v == ["SUCCEEDED"] for v in counts.values())
        assert len(await incidents(factory)) == 1

    async def test_cancellation_propagates_and_leaves_nothing_behind(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def cancelled(self: ResponseActionRepository, action: Any) -> Any:
            raise asyncio.CancelledError

        monkeypatch.setattr(ResponseActionRepository, "insert", cancelled)
        with pytest.raises(asyncio.CancelledError):
            await service(factory).handle(
                decision(0, D, situation_id=1, actions=[ActionType.RECORD_INCIDENT])
            )
        assert await incidents(factory) == []

    async def test_an_unreadable_database_reports_persist_failed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        class Down:
            def __call__(self) -> Down:
                return self

            async def __aenter__(self) -> AsyncSession:
                raise RuntimeError("database is down")

            async def __aexit__(self, *exc: object) -> bool:
                return False

        result = await ResponseService(SETTINGS, Down()).handle(  # type: ignore[arg-type]
            decision(0, D, situation_id=1, actions=[BLOCK])
        )
        assert result.outcomes[0].skip_reason is SkipReason.PERSIST_FAILED


class TestNoLiveExecution:
    async def test_live_actions_true_still_simulates_everything_and_warns(
        self, factory: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
    ) -> None:
        live = Settings(live_actions=True)
        with caplog.at_level(logging.WARNING, logger="response.service"):
            svc = ResponseService(live, factory)
        assert any("live response is not implemented" in r.getMessage() for r in caplog.records)
        await svc.handle(decision(0, G, situation_id=1, new_situation=True))
        rows = await actions(factory)
        assert rows and all(r.is_simulated is True for r in rows)
        assert all(r.action_class != ActionClass.LIVE_PROTECTIVE.value for r in rows)

    async def test_a_live_verdict_from_the_guard_is_refused_and_recorded_as_blocked(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        spy = SpyGuard(
            override=GuardVerdict(
                allowed=True,
                is_simulated=False,
                reason="Authorized",
                action_class=ActionClass.LIVE_PROTECTIVE,
            )
        )
        executor = failing_executor(*ActionType)  # any execution would be recorded as FAILED
        result = await service(factory, guard=spy, executor=executor).handle(
            decision(0, D, situation_id=1, actions=[BLOCK])
        )
        assert result.outcomes[0].status is ActionStatus.BLOCKED
        (row,) = await actions(factory)
        assert row.status == "BLOCKED"
        assert "refusing live execution" in row.result
        assert [s["status"] for s in json.loads(row.lifecycle)] == [
            "PLANNED",
            "AUTHORIZED",
            "BLOCKED",
        ]
        assert row.is_simulated is True
        assert spy.fired == []


async def incident_status(
    factory: async_sessionmaker[AsyncSession], incident_id: str
) -> str | None:
    async with factory() as session:
        row = await IncidentRepository(session).get_by_incident_id(incident_id)
    return row.status if row is not None else None


class TestRelaxedAlertCooldown:
    async def test_a_new_detection_inside_the_cooldown_is_kept_but_not_alerted_again(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        alert = [ActionType.GENERATE_ALERT]
        first_event = await persisted_event(factory, 0)
        second_event = await persisted_event(factory, 30)
        svc = service(factory)
        first = await svc.handle(decision(0, R, actions=alert, event_ids=[first_event]))
        second = await svc.handle(decision(30, R, actions=alert, event_ids=[second_event]))

        assert first.outcomes[0].status is ActionStatus.SUCCEEDED
        assert second.outcomes[0].skip_reason is SkipReason.COOLDOWN
        assert [r.triggering_event_id for r in await actions(factory)] == [first_event]
        async with factory() as session:
            repo = DetectionEventRepository(session)
            # Both detections remain in the event store (the dashboard's event feed).
            assert await repo.get_by_id(first_event) is not None
            assert await repo.get_by_id(second_event) is not None


class TestIncidentResolution:
    """An incident is resolved once its situation is over for good, exactly once."""

    async def _open_incident(self, factory: async_sessionmaker[AsyncSession]) -> None:
        await service(factory).handle(
            decision(0, A, situation_id=1, previous=R, new_situation=True)
        )

    async def test_an_ended_situation_resolves_its_open_incident(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        result = await service(factory).handle(decision(400, R, actions=[], ended=1, recovered=90))
        (incident,) = await incidents(factory)
        assert result.resolved_incident_id == "SIT-1"
        assert result.complete
        assert incident.status == "resolved"
        assert incident.recovered_at.replace(tzinfo=None) == decision(90, R).calculated_at.replace(
            tzinfo=None
        )
        assert incident.resolved_at.replace(tzinfo=None) == decision(400, R).calculated_at.replace(
            tzinfo=None
        )
        assert incident.resolution == "QUIET_FOR_REOPEN_WINDOW"
        assert incident.recovered_at != incident.resolved_at
        assert incident.recovered_at < incident.resolved_at

    async def test_a_resolved_incident_is_never_reopened(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        svc = service(factory)
        await svc.handle(decision(400, R, actions=[], ended=1, recovered=90))
        # The opening decision redelivered, and a later decision still in situation 1.
        replay = await svc.handle(decision(0, A, situation_id=1, previous=R, new_situation=True))
        late = await svc.handle(
            decision(450, A, situation_id=1, actions=[ActionType.RECORD_INCIDENT])
        )
        (incident,) = await incidents(factory)
        assert incident.status == "resolved"
        record = ActionType.RECORD_INCIDENT
        assert replay.by_action()[record].skip_reason is SkipReason.ALREADY_PROCESSED
        assert late.by_action()[record].skip_reason is SkipReason.DUPLICATE
        assert await incident_status(factory, "SIT-1") == "resolved"

    async def test_a_superseded_incident_is_resolved_before_the_new_one_is_inserted(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._open_incident(factory)
        order: list[str] = []
        real_resolve = IncidentRepository.resolve_if_open
        real_insert = IncidentRepository.insert

        async def resolve(self: IncidentRepository, incident_id: str, **k: Any) -> bool:
            order.append(f"resolve {incident_id}")
            return await real_resolve(self, incident_id, **k)

        async def insert(self: IncidentRepository, incident: Any) -> Any:
            order.append(f"insert {incident.incident_id}")
            return await real_insert(self, incident)

        monkeypatch.setattr(IncidentRepository, "resolve_if_open", resolve)
        monkeypatch.setattr(IncidentRepository, "insert", insert)
        await service(factory).handle(
            decision(
                500,
                A,
                situation_id=5,
                previous=R,
                new_situation=True,
                ended=1,
                recovered=90,
                ended_reason="SUPERSEDED_BY_NEW_SITUATION",
            )
        )
        assert order == ["resolve SIT-1", "insert SIT-5"]

    async def test_a_decision_without_an_ended_situation_changes_nothing(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        result = await service(factory).handle(decision(60, A, situation_id=1, actions=[]))
        assert result.resolved_incident_id is None
        assert [i.status for i in await incidents(factory)] == ["open"]

    async def test_resolution_is_idempotent_across_decisions_and_restarts(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        svc = service(factory)
        first = await svc.handle(decision(400, R, actions=[], ended=1, recovered=90))
        again = await svc.handle(decision(410, R, actions=[], ended=1, recovered=90))
        restarted = await service(factory).handle(
            decision(420, R, actions=[], ended=1, recovered=90)
        )
        assert first.resolved_incident_id == "SIT-1"
        assert again.resolved_incident_id is None
        assert restarted.resolved_incident_id is None
        (incident,) = await incidents(factory)
        # resolved_at stays the first resolution's time.
        assert incident.resolved_at.replace(tzinfo=None) == decision(400, R).calculated_at.replace(
            tzinfo=None
        )

    async def test_an_analysts_investigating_status_is_never_overridden(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        async with factory() as session, session.begin():
            await IncidentRepository(session).update_status("SIT-1", "investigating")
        result = await service(factory).handle(decision(400, R, actions=[], ended=1, recovered=90))
        (incident,) = await incidents(factory)
        assert result.resolved_incident_id is None
        assert (incident.status, incident.resolved_at) == ("investigating", None)

    async def test_an_incident_recorded_late_is_still_resolved(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        early = await svc.handle(decision(400, R, actions=[], ended=1, recovered=90))
        assert early.resolved_incident_id is None and early.complete
        # The opening decision is (re)delivered after the situation ended.
        await svc.handle(decision(0, A, situation_id=1, previous=R, new_situation=True))
        late = await svc.handle(decision(410, R, actions=[], ended=1, recovered=90))
        assert late.resolved_incident_id == "SIT-1"

    async def test_a_superseded_situation_is_resolved_before_the_new_incident_opens(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        result = await service(factory).handle(
            decision(
                500,
                A,
                situation_id=5,
                previous=R,
                new_situation=True,
                ended=1,
                recovered=90,
                ended_reason="SUPERSEDED_BY_NEW_SITUATION",
            )
        )
        assert result.resolved_incident_id == "SIT-1"
        rows = await incidents(factory)
        assert [(i.incident_id, i.status, i.resolution) for i in rows] == [
            ("SIT-1", "resolved", "SUPERSEDED_BY_NEW_SITUATION"),
            ("SIT-5", "open", None),
        ]

    async def test_a_failed_resolution_is_reported_and_retried(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._open_incident(factory)
        real = IncidentRepository.resolve_if_open

        async def broken(self: IncidentRepository, *a: Any, **k: Any) -> bool:
            raise RuntimeError("database locked")

        svc = service(factory)
        monkeypatch.setattr(IncidentRepository, "resolve_if_open", broken)
        failed = await svc.handle(decision(400, R, actions=[], ended=1, recovered=90))
        monkeypatch.setattr(IncidentRepository, "resolve_if_open", real)
        retried = await svc.handle(decision(410, R, actions=[], ended=1, recovered=90))

        assert failed.resolution_failed and not failed.complete
        assert retried.resolved_incident_id == "SIT-1" and retried.complete
        assert [i.status for i in await incidents(factory)] == ["resolved"]

    async def test_resolution_executes_nothing_and_records_no_action(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self._open_incident(factory)
        before = len(await actions(factory))
        spy = SpyGuard()
        await service(factory, guard=spy).handle(
            decision(400, R, actions=[], ended=1, recovered=90)
        )
        assert len(await actions(factory)) == before
        assert spy.evaluations == []
