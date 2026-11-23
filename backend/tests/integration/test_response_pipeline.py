"""
End-to-end response scenario.

    FakeTelemetryProvider -> TelemetryCollector -> DetectionEngine
        -> ThreatAssessmentService -> ResponseService -> response_actions / incidents

Uses the deterministic Phase 4 scenario (normal -> CPU -> network -> auth burst ->
repeated failures -> critical escalation -> recovery) and feeds every decision,
in order, to the response layer.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from collections import Counter
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import Settings
from database.models import ResponseAction
from database.repositories import DetectionEventRepository
from models.enums import ActionStatus, ActionType, DefenseState
from response.actions import ResponseResult, SkipReason
from response.service import ResponseService
from tests.response_helpers import actions, database, incidents
from tests.threat_helpers import at
from tests.threat_scenario import Scenario, ScenarioResult, play_attack, run_scenario

SETTINGS = Settings()
ONCE_PER_SITUATION = (
    ActionType.RECORD_INCIDENT,
    ActionType.SIMULATE_IP_BLOCK,
    ActionType.SIMULATE_PROCESS_ISOLATE,
    ActionType.SIMULATE_QUARANTINE,
)


async def respond(
    factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
) -> list[ResponseResult]:
    return await ResponseService(SETTINGS, factory).handle_all(scenario.decisions)


def fingerprint(rows: list[ResponseAction]) -> list[tuple[Any, ...]]:
    return [
        (
            r.id,
            r.executed_at.isoformat(),
            r.action_type,
            r.defense_state,
            r.status,
            r.situation_id,
            r.scope_key,
            r.idempotency_key,
            r.triggering_event_id,
            r.result,
            r.lifecycle,
        )
        for r in rows
    ]


class TestEndToEndResponse:
    async def test_the_attack_produces_one_incident_and_each_protective_action_once(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            results = await respond(factory, scenario)
            rows = await actions(factory)
            incident_rows = await incidents(factory)

        situations = {d.situation_id for d in scenario.decisions if d.situation_id is not None}
        assert len(situations) == 1
        (situation,) = situations

        succeeded = Counter(r.action_type for r in rows if r.status == "SUCCEEDED")
        for action in ONCE_PER_SITUATION:
            assert succeeded[action.value] == 1, action
        assert [i.incident_id for i in incident_rows] == [f"SIT-{situation}"]
        assert all(r.status == "SUCCEEDED" for r in rows), Counter(r.status for r in rows)
        assert all(result.complete for result in results)

    async def test_alerts_follow_the_state_path_without_repeating(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        in_situation = [
            r.scope_key.rsplit(":", 1)[-1]
            for r in rows
            if r.action_type == "GENERATE_ALERT" and r.situation_id is not None
        ]
        # One alert per state entered; re-entering DEFENSIVE and ALERT on the way down
        # does not alert again.
        assert in_situation == ["ALERT", "DEFENSIVE", "AGGRESSIVE"]
        monitoring = [
            r.scope_key.rsplit(":", 1)[-1] for r in rows if r.action_type == "INCREASE_MONITORING"
        ]
        assert monitoring == ["ALERT", "DEFENSIVE", "AGGRESSIVE"]

    async def test_alerts_outside_the_situation_respect_the_cooldown(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        relaxed = [r.executed_at for r in rows if r.scope_key == "global:GENERATE_ALERT"]
        assert relaxed, "evidence while RELAXED should alert"
        gaps = [(b - a).total_seconds() for a, b in zip(relaxed, relaxed[1:], strict=False)]
        assert all(gap >= SETTINGS.response_alert_cooldown_seconds for gap in gaps)

    async def test_actions_are_recorded_in_order_and_point_at_real_evidence(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            rows = await actions(factory)
            async with factory() as session:
                repo = DetectionEventRepository(session)
                for row in rows:
                    if row.triggering_event_id is not None:
                        assert await repo.get_by_id(row.triggering_event_id) is not None

        times = [r.executed_at for r in rows]
        assert times == sorted(times)
        quarantine = next(r for r in rows if r.action_type == "SIMULATE_QUARANTINE")
        assert quarantine.defense_state == "AGGRESSIVE"
        block = next(r for r in rows if r.action_type == "SIMULATE_IP_BLOCK")
        assert block.defense_state == "DEFENSIVE"
        assert block.executed_at < quarantine.executed_at

    async def test_every_record_is_simulated_with_a_complete_lifecycle(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        assert rows
        for row in rows:
            assert row.is_simulated is True
            assert row.action_class != "LIVE_PROTECTIVE"
            assert [s["status"] for s in json.loads(row.lifecycle)] == [
                "PLANNED",
                "AUTHORIZED",
                "EXECUTING",
                "SUCCEEDED",
            ]
            assert row.dry_run_description


SECOND_ATTACK_AT = 800.0  # well past recovery (~290 s) plus the 300 s reopen window
PROTECTIVE = (
    ActionType.SIMULATE_IP_BLOCK,
    ActionType.SIMULATE_PROCESS_ISOLATE,
    ActionType.SIMULATE_QUARANTINE,
)


async def two_attacks(factory: async_sessionmaker[AsyncSession]) -> ScenarioResult:
    s = Scenario(factory)
    await play_attack(s)
    await play_attack(s, start=SECOND_ATTACK_AT)
    return s.result


def state_path(decisions: list[Any]) -> list[str]:
    path: list[str] = []
    for d in decisions:
        if not path or path[-1] != d.defense_state.value:
            path.append(d.defense_state.value)
    return path


class TestTwoIndependentSituations:
    """Attack, full recovery, then an unrelated later attack."""

    async def test_each_attack_is_one_stable_situation_closed_by_recovery(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)

        first = [s.decision for s in scenario.steps if s.t < SECOND_ATTACK_AT]
        second = [s.decision for s in scenario.steps if s.t >= SECOND_ATTACK_AT]
        expected = ["RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE", "DEFENSIVE", "ALERT", "RELAXED"]
        assert state_path(first) == expected
        assert state_path(second) == expected

        ids_1 = {d.situation_id for d in first if d.defense_state is not DefenseState.RELAXED}
        ids_2 = {d.situation_id for d in second if d.defense_state is not DefenseState.RELAXED}
        assert len(ids_1) == 1 and len(ids_2) == 1
        assert ids_1 != ids_2 and None not in ids_1 | ids_2
        # Recovery to RELAXED ends the situation.
        assert first[-1].defense_state is DefenseState.RELAXED
        assert first[-1].situation_id is None
        assert second[-1].situation_id is None
        assert sum(d.new_situation for d in scenario.decisions) == 2

    async def test_each_situation_gets_its_own_incident_and_protective_actions(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            results = await respond(factory, scenario)
            rows = await actions(factory)
            incident_rows = await incidents(factory)

        opened = [d.situation_id for d in scenario.decisions if d.new_situation]
        assert [i.incident_id for i in incident_rows] == [f"SIT-{sid}" for sid in opened]

        succeeded = Counter(
            (r.situation_id, r.action_type) for r in rows if r.status == "SUCCEEDED"
        )
        for sid in opened:
            for action in ONCE_PER_SITUATION:
                assert succeeded[(sid, action.value)] == 1, (sid, action)
        assert all(n == 1 for (sid, a), n in succeeded.items() if a.startswith("SIMULATE_"))
        assert all(r.status == "SUCCEEDED" for r in rows)
        assert all(result.complete for result in results)

    async def test_the_guard_authorizes_every_action_before_it_is_simulated(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        assert rows
        for row in rows:
            steps = [s["status"] for s in json.loads(row.lifecycle)]
            assert steps.index("AUTHORIZED") < steps.index("EXECUTING"), steps
            assert row.guard_reason
            assert row.is_simulated is True
        protective = {r.action_type for r in rows if r.action_type in {a.value for a in PROTECTIVE}}
        assert protective == {a.value for a in PROTECTIVE}
        assert all(a.value.startswith("SIMULATE_") for a in PROTECTIVE)

    async def test_redelivering_both_attacks_executes_nothing_twice(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            await respond(factory, scenario)
            before = fingerprint(await actions(factory))
            await ResponseService(SETTINGS, factory).handle_all(scenario.decisions)
            after = fingerprint(await actions(factory))
            assert len(await incidents(factory)) == 2

        assert after == before


class TestIncidentLifecycle:
    async def test_the_incident_is_resolved_once_the_reopen_window_passes(self) -> None:
        async with database() as factory:
            s = Scenario(factory)
            await play_attack(s)
            recovered = next(
                st.t
                for st in s.result.steps
                if st.decision.state_changed and st.decision.defense_state is DefenseState.RELAXED
            )
            window = SETTINGS.threat_incident_reopen_seconds
            # Quiet monitoring continues until well past the reopen window.
            for t in range(430, int(recovered + window) + 40, 10):
                await s.telemetry(t, "quiet")
            results = await respond(factory, s.result)
            (incident,) = await incidents(factory)

        resolutions = [
            (r.decided_at, r.resolved_incident_id) for r in results if r.resolved_incident_id
        ]
        assert len(resolutions) == 1
        resolved_at, incident_id = resolutions[0]
        assert incident_id == incident.incident_id
        assert (resolved_at - at(recovered)).total_seconds() >= window
        assert incident.status == "resolved"
        assert incident.resolution == "QUIET_FOR_REOPEN_WINDOW"
        assert incident.recovered_at.replace(tzinfo=None) == at(recovered).replace(tzinfo=None)

    async def test_the_incident_stays_open_while_the_situation_could_resume(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)  # ends 130 s after recovery
            await respond(factory, scenario)
            (incident,) = await incidents(factory)
        assert incident.status == "open"
        assert incident.resolved_at is None

    async def test_two_attacks_resolve_the_first_incident_and_open_the_second(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            await respond(factory, scenario)
            rows = await incidents(factory)
        first, second = rows
        assert (first.status, first.resolution) == ("resolved", "QUIET_FOR_REOPEN_WINDOW")
        assert first.resolved_at.replace(tzinfo=None) < second.created_at.replace(tzinfo=None)
        assert second.status == "open"


class TestNoRepeatedAlerts:
    async def test_relaxed_alerts_only_accompany_new_detections(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        alerted_at = {
            r.executed_at.replace(tzinfo=None)
            for r in rows
            if r.action_type == "GENERATE_ALERT" and r.situation_id is None
        }
        with_detections = {
            st.decision.calculated_at.replace(tzinfo=None) for st in scenario.steps if st.detections
        }
        assert alerted_at, "a new detection while RELAXED should alert"
        assert alerted_at <= with_detections

    async def test_recovery_produces_no_alerts(self) -> None:
        async with database() as factory:
            scenario = await two_attacks(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        recovery = [(s.t, s.decision) for s in scenario.steps if s.phase == "recovery"]
        relaxed_recovery = {
            d.calculated_at.replace(tzinfo=None)
            for _, d in recovery
            if d.defense_state is DefenseState.RELAXED
        }
        assert relaxed_recovery, "the scenario should include RELAXED recovery samples"
        assert all(
            not d.recommended_actions
            for _, d in recovery
            if d.defense_state is DefenseState.RELAXED
        )
        assert not any(r.executed_at.replace(tzinfo=None) in relaxed_recovery for r in rows)

    async def test_decaying_evidence_after_recovery_never_alerts_periodically(self) -> None:
        # Regression: before the fix, leftover evidence alerted every 60 s while RELAXED.
        async with database() as factory:
            s = Scenario(factory)
            await play_attack(s)
            for t in range(430, 1200, 10):  # a long quiet tail: about 13 minutes
                await s.telemetry(t, "quiet")
            await respond(factory, s.result)
            rows = await actions(factory)

        recovered = next(
            st.t
            for st in s.result.steps
            if st.decision.state_changed and st.decision.defense_state is DefenseState.RELAXED
        )
        after = [st.decision for st in s.result.steps if st.t > recovered]
        decaying = [d for d in after if d.threat_score > 0]
        assert len(decaying) >= 6, "evidence should still be in the scorer after recovery"
        assert all(not d.recommended_actions for d in after)
        late_alerts = [
            r
            for r in rows
            if r.action_type == "GENERATE_ALERT"
            and r.executed_at.replace(tzinfo=None) > at(recovered).replace(tzinfo=None)
        ]
        assert late_alerts == []


class TestExactlyOnce:
    async def test_redelivering_every_decision_records_nothing_new(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            before = fingerprint(await actions(factory))
            again = await respond(factory, scenario)
            after = fingerprint(await actions(factory))
            assert len(await incidents(factory)) == 1

        assert after == before
        recorded = [o for r in again for o in r.outcomes if o.status is not None]
        assert recorded == []
        assert {o.skip_reason for r in again for o in r.outcomes} <= {
            SkipReason.ALREADY_PROCESSED,
            SkipReason.DUPLICATE,
            SkipReason.COOLDOWN,
        }

    async def test_restarting_the_response_service_mid_attack_changes_nothing(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            uninterrupted = fingerprint(await actions(factory))

        async with database() as factory:
            scenario = await run_scenario(factory)
            decisions = scenario.decisions
            split = next(
                i for i, d in enumerate(decisions) if d.defense_state is DefenseState.AGGRESSIVE
            )
            first = ResponseService(SETTINGS, factory)
            await first.handle_all(decisions[: split + 1])
            second = ResponseService(SETTINGS, factory)  # a restart: fresh guard, fresh memory
            await second.handle_all(decisions[split - 3 :])  # overlap: some decisions redelivered
            restarted = fingerprint(await actions(factory))

        assert restarted == uninterrupted

    async def test_the_response_is_deterministic(self) -> None:
        runs = []
        for _ in range(2):
            async with database() as factory:
                scenario = await run_scenario(factory)
                await respond(factory, scenario)
                runs.append(fingerprint(await actions(factory)))
        assert runs[0] == runs[1]
        assert len(runs[0]) >= 10


class TestNoHostAction:
    async def test_the_full_pipeline_never_touches_the_host(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[str] = []

        def forbid(name: str):  # type: ignore[no-untyped-def]
            def blocked(*_a: object, **_k: object) -> None:
                attempts.append(name)
                raise AssertionError(f"host action attempted: {name}")

            return blocked

        for module, attr in [
            (subprocess, "Popen"),
            (subprocess, "run"),
            (subprocess, "call"),
            (os, "system"),
            (os, "kill"),
            (os, "remove"),
            (os, "unlink"),
        ]:
            monkeypatch.setattr(module, attr, forbid(f"{module.__name__}.{attr}"))
        monkeypatch.setattr(socket.socket, "connect", forbid("socket.connect"))
        monkeypatch.setattr(socket.socket, "connect_ex", forbid("socket.connect_ex"))

        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            rows = await actions(factory)

        assert attempts == []
        assert {r.action_type for r in rows} >= {a.value for a in ONCE_PER_SITUATION}

    async def test_live_actions_true_changes_nothing_about_the_response(self) -> None:
        async with database() as factory:
            scenario = await run_scenario(factory)
            await respond(factory, scenario)
            baseline = fingerprint(await actions(factory))

        async with database() as factory:
            scenario = await run_scenario(factory)
            live = Settings(live_actions=True)
            await ResponseService(live, factory).handle_all(scenario.decisions)
            rows = await actions(factory)

        assert fingerprint(rows) == baseline
        assert all(r.is_simulated for r in rows)
        assert ActionStatus.SUCCEEDED.value in {r.status for r in rows}
