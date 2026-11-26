"""
The Phase 2 runtime: schema bootstrap, lifecycle, monitoring loop, pipeline
order, persistence, duplicate handling and restart, on a real temporary database.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import inspect

from database.base import Base
from database.bootstrap import SchemaMismatchError, SchemaStatus, ensure_schema, head_revision
from database.engine import create_all_tables
from models.enums import ActionType, DefenseState
from tests.runtime_helpers import (
    FakeClock,
    actions,
    build,
    cycles,
    detections,
    engine_for,
    fresh_database,
    incidents,
    play,
    quiet_settings,
    samples,
    transitions,
)

PROTECTIVE = {
    ActionType.SIMULATE_IP_BLOCK.value,
    ActionType.SIMULATE_PROCESS_ISOLATE.value,
    ActionType.SIMULATE_QUARANTINE.value,
}


# ── Fresh-start schema ─────────────────────────────────────────────────────────


class TestSchemaBootstrap:
    async def test_an_empty_database_gets_the_full_schema_from_the_migrations(
        self, tmp_path: Path
    ) -> None:
        engine = engine_for(tmp_path / "fresh.db")
        try:
            assert await ensure_schema(engine) is SchemaStatus.CREATED
            async with engine.connect() as conn:
                tables = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))
            assert set(Base.metadata.tables) <= tables
            assert "alembic_version" in tables
            assert await ensure_schema(engine) is SchemaStatus.CURRENT
        finally:
            await engine.dispose()

    async def test_a_database_outside_alembic_is_refused_and_left_untouched(
        self, tmp_path: Path
    ) -> None:
        engine = engine_for(tmp_path / "legacy.db")
        try:
            await create_all_tables(engine)
            async with engine.connect() as conn:
                before = sorted(await conn.run_sync(lambda c: inspect(c).get_table_names()))
            with pytest.raises(SchemaMismatchError, match="alembic upgrade head"):
                await ensure_schema(engine)
            async with engine.connect() as conn:
                after = sorted(await conn.run_sync(lambda c: inspect(c).get_table_names()))
            assert after == before
        finally:
            await engine.dispose()

    def test_the_expected_head_is_the_latest_migration(self) -> None:
        assert head_revision() == "f8b5d2c30008"


# ── Lifecycle and monitoring loop ──────────────────────────────────────────────


class TestMonitoringLoop:
    async def test_the_loop_runs_cycles_and_stops_without_orphaned_tasks(
        self, tmp_path: Path
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            runtime = build(
                factory, FakeClock(), settings=quiet_settings(poll_interval_seconds=0.25)
            )
            runtime._sleep = asyncio.sleep  # real time for the loop itself
            await runtime.start()
            assert runtime.running
            for _ in range(200):
                if runtime.stats.cycles >= 2:
                    break
                await asyncio.sleep(0.05)
            assert runtime.stats.cycles >= 2
            await runtime.stop()
            assert not runtime.running
            names = {t.get_name() for t in asyncio.all_tasks()}
            assert not {n for n in names if n.startswith("sentinel-")}
            assert len(await samples(factory)) >= 2

    async def test_one_failing_cycle_does_not_stop_monitoring(self, tmp_path: Path) -> None:
        async with fresh_database(tmp_path) as factory:
            runtime = build(
                factory, FakeClock(), settings=quiet_settings(poll_interval_seconds=0.25)
            )
            runtime._sleep = asyncio.sleep
            real = runtime.detection.process_sample
            calls = {"n": 0}

            async def flaky(sample: Any) -> Any:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("transient detection failure")
                return await real(sample)

            runtime.detection.process_sample = flaky  # type: ignore[method-assign]
            await runtime.start()
            for _ in range(200):
                if runtime.stats.cycles >= 2:
                    break
                await asyncio.sleep(0.05)
            await runtime.stop()
            assert runtime.stats.failed_cycles == 1
            assert runtime.stats.last_error == "RuntimeError"
            assert runtime.stats.cycles >= 2
            assert runtime.stats.consecutive_failures == 0

    async def test_a_telemetry_failure_still_re_evaluates_decay(self, tmp_path: Path) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            runtime = build(factory, clock)
            await runtime.start(monitor=False)

            async def broken() -> Any:
                raise OSError("sensor unavailable")

            runtime.collector._provider.collect = broken  # type: ignore[method-assign]
            decision = await runtime.run_cycle()
            assert decision.defense_state is DefenseState.RELAXED
            assert runtime.stats.telemetry_failures == 1
            assert runtime.stats.decisions == 1
            await runtime.stop()

    async def test_measurements_are_recorded_for_every_stage(self, tmp_path: Path) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            runtime = build(factory, clock)
            await runtime.start(monitor=False)
            await cycles(runtime, clock, 3)
            view = runtime.status_view()
            assert view.cycles == 3
            for value in (
                view.last_cycle_ms,
                view.max_cycle_ms,
                view.last_telemetry_ms,
                view.last_detection_ms,
                view.last_decision_ms,
            ):
                assert value is not None and value >= 0
            await runtime.stop()


# ── Authoritative pipeline order ───────────────────────────────────────────────


class TestPipelineOrder:
    async def test_each_stage_feeds_the_next_and_explanation_comes_last(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            runtime = build(factory, clock)
            await runtime.start(monitor=False)
            order: list[str] = []

            def spy(owner: Any, name: str, label: str) -> None:
                # Patched on the class (restored by monkeypatch): the planner and other
                # value objects are frozen, slotted dataclasses whose instances are immutable.
                cls = type(owner)
                real = getattr(cls, name)

                if asyncio.iscoroutinefunction(real):

                    async def wrapped_async(self: Any, *a: Any, **k: Any) -> Any:
                        order.append(label)
                        return await real(self, *a, **k)

                    monkeypatch.setattr(cls, name, wrapped_async)
                else:

                    def wrapped(self: Any, *a: Any, **k: Any) -> Any:
                        order.append(label)
                        return real(self, *a, **k)

                    monkeypatch.setattr(cls, name, wrapped)

            spy(runtime.collector, "collect_once", "telemetry")
            spy(runtime.detection, "process_sample", "detection")
            spy(runtime.threat, "assess", "scoring+state")
            spy(runtime.response, "handle", "decision->response")
            spy(runtime.response._planner, "plan", "planner")
            spy(runtime.response._guard, "evaluate", "guard")
            spy(runtime.response._executor, "execute", "executor")
            spy(runtime.explanation, "observe", "explanation")

            await cycles(runtime, clock, 1)
            # A quiet cycle: RELAXED plans nothing, so the guard and executor are not reached.
            assert order == [
                "telemetry",
                "detection",
                "scoring+state",
                "decision->response",
                "planner",
                "explanation",
            ]
            order.clear()

            await play(runtime, "suspicious")
            first_guard = order.index("guard")
            assert order.index("scoring+state") < order.index("planner") < first_guard
            assert first_guard < order.index("executor")
            # observe() follows every handle(); never precedes the decision it explains.
            for i, label in enumerate(order):
                if label == "explanation":
                    assert "decision->response" in order[:i]
            assert order.count("explanation") == order.count("decision->response")
            await runtime.stop()

    async def test_the_explained_decision_is_the_authoritative_one(self, tmp_path: Path) -> None:
        async with fresh_database(tmp_path) as factory:
            runtime = build(factory, FakeClock())
            await runtime.start(monitor=False)
            handled: list[Any] = []
            observed: list[Any] = []
            real_handle, real_observe = runtime.response.handle, runtime.explanation.observe

            async def handle(decision: Any) -> Any:
                handled.append(decision)
                return await real_handle(decision)

            def observe(decision: Any) -> bool:
                observed.append(decision)
                return real_observe(decision)

            runtime.response.handle = handle  # type: ignore[method-assign]
            runtime.explanation.observe = observe  # type: ignore[method-assign]
            await play(runtime, "critical")
            assert observed and all(o is h for o, h in zip(observed, handled, strict=True))
            await runtime.stop()


# ── Scenarios, persistence, duplicates, restart ─────────────────────────────────


class TestScenariosAndPersistence:
    async def test_normal_stays_relaxed_with_no_actions(self, tmp_path: Path) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            runtime = build(factory, clock)
            await runtime.start(monitor=False)
            await play(runtime, "normal")
            await cycles(runtime, clock, 5)
            assert runtime.defense_state is DefenseState.RELAXED
            assert await actions(factory) == []
            assert await incidents(factory) == []
            await runtime.stop()

    async def test_suspicious_raises_the_posture_with_simulated_responses(
        self, tmp_path: Path
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            runtime = build(factory, FakeClock())
            await runtime.start(monitor=False)
            await play(runtime, "suspicious")
            assert runtime.defense_state in {DefenseState.ALERT, DefenseState.DEFENSIVE}
            recorded = await actions(factory)
            assert recorded and all(a.is_simulated for a in recorded)
            assert {a.action_type for a in recorded} >= {"GENERATE_ALERT", "RECORD_INCIDENT"}
            assert ActionType.SIMULATE_QUARANTINE.value not in {a.action_type for a in recorded}
            assert all(e.is_synthetic for e in await detections(factory))
            await runtime.stop()

    async def test_critical_escalates_to_aggressive_with_audit_and_explanation(
        self, tmp_path: Path
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            runtime = build(factory, FakeClock())
            await runtime.start(monitor=False)
            await play(runtime, "critical")
            assert runtime.defense_state is DefenseState.AGGRESSIVE
            recorded = await actions(factory)
            assert PROTECTIVE <= {a.action_type for a in recorded}
            assert all(a.is_simulated for a in recorded)
            assert all(a.lifecycle and a.status for a in recorded)
            times = [a.executed_at for a in recorded]
            assert times == sorted(times)
            path = [(t.from_state, t.to_state) for t in await transitions(factory)]
            levels = [s.value for s in DefenseState]
            assert path[0][0] == "RELAXED" and path[-1][1] == "AGGRESSIVE"
            # Every escalation climbs exactly one level, so each level is in the audit trail.
            assert all(levels.index(b) == levels.index(a) + 1 for a, b in path)
            (incident,) = await incidents(factory)
            assert incident.incident_id.startswith("SIT-") and incident.status == "open"
            assert await runtime.explanation.run_pending() >= 0
            assert runtime.explanation.stats.recorded >= 1
            await runtime.stop()

    async def test_repeated_attacks_in_one_situation_do_not_duplicate_actions(
        self, tmp_path: Path
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            runtime = build(factory, clock)
            await runtime.start(monitor=False)
            await play(runtime, "critical")
            before = [a.action_type for a in await actions(factory)]
            await play(runtime, "critical")
            await cycles(runtime, clock, 3)
            after = [a.action_type for a in await actions(factory)]
            for action in PROTECTIVE | {"RECORD_INCIDENT"}:
                assert after.count(action) == before.count(action) == 1
            assert len(await incidents(factory)) == 1
            await runtime.stop()

    async def test_a_restart_restores_the_posture_and_records_nothing_twice(
        self, tmp_path: Path
    ) -> None:
        async with fresh_database(tmp_path) as factory:
            clock = FakeClock()
            first = build(factory, clock)
            await first.start(monitor=False)
            await play(first, "critical")
            await first.stop()
            recorded = len(await actions(factory))

            second = build(factory, clock)
            await second.start(monitor=False)
            assert second.defense_state is DefenseState.AGGRESSIVE
            await cycles(second, clock, 3)
            assert len(await incidents(factory)) == 1
            new = (await actions(factory))[recorded:]
            assert not {a.action_type for a in new} & (PROTECTIVE | {"RECORD_INCIDENT"})
            await second.stop()
