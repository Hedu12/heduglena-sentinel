"""
End-to-end deterministic threat scenario.

    NORMAL -> CPU ANOMALY -> NETWORK ANOMALY -> AUTH FAILURE BURST
           -> REPEATED AUTH FAILURES -> CRITICAL ESCALATION -> RECOVERY

Real telemetry objects flow through the real collector, detection engine and
threat service into SQLite. The scenario helper lives in tests/threat_scenario.py.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import Settings
from database.engine import create_all_tables, drop_all_tables
from database.models import DefenseStateChange, DetectionEvent, Incident, ThreatScore
from models.enums import ActionClass, ActionType, DefenseState
from response.guard import ResponseGuard
from tests.threat_scenario import ScenarioResult, run_scenario
from threat.config import ThreatConfig

CONFIG = ThreatConfig.from_settings(Settings())


async def new_factory() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    return eng, async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng, f = await new_factory()
    yield f
    await drop_all_tables(eng)
    await eng.dispose()


@pytest_asyncio.fixture()
async def scenario(factory: async_sessionmaker[AsyncSession]) -> ScenarioResult:
    return await run_scenario(factory)


async def table(factory: async_sessionmaker[AsyncSession], model: type) -> list:  # type: ignore[type-arg]
    async with factory() as session:
        return list((await session.execute(select(model).order_by(model.id))).scalars().all())


def score_at(result: ScenarioResult, t: float) -> float:
    return next(s.decision.threat_score for s in result.steps if s.t == t)


class TestDetectionEvidence:
    async def test_detection_events_are_persisted_in_scenario_order(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        stored = await table(factory, DetectionEvent)
        assert [e.event_type for e in stored] == [
            "cpu_sustained_high",
            "network_throughput_high",
            "auth_failure_burst",
            "auth_failure_burst",
            "suspicious_process",
        ]
        assert [e.classification for e in stored] == [
            "INFORMATIONAL",
            "INFORMATIONAL",
            "SUSPICIOUS",
            "HIGH_CONFIDENCE",
            "HIGH_CONFIDENCE",
        ]
        assert [e.id for e in stored] == [e.id for e in scenario.detections()]

    async def test_normal_and_recovery_phases_produce_no_detections(
        self, scenario: ScenarioResult
    ) -> None:
        for phase in ("normal", "quiet", "recovery"):
            assert all(not s.detections for s in scenario.phase(phase))


class TestScoreProgression:
    async def test_score_rises_at_each_escalation_step(self, scenario: ScenarioResult) -> None:
        cpu, network = score_at(scenario, 35), score_at(scenario, 55)
        burst, escalated, critical = (
            score_at(scenario, 104),
            score_at(scenario, 109),
            score_at(scenario, 125),
        )
        assert 0.0 == score_at(scenario, 20) < cpu
        assert network > 0.15
        assert burst > cpu
        assert escalated > burst
        assert critical > escalated

    async def test_an_isolated_resource_anomaly_alone_does_not_leave_relaxed(
        self, scenario: ScenarioResult
    ) -> None:
        for t in (35, 55):  # the CPU and network anomalies, before any security event
            step = next(s for s in scenario.steps if s.t == t)
            assert step.decision.threat_score < CONFIG.state.threshold_alert
            assert step.decision.defense_state is DefenseState.RELAXED

    async def test_every_score_is_in_range_and_explainable(self, scenario: ScenarioResult) -> None:
        for step in scenario.steps:
            d = step.decision
            b = d.breakdown
            assert 0.0 <= d.threat_score <= 1.0
            assert d.reason_codes, "every decision carries reason codes"
            parts = (
                b.severity_contribution
                + b.confidence_contribution
                + b.repetition_contribution
                + b.escalation_contribution
                + b.correlation_contribution
                + b.cross_domain_contribution
            )
            assert b.raw_total == pytest.approx(parts, abs=1e-5)
            assert d.threat_score == pytest.approx(min(1.0, b.raw_total), abs=1e-5)
            json.dumps(d.to_dict(), allow_nan=False)

    async def test_the_critical_decision_explains_itself(self, scenario: ScenarioResult) -> None:
        decision = next(s.decision for s in scenario.steps if s.t == 125)
        codes = {c.value for c in decision.reason_codes}
        assert {
            "CRITICAL_EVENT",
            "HIGH_CONFIDENCE_EVIDENCE",
            "SYNTHETIC_SECURITY_EVENT",
            "CROSS_SIGNAL_CORRELATION",
            "ESCALATING_ACTIVITY",
            "SEVERE_ESCALATION_BYPASS",
        } <= codes
        assert decision.breakdown.signals[0].event_type == "suspicious_process"
        assert decision.breakdown.correlation_contribution > 0

    async def test_score_decays_during_recovery_and_ends_near_zero(
        self, scenario: ScenarioResult
    ) -> None:
        recovery = [s.decision.threat_score for s in scenario.phase("recovery")]
        assert recovery == sorted(recovery, reverse=True)
        assert recovery[-1] < 0.05
        assert all(s.decision.breakdown.decay >= 0 for s in scenario.steps)


class TestStateProgression:
    async def test_state_changes_are_persisted_in_order(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        changes = await table(factory, DefenseStateChange)
        assert [c.from_state for c in changes][0] == "RELAXED"
        assert [c.to_state for c in changes] == [
            "ALERT",
            "DEFENSIVE",
            "AGGRESSIVE",
            "DEFENSIVE",
            "ALERT",
            "RELAXED",
        ]
        for earlier, later in zip(changes, changes[1:], strict=False):
            assert earlier.to_state == later.from_state, "transition chain is unbroken"

    async def test_persisted_transitions_match_the_decisions_and_carry_evidence(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        changes = await table(factory, DefenseStateChange)
        decisions = [s.decision for s in scenario.steps if s.decision.state_changed]
        assert len(changes) == len(decisions) == 6
        for row, decision in zip(changes, decisions, strict=True):
            assert row.id == decision.transition_id
            assert row.to_state == decision.defense_state.value
            assert row.trigger_score == pytest.approx(decision.threat_score)
            evidence = json.loads(row.evidence or "")
            assert evidence["previous_state"] == row.from_state
            assert evidence["new_state"] == row.to_state
            assert evidence["transition_reason_codes"]
            assert evidence["breakdown"]["final_score"] == pytest.approx(decision.threat_score)
            assert row.reason == decision.evaluation.reason_codes[0].value
        # Each transition records the score that preceded it.
        assert changes[0].previous_score is not None
        assert all(c.previous_score is not None for c in changes[1:])

    async def test_score_history_is_persisted(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        scores = await table(factory, ThreatScore)
        assert 0 < len(scores) < len(scenario.steps)  # unchanged scores are not re-stored
        assert all(0.0 <= s.score <= 1.0 for s in scores)
        assert max(s.score for s in scores) == pytest.approx(
            max(s.decision.threat_score for s in scenario.steps)
        )

    async def test_escalation_is_immediate_and_de_escalation_is_gradual(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        changes = await table(factory, DefenseStateChange)
        by_to = {c.to_state: c for c in changes}
        # Climbing happens at the instant the evidence arrives (t=104, 109, 125).
        assert [(c.changed_at - changes[0].changed_at).total_seconds() for c in changes[:3]] == [
            0.0,
            5.0,
            21.0,
        ]
        # Descending takes at least a cooldown per level, starting from the peak.
        assert [c.to_state for c in changes[3:]] == ["DEFENSIVE", "ALERT", "RELAXED"]
        times = [by_to["AGGRESSIVE"].changed_at, *[c.changed_at for c in changes[3:]]]
        for earlier, later in zip(times, times[1:], strict=False):
            assert (later - earlier).total_seconds() >= CONFIG.state.cooldown_seconds

    async def test_the_state_never_flaps(self, scenario: ScenarioResult) -> None:
        states = [s.decision.defense_state for s in scenario.steps]
        order = list(DefenseState)
        peak = max(order.index(s) for s in states)
        rises = [
            i for i in range(1, len(states)) if order.index(states[i]) > order.index(states[i - 1])
        ]
        falls = [
            i for i in range(1, len(states)) if order.index(states[i]) < order.index(states[i - 1])
        ]
        assert peak == 3
        assert rises and falls and max(rises) < min(falls), "all climbing precedes all descending"

    async def test_active_critical_evidence_holds_the_state_up_despite_decay(
        self, scenario: ScenarioResult
    ) -> None:
        # t=170 is 45 s after the critical event: still inside the 60 s active window, so
        # the state cannot fall below DEFENSIVE even though the score has decayed to ~0.53.
        step = next(s for s in scenario.steps if s.t == 170)
        assert step.decision.defense_state is DefenseState.DEFENSIVE


class TestResponseBoundary:
    async def test_decisions_recommend_actions_appropriate_to_the_state(
        self, scenario: ScenarioResult
    ) -> None:
        by_state: dict[DefenseState, set[ActionType]] = {}
        for step in scenario.steps:
            by_state.setdefault(step.decision.defense_state, set()).update(
                step.decision.recommended_actions
            )
        assert ActionType.SIMULATE_QUARANTINE in by_state[DefenseState.AGGRESSIVE]
        assert ActionType.SIMULATE_IP_BLOCK in by_state[DefenseState.DEFENSIVE]
        assert ActionType.SIMULATE_QUARANTINE not in by_state[DefenseState.DEFENSIVE]
        assert ActionType.INCREASE_MONITORING in by_state[DefenseState.ALERT]
        assert ActionType.SIMULATE_IP_BLOCK not in by_state[DefenseState.ALERT]

    async def test_every_recommendation_is_one_the_unmodified_guard_authorises_as_simulated(
        self, scenario: ScenarioResult
    ) -> None:
        guard = ResponseGuard(settings=Settings(live_actions=False))
        for step in scenario.steps:
            for action in step.decision.recommended_actions:
                verdict = guard.evaluate(action, step.decision.defense_state)
                assert verdict.allowed
                if verdict.action_class is ActionClass.SIMULATED_PROTECTIVE:
                    assert verdict.is_simulated is True

    async def test_running_the_scenario_performs_no_host_action(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[str] = []

        def forbid(name: str):  # type: ignore[no-untyped-def]
            def _blocked(*_a: object, **_k: object) -> None:
                attempts.append(name)
                raise AssertionError(f"host action attempted: {name}")

            return _blocked

        monkeypatch.setattr(subprocess, "Popen", forbid("subprocess.Popen"))
        monkeypatch.setattr(subprocess, "run", forbid("subprocess.run"))
        monkeypatch.setattr(os, "system", forbid("os.system"))
        monkeypatch.setattr(os, "kill", forbid("os.kill"))
        monkeypatch.setattr(os, "remove", forbid("os.remove"))
        monkeypatch.setattr(socket.socket, "connect", forbid("socket.connect"))
        monkeypatch.setattr(socket.socket, "connect_ex", forbid("socket.connect_ex"))

        result = await run_scenario(factory)

        assert attempts == []
        assert result.decisions[-1].defense_state is DefenseState.RELAXED
        assert max(d.threat_score for d in result.decisions) > 0.8

    async def test_scoring_evidence_does_not_create_incidents(
        self, factory: async_sessionmaker[AsyncSession], scenario: ScenarioResult
    ) -> None:
        async with factory() as session:
            count = (await session.execute(select(func.count()).select_from(Incident))).scalar_one()
        assert count == 0


class TestDeterminism:
    async def test_the_same_scenario_produces_identical_decisions(self) -> None:
        outputs = []
        for _ in range(2):
            eng, f = await new_factory()
            try:
                outputs.append([d.to_dict() for d in (await run_scenario(f)).decisions])
            finally:
                await eng.dispose()
        assert outputs[0] == outputs[1]
        assert len(outputs[0]) > 40
