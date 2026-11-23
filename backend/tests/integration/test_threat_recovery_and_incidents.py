"""
Restart recovery, once-per-situation incident recommendations, and the guarded
bypass into AGGRESSIVE, all through ThreatAssessmentService and a real database.

Detection events here are persisted first, because recovery rebuilds evidence
from the detection_events table exactly as a real restart would.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import threat.service as service_module
from core.config import Settings
from core.exceptions import DatabaseError
from database.engine import create_all_tables, drop_all_tables
from database.models import DetectionEvent
from database.repositories import DetectionEventRepository
from models.enums import ActionType, DefenseState
from tests.threat_helpers import at
from threat.config import ScoringConfig, StateConfig, ThreatConfig
from threat.decision import Decision
from threat.reasons import ReasonCode
from threat.service import ThreatAssessmentService

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)
CONFIG = ThreatConfig.from_settings(Settings())


async def make_factory() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    return eng, async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng, f = await make_factory()
    yield f
    await drop_all_tables(eng)
    await eng.dispose()


def service(
    factory: async_sessionmaker[AsyncSession], config: ThreatConfig = CONFIG
) -> ThreatAssessmentService:
    return ThreatAssessmentService(config, factory)


def raw(
    event_type: str,
    severity: str,
    classification: str,
    confidence: float,
    t: float,
    *,
    synthetic: bool = False,
) -> DetectionEvent:
    return DetectionEvent(
        detected_at=at(t),
        rule_id="DET-TEST-001",
        rule_name="test",
        severity=severity,
        metric_key="m",
        is_synthetic=synthetic,
        event_type=event_type,
        classification=classification,
        confidence=confidence,
    )


def cpu(t: float) -> DetectionEvent:
    return raw("cpu_sustained_high", "MEDIUM", "INFORMATIONAL", 0.3, t)


def net(t: float) -> DetectionEvent:
    return raw("network_throughput_high", "MEDIUM", "INFORMATIONAL", 0.3, t)


def auth_suspicious(t: float) -> DetectionEvent:
    return raw("auth_failure_burst", "HIGH", "SUSPICIOUS", 0.55, t, synthetic=True)


def auth_critical(t: float) -> DetectionEvent:
    return raw("auth_failure_burst", "CRITICAL", "HIGH_CONFIDENCE", 0.9, t, synthetic=True)


def malicious(t: float) -> DetectionEvent:
    return raw("suspicious_process", "CRITICAL", "HIGH_CONFIDENCE", 0.95, t, synthetic=True)


async def persist(
    factory: async_sessionmaker[AsyncSession], *events: DetectionEvent
) -> list[DetectionEvent]:
    async with factory() as session, session.begin():
        repo = DetectionEventRepository(session)
        return [await repo.insert(e) for e in events]


async def run_ticks(
    svc: ThreatAssessmentService, start: float, stop: float, step: float
) -> list[Decision]:
    out = []
    t = start
    while t <= stop:
        out.append(await svc.assess([], at(t)))
        t += step
    return out


def incident_decisions(decisions: list[Decision]) -> list[Decision]:
    return [d for d in decisions if ActionType.RECORD_INCIDENT in d.recommended_actions]


class _FailingFactory:
    def __call__(self) -> _FailingFactory:
        return self

    async def __aenter__(self) -> AsyncSession:
        raise RuntimeError("database is down")

    async def __aexit__(self, *exc: object) -> bool:
        return False


class TestRestartRecoversEvidence:
    async def test_the_score_after_a_restart_equals_the_score_before(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        events = await persist(factory, cpu(0), net(10), auth_suspicious(20), auth_critical(30))
        for event, t in zip(events, (0, 10, 20, 30), strict=True):
            await svc.assess([event], at(t))
        before = await svc.assess([], at(45))
        assert before.threat_score > 0.5

        restarted = service(factory)
        await restarted.restore_state(at(45))
        after = await restarted.assess([], at(45))

        assert after.threat_score == before.threat_score
        assert after.defense_state is before.defense_state
        assert after.breakdown.to_dict() == before.breakdown.to_dict()
        assert after.situation_id == before.situation_id

    async def test_without_recovery_a_restarted_service_would_forget_everything(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Documents what restore_state fixes: a service that skips it scores zero.
        svc = service(factory)
        (event,) = await persist(factory, malicious(0))
        await svc.assess([event], at(0))
        forgetful = service(factory)
        assert (await forgetful.assess([], at(10))).threat_score == 0.0
        recovered = service(factory)
        await recovered.restore_state(at(10))
        assert (await recovered.assess([], at(10))).threat_score > 0.4

    async def test_evidence_older_than_the_ttl_is_not_replayed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await persist(factory, malicious(0))
        restarted = service(factory)
        await restarted.restore_state(at(CONFIG.scoring.evidence_ttl_seconds + 100))
        decision = await restarted.assess([], at(CONFIG.scoring.evidence_ttl_seconds + 100))
        assert decision.threat_score == 0.0
        assert decision.breakdown.signal_count == 0

    async def test_replay_is_bounded_by_the_dedup_window(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        small = ThreatConfig(ScoringConfig(dedup_window=5), StateConfig())
        await persist(factory, *[cpu(i) for i in range(30)])
        restarted = service(factory, small)
        await restarted.restore_state(at(30))
        decision = await restarted.assess([], at(30))
        assert decision.breakdown.signals[0].count == 5  # newest five, not all thirty

    async def test_events_already_replayed_are_not_counted_again(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        (event,) = await persist(factory, cpu(0))
        restarted = service(factory)
        await restarted.restore_state(at(5))
        decision = await restarted.assess([event], at(5))
        assert decision.breakdown.signals[0].count == 1

    async def test_future_dated_rows_cannot_pin_the_score_after_a_restart(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await persist(factory, malicious(10_000_000))
        restarted = service(factory)
        await restarted.restore_state(at(0))
        assert (await restarted.assess([], at(400))).threat_score == 0.0

    async def test_restoring_twice_gives_the_same_result(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await persist(factory, auth_critical(0))
        svc = service(factory)
        await svc.restore_state(at(20))
        first = (await svc.assess([], at(20))).breakdown.to_dict()
        await svc.restore_state(at(20))
        assert (await svc.assess([], at(20))).breakdown.to_dict() == first

    async def test_a_raised_state_is_not_dropped_instantly_after_a_long_outage(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        first = service(factory)
        (event,) = await persist(factory, malicious(0))
        await first.assess([event], at(0))
        assert first.state is D

        restarted = service(factory)
        await restarted.restore_state(at(5000))  # evidence long expired
        assert (await restarted.assess([], at(5000))).defense_state is D
        assert (await restarted.assess([], at(5029))).defense_state is D
        assert (await restarted.assess([], at(5030))).defense_state is A  # one level per cooldown

    async def test_a_restart_in_the_middle_of_a_run_changes_nothing_that_follows(self) -> None:
        async def play(restart_at: float | None) -> list[tuple[float, DefenseState]]:
            eng, f = await make_factory()
            try:
                svc = service(f)
                events = await persist(f, cpu(0), net(10), auth_suspicious(20), auth_critical(30))
                times = {0: events[0], 10: events[1], 20: events[2], 30: events[3]}
                out: list[tuple[float, DefenseState]] = []
                t = 0.0
                while t <= 420:
                    if restart_at is not None and t == restart_at:
                        svc = service(f)
                        await svc.restore_state(at(t))
                    decision = await svc.assess(
                        [times[int(t)]] if int(t) in times and t == int(t) else [], at(t)
                    )
                    out.append((round(decision.threat_score, 6), decision.defense_state))
                    t += 5
                return out
            finally:
                await eng.dispose()

        order = list(DefenseState)
        uninterrupted = await play(None)
        # The only thing a restart cannot recover is a timer that was mid-flight, so the
        # restored machine starts a fresh cooldown. That may delay a step DOWN; the
        # contract is that it never makes the state less cautious, and never changes
        # the score.
        settle = 3 * CONFIG.state.cooldown_seconds
        for restart_at in (35.0, 60.0, 120.0, 200.0):
            restarted = await play(restart_at)
            assert len(restarted) == len(uninterrupted)
            for i, ((score_a, state_a), (score_b, state_b)) in enumerate(
                zip(uninterrupted, restarted, strict=True)
            ):
                t = i * 5
                assert score_b == score_a, f"score differs at t={t} (restart {restart_at})"
                assert order.index(state_b) >= order.index(state_a), (
                    f"restart made the state less cautious at t={t} (restart {restart_at})"
                )
                if t >= restart_at + settle:
                    assert state_b == state_a, f"did not converge by t={t} (restart {restart_at})"


class TestRestartRecoversTheSituation:
    async def test_an_open_situation_survives_a_restart_with_the_same_id_and_no_new_incident(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        (event,) = await persist(factory, malicious(0))
        opening = await svc.assess([event], at(0))
        assert opening.new_situation and ActionType.RECORD_INCIDENT in opening.recommended_actions

        restarted = service(factory)
        await restarted.restore_state(at(10))
        assert restarted.situation_id == opening.situation_id
        later = await run_ticks(restarted, 10, 200, 10)
        assert incident_decisions(later) == []
        assert {d.situation_id for d in later if d.defense_state is not R} == {opening.situation_id}

    async def test_a_restart_just_after_a_situation_closed_still_merges_a_quick_re_escalation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        (first,) = await persist(factory, malicious(0))
        opening = await svc.assess([first], at(0))
        ticks = await run_ticks(svc, 5, 400, 5)
        closed_at = next(d.calculated_at for d in ticks if d.defense_state is R)

        restarted = service(factory)
        resume_t = (closed_at - at(0)).total_seconds() + 5
        await restarted.restore_state(at(resume_t))
        (second,) = await persist(factory, malicious(resume_t + 10))
        decision = await restarted.assess([second], at(resume_t + 10))
        assert decision.defense_state is not R
        assert decision.new_situation is False
        assert decision.situation_id == opening.situation_id
        assert ActionType.RECORD_INCIDENT not in decision.recommended_actions

    async def test_a_situation_opened_outside_the_replay_window_is_adopted(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        svc = service(factory)
        events = await persist(factory, auth_suspicious(0), auth_critical(5))
        await svc.assess([events[0]], at(0))  # RELAXED -> ALERT (opens the situation)
        await svc.assess([events[1]], at(5))  # ALERT -> DEFENSIVE
        monkeypatch.setattr(service_module, "RESTORE_TRANSITION_LIMIT", 1)

        restarted = service(factory)
        await restarted.restore_state(at(8))
        assert restarted.state is D
        assert restarted.situation_id is not None  # adopted, not lost
        later = await run_ticks(restarted, 8, 60, 4)
        assert incident_decisions(later) == []


class TestRecordIncidentIsEdgeTriggered:
    async def test_it_is_recommended_exactly_once_across_a_whole_incident(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        events = await persist(
            factory, cpu(0), net(5), auth_suspicious(100), auth_critical(105), malicious(125)
        )
        decisions: list[Decision] = []
        timeline = {0: events[0], 5: events[1], 100: events[2], 105: events[3], 125: events[4]}
        for t in range(0, 600, 5):
            decisions.append(await svc.assess([timeline[t]] if t in timeline else [], at(t)))

        assert {d.defense_state for d in decisions} == {R, A, D, G}  # a full climb and descent
        recommended = incident_decisions(decisions)
        assert len(recommended) == 1
        assert recommended[0].new_situation is True
        assert recommended[0].state_changed is True
        assert recommended[0].previous_state is R

    async def test_escalating_inside_a_situation_does_not_record_another(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        events = await persist(
            factory, auth_suspicious(0), auth_critical(5), malicious(10), cpu(10)
        )
        first = await svc.assess([events[0]], at(0))
        rest = [
            await svc.assess([events[1]], at(5)),
            await svc.assess([events[2], events[3]], at(10)),
            await svc.assess([], at(11)),
            await svc.assess([], at(12)),
        ]
        assert ActionType.RECORD_INCIDENT in first.recommended_actions
        assert incident_decisions(rest) == []
        assert any(d.state_changed for d in rest), "the state did escalate within the situation"
        assert {d.situation_id for d in rest} == {first.situation_id}

    async def test_steady_state_decisions_never_recommend_an_incident(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        (event,) = await persist(factory, malicious(0))
        await svc.assess([event], at(0))
        steady = await run_ticks(svc, 1, 55, 1)
        assert len(steady) == 55
        assert incident_decisions(steady) == []
        assert all(ActionType.INCREASE_MONITORING in d.recommended_actions for d in steady)

    async def test_relaxed_decisions_carry_no_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        decision = await svc.assess([], at(0))
        assert decision.situation_id is None
        assert decision.new_situation is False

    async def test_a_re_escalation_soon_after_recovery_is_the_same_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        first, second = await persist(factory, malicious(0), malicious(300))
        opening = await svc.assess([first], at(0))
        ticks = await run_ticks(svc, 5, 295, 5)
        assert any(d.defense_state is R for d in ticks), "the first situation must have ended"
        again = await svc.assess([second], at(300))
        assert again.defense_state is not R
        assert again.new_situation is False
        assert again.situation_id == opening.situation_id
        assert ActionType.RECORD_INCIDENT not in again.recommended_actions

    async def test_a_new_escalation_after_the_reopen_window_is_a_new_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        config = ThreatConfig(ScoringConfig(), StateConfig(), incident_reopen_seconds=30)
        svc = service(factory, config)
        first, second = await persist(factory, malicious(0), malicious(600))
        opening = await svc.assess([first], at(0))
        ticks = await run_ticks(svc, 5, 595, 5)
        assert any(d.defense_state is R for d in ticks)
        again = await svc.assess([second], at(600))
        assert again.new_situation is True
        assert again.situation_id != opening.situation_id
        assert ActionType.RECORD_INCIDENT in again.recommended_actions

    async def test_a_noisy_boundary_cannot_produce_a_stream_of_incidents(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        decisions: list[Decision] = []
        # A burst of suspicious activity every 100 s for an hour.
        for cycle in range(36):
            (event,) = await persist(factory, auth_suspicious(cycle * 100))
            decisions.append(await svc.assess([event], at(cycle * 100)))
            decisions.extend(await run_ticks(svc, cycle * 100 + 10, cycle * 100 + 90, 10))
        assert len(incident_decisions(decisions)) <= 2

    async def test_a_failed_save_does_not_use_up_the_one_incident_recommendation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        (event,) = await persist(factory, malicious(0))
        svc = ThreatAssessmentService(CONFIG, _FailingFactory())  # type: ignore[arg-type]
        with pytest.raises(DatabaseError):
            await svc.assess([event], at(0))
        assert svc.situation_id is None  # nothing was recorded as opened

        svc._session_factory = factory  # the database recovers
        recovered = await svc.assess([], at(1))
        assert recovered.new_situation is True
        assert ActionType.RECORD_INCIDENT in recovered.recommended_actions
        assert incident_decisions(await run_ticks(svc, 2, 30, 2)) == []  # and only once

    async def test_every_decision_in_a_situation_names_it(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        (event,) = await persist(factory, malicious(0))
        opening = await svc.assess([event], at(0))
        ticks = await run_ticks(svc, 5, 100, 5)
        raised = [d for d in ticks if d.defense_state is not R]
        assert raised
        assert all(d.situation_id == opening.situation_id for d in raised)
        assert opening.to_dict()["situation_id"] == opening.situation_id  # type: ignore[index]


HEAVY = ThreatConfig(
    ScoringConfig(weight_severity=0.9, weight_confidence=0.1), StateConfig()
)  # a single critical event alone scores ~0.995


class TestAggressiveBypassThroughTheService:
    async def test_a_lone_critical_event_cannot_reach_aggressive_even_with_a_near_maximal_score(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, HEAVY)
        (event,) = await persist(factory, malicious(0))
        decisions = [await svc.assess([event], at(0))]
        decisions += [await svc.assess([], at(i * 0.5)) for i in range(1, 6)]
        assert decisions[0].threat_score > 0.9
        assert {d.defense_state for d in decisions} <= {A, D}
        assert any(ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION in d.reason_codes for d in decisions)
        assert all(d.breakdown.corroborating_categories == 1 for d in decisions)

    async def test_a_second_independent_category_unlocks_the_bypass(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, HEAVY)
        events = await persist(factory, malicious(0), cpu(0))
        await svc.assess([events[0]], at(0))
        withheld = await svc.assess([], at(0.1))
        assert withheld.defense_state is not G
        unlocked = [await svc.assess([events[1]], at(0.2)), await svc.assess([], at(0.3))]
        assert unlocked[-1].defense_state is G
        assert unlocked[-1].breakdown.corroborating_categories >= 2

    async def test_duplicate_events_from_one_signal_do_not_corroborate(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, HEAVY)
        events = await persist(factory, *[malicious(i * 0.01) for i in range(10)])
        decisions = [await svc.assess(events, at(0.1))]
        decisions += [await svc.assess([], at(0.2 + i * 0.1)) for i in range(5)]
        assert all(d.breakdown.corroborating_categories == 1 for d in decisions)
        assert all(d.defense_state is not G for d in decisions)

    async def test_every_level_appears_in_the_audit_trail(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        from sqlalchemy import select

        from database.models import DefenseStateChange

        svc = service(factory, HEAVY)
        events = await persist(factory, auth_critical(0), cpu(0))
        for t, batch in enumerate([[events[0], events[1]], [], [], []]):
            await svc.assess(batch, at(t * 0.1))
        async with factory() as session:
            rows = (
                (await session.execute(select(DefenseStateChange).order_by(DefenseStateChange.id)))
                .scalars()
                .all()
            )
        path: list[Any] = [rows[0].from_state, *[r.to_state for r in rows]]
        # RELAXED -> DEFENSIVE (floor) -> AGGRESSIVE (corroborated bypass): none skipped silently
        assert path[0] == "RELAXED"
        assert path[-1] == "AGGRESSIVE"
        assert all(a != b for a, b in zip(path, path[1:], strict=False))
