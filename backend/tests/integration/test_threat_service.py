"""
Integration tests for ThreatAssessmentService with a real (in-memory) database.

Covers persistence of scores and state transitions, structured evidence,
append-only behaviour, failure rollback, restart recovery, and the separation
between evidence (detection events), scoring, and incidents.
"""

from __future__ import annotations

import asyncio
import json
import logging
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
from core.exceptions import DatabaseError
from database.engine import create_all_tables, drop_all_tables
from database.models import DefenseStateChange, DetectionEvent, Incident, ThreatScore
from models.enums import ActionType, DefenseState
from tests.threat_helpers import at
from threat.config import ThreatConfig
from threat.reasons import ReasonCode
from threat.service import ThreatAssessmentService

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)
CONFIG = ThreatConfig.from_settings(Settings())


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    yield async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    await drop_all_tables(eng)
    await eng.dispose()


def service(factory: async_sessionmaker[AsyncSession]) -> ThreatAssessmentService:
    return ThreatAssessmentService(CONFIG, factory)


_ids = {"n": 0}


def detection(
    event_type: str,
    severity: str,
    classification: str,
    confidence: float,
    t: float,
    *,
    synthetic: bool = False,
    event_id: int | None = None,
) -> DetectionEvent:
    """An in-memory DetectionEvent as the detection engine would have persisted it."""
    _ids["n"] += 1
    event = DetectionEvent(
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
    event.id = event_id if event_id is not None else _ids["n"] + 10_000
    return event


def malicious_process(t: float = 0.0) -> DetectionEvent:
    return detection("suspicious_process", "CRITICAL", "HIGH_CONFIDENCE", 0.95, t, synthetic=True)


def cpu_event(t: float = 0.0) -> DetectionEvent:
    return detection("cpu_sustained_high", "MEDIUM", "INFORMATIONAL", 0.3, t)


async def rows(
    factory: async_sessionmaker[AsyncSession], model: type[ThreatScore] | type[DefenseStateChange]
) -> list[ThreatScore] | list[DefenseStateChange]:
    async with factory() as session:
        result = await session.execute(select(model).order_by(model.id))  # type: ignore[attr-defined]
        return list(result.scalars().all())


class _FailingFactory:
    """A session factory whose sessions cannot be opened."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def __call__(self) -> _FailingFactory:
        return self

    async def __aenter__(self) -> AsyncSession:
        raise self._error

    async def __aexit__(self, *exc: object) -> bool:
        return False


class TestScorePersistence:
    async def test_first_assessment_persists_a_baseline_score_row(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        decision = await svc.assess([], at(0))
        assert decision.threat_score == 0.0
        assert decision.defense_state is R
        assert decision.recommended_actions == ()
        assert ReasonCode.NO_ACTIVE_EVIDENCE in decision.reason_codes
        assert decision.score_record_id is not None
        assert decision.transition_id is None
        (row,) = await rows(factory, ThreatScore)
        assert row.score == 0.0
        assert row.defense_state == "RELAXED"

    async def test_unchanged_score_is_not_persisted_again(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([], at(0))
        for t in (1, 2, 3):
            decision = await svc.assess([], at(t))
            assert decision.score_record_id is None
        assert len(await rows(factory, ThreatScore)) == 1

    async def test_a_material_score_change_is_persisted(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([], at(0))
        decision = await svc.assess([cpu_event(1)], at(1))
        assert decision.score_record_id is not None
        assert len(await rows(factory, ThreatScore)) == 2

    async def test_decay_over_time_is_recorded_as_score_history(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([cpu_event(0)], at(0))
        for t in range(10, 250, 10):
            await svc.assess([], at(t))
        scores = [r.score for r in await rows(factory, ThreatScore)]
        assert len(scores) > 3
        assert scores == sorted(scores, reverse=True)
        assert all(0.0 <= s <= 1.0 for s in scores)

    async def test_score_row_carries_the_structured_breakdown(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        decision = await svc.assess([malicious_process(0)], at(0))
        row = (await rows(factory, ThreatScore))[0]
        breakdown = json.loads(row.breakdown or "")
        assert breakdown["final_score"] == pytest.approx(row.score)
        for key in (
            "severity_contribution",
            "confidence_contribution",
            "repetition_contribution",
            "correlation_contribution",
            "decay",
            "reason_codes",
            "signals",
        ):
            assert key in breakdown
        assert "CRITICAL_EVENT" in breakdown["reason_codes"]
        assert json.loads(row.contributing_events or "[]") == [
            s.event_id for s in decision.breakdown.signals
        ]


class TestTransitionPersistence:
    async def test_transition_is_persisted_with_structured_evidence(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        event = malicious_process(0)
        decision = await svc.assess([event], at(0))

        assert decision.state_changed is True
        assert decision.defense_state is D
        assert decision.transition_id is not None
        (change,) = await rows(factory, DefenseStateChange)
        assert (change.from_state, change.to_state) == ("RELAXED", "DEFENSIVE")
        assert change.trigger_score == pytest.approx(decision.threat_score)
        assert change.previous_score is None  # first evaluation: nothing before it
        assert change.reason in {c.value for c in decision.evaluation.reason_codes}
        assert json.loads(change.trigger_event_ids or "[]") == [event.id]
        assert change.changed_at.replace(tzinfo=None) == at(0).replace(tzinfo=None)

        evidence = json.loads(change.evidence or "")
        assert evidence["previous_state"] == "RELAXED"
        assert evidence["new_state"] == "DEFENSIVE"
        assert evidence["new_score"] == pytest.approx(decision.threat_score)
        assert evidence["transition_reason_codes"]
        assert "CRITICAL_EVENT" in evidence["score_reason_codes"]
        assert evidence["triggering_signals"][0]["event_type"] == "suspicious_process"
        assert evidence["breakdown"]["final_score"] == pytest.approx(decision.threat_score)

    async def test_previous_score_is_recorded_on_later_transitions(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        first = await svc.assess([cpu_event(0)], at(0))
        decision = await svc.assess([malicious_process(5)], at(5))
        assert decision.state_changed
        change = (await rows(factory, DefenseStateChange))[-1]
        assert change.previous_score == pytest.approx(first.threat_score)
        assert change.trigger_score == pytest.approx(decision.threat_score)
        assert change.trigger_score > change.previous_score

    async def test_no_transition_row_when_the_state_is_unchanged(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([cpu_event(0)], at(0))
        await svc.assess([], at(5))
        assert await rows(factory, DefenseStateChange) == []

    async def test_full_climb_and_descent_is_persisted_in_order(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(0)], at(0))  # RELAXED -> DEFENSIVE
        for t in range(10, 600, 5):
            await svc.assess([], at(t))
        changes = await rows(factory, DefenseStateChange)
        path = [changes[0].from_state, *[c.to_state for c in changes]]
        assert path == ["RELAXED", "DEFENSIVE", "ALERT", "RELAXED"]
        times = [c.changed_at for c in changes]
        assert times == sorted(times)
        # One level at a time, each at least a cooldown apart.
        for earlier, later in zip(changes[1:], changes[2:], strict=False):
            gap = (later.changed_at - earlier.changed_at).total_seconds()
            assert gap >= CONFIG.state.cooldown_seconds

    async def test_persisted_rows_are_append_only(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([cpu_event(0)], at(0))
        await svc.assess([malicious_process(5)], at(5))
        snapshot = [
            (r.id, r.changed_at, r.from_state, r.to_state, r.trigger_score, r.evidence)
            for r in await rows(factory, DefenseStateChange)
        ]
        score_snapshot = [(r.id, r.score, r.breakdown) for r in await rows(factory, ThreatScore)]
        for t in range(10, 400, 10):
            await svc.assess([], at(t))
        after = await rows(factory, DefenseStateChange)
        assert [
            (r.id, r.changed_at, r.from_state, r.to_state, r.trigger_score, r.evidence)
            for r in after[: len(snapshot)]
        ] == snapshot
        after_scores = await rows(factory, ThreatScore)
        assert [(r.id, r.score, r.breakdown) for r in after_scores[: len(score_snapshot)]] == (
            score_snapshot
        )
        assert len(after) > len(snapshot)


class TestDecisionOutput:
    async def test_decision_recommends_but_does_not_execute(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        decision = await svc.assess([malicious_process(0)], at(0))
        assert decision.defense_state is D
        assert ActionType.SIMULATE_IP_BLOCK in decision.recommended_actions
        assert ActionType.SIMULATE_QUARANTINE not in decision.recommended_actions
        assert all(isinstance(a, ActionType) for a in decision.recommended_actions)
        d = decision.to_dict()
        assert d["defense_state"] == "DEFENSIVE"
        assert "CRITICAL_EVENT" in d["reason_codes"]  # type: ignore[operator]

    async def test_relaxed_alerts_only_when_an_evaluation_brings_new_evidence(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        fresh = await svc.assess([cpu_event(0)], at(0))
        decaying = [await svc.assess([], at(t)) for t in (5, 60, 120)]
        another = await svc.assess([cpu_event(130)], at(130))
        assert fresh.defense_state is R
        assert fresh.recommended_actions == (ActionType.GENERATE_ALERT,)
        for d in decaying:
            assert d.defense_state is R and d.threat_score > 0  # evidence still active
            assert d.recommended_actions == ()  # but nothing new to alert about
        assert another.recommended_actions == (ActionType.GENERATE_ALERT,)

    async def test_a_malformed_event_alone_is_not_new_evidence(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        bad = detection("cpu_sustained_high", "BOGUS", "INFORMATIONAL", 0.3, 0)
        decision = await svc.assess([bad], at(0))
        assert decision.recommended_actions == ()

    async def test_a_redelivered_event_is_not_new_evidence(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        event = cpu_event(0)
        first = await svc.assess([event], at(0))
        again = await svc.assess([event], at(1))
        assert first.recommended_actions == (ActionType.GENERATE_ALERT,)
        assert again.recommended_actions == ()

    async def test_the_decision_reports_when_a_situation_is_over_for_good(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(0)], at(0))
        opened = svc.situation_id
        assert opened is not None
        t, decision = 0, None
        while t < 2_000:
            t += 10
            decision = await svc.assess([], at(t))
            if decision.defense_state is R:
                break
        assert decision is not None and decision.defense_state is R
        recovered = t
        window = CONFIG.incident_reopen_seconds
        inside = await svc.assess([], at(recovered + window - 1))
        after = await svc.assess([], at(recovered + window))
        assert decision.ended_situation_id is None
        assert inside.ended_situation_id is None
        assert after.ended_situation_id == opened
        assert after.ended_situation_recovered_at == at(recovered)
        assert after.ended_situation_reason == "QUIET_FOR_REOPEN_WINDOW"
        assert after.to_dict()["ended_situation_id"] == opened

    async def test_a_restart_still_reports_the_ended_situation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(0)], at(0))
        opened = svc.situation_id
        t = 0
        while svc.state is not R and t < 2_000:
            t += 10
            await svc.assess([], at(t))
        assert svc.state is R
        window = CONFIG.incident_reopen_seconds

        restarted = service(factory)
        await restarted.restore_state(at(t + window))
        decision = await restarted.assess([], at(t + window))
        assert decision.ended_situation_id == opened
        assert decision.ended_situation_recovered_at == at(t)

    async def test_evidence_does_not_create_incidents(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        for t, event in enumerate([cpu_event(0), malicious_process(5)]):
            await svc.assess([event], at(t * 5))
        for t in range(20, 300, 20):
            await svc.assess([], at(t))
        async with factory() as session:
            count = (await session.execute(select(func.count()).select_from(Incident))).scalar_one()
        assert count == 0

    async def test_active_critical_evidence_floors_the_state_despite_a_low_score(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(0)], at(0))
        # Fifty seconds later the score has decayed below the DEFENSIVE exit threshold,
        # but the critical event is still inside the 60 s active window.
        decision = await svc.assess([], at(50))
        assert decision.threat_score < CONFIG.state.exit(D) + 0.2
        assert decision.defense_state is D
        # A weak, unrelated event cannot pull the state down.
        decision = await svc.assess([cpu_event(55)], at(55))
        assert decision.defense_state is D


class TestEvidenceHandling:
    async def test_a_duplicate_event_is_not_counted_twice_across_calls(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        event = cpu_event(0)
        first = await svc.assess([event], at(0))
        second = await svc.assess([event], at(0))
        assert second.threat_score == first.threat_score
        assert second.breakdown.signals[0].count == 1

    async def test_malformed_event_is_skipped_without_breaking_scoring(
        self, factory: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
    ) -> None:
        svc = service(factory)
        bad = detection("cpu_sustained_high", "BOGUS", "INFORMATIONAL", 0.3, 0)
        with caplog.at_level(logging.WARNING, logger="threat.service"):
            decision = await svc.assess([bad, malicious_process(0)], at(0))
        assert decision.defense_state is D
        assert any("malformed" in r.getMessage() for r in caplog.records)

    async def test_future_dated_evidence_cannot_hold_the_score_up(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(10_000_000)], at(0))  # claims to be from the future
        late = await svc.assess([], at(400))
        assert late.threat_score == 0.0

    async def test_naive_now_is_rejected(self, factory: async_sessionmaker[AsyncSession]) -> None:
        from datetime import datetime

        with pytest.raises(ValueError):
            await service(factory).assess([], datetime(2025, 1, 1))


class TestFailureHandling:
    async def test_persistence_failure_rolls_the_state_back_and_raises(
        self, factory: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
    ) -> None:
        svc = ThreatAssessmentService(CONFIG, _FailingFactory(RuntimeError("db down")))  # type: ignore[arg-type]
        with caplog.at_level(logging.ERROR, logger="threat.service"):
            with pytest.raises(DatabaseError):
                await svc.assess([malicious_process(0)], at(0))
        assert svc.state is R  # memory never claims a state the audit trail lacks
        assert any("rolled back" in r.getMessage() for r in caplog.records)

    async def test_the_transition_is_re_derived_and_saved_once_the_database_recovers(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = ThreatAssessmentService(CONFIG, _FailingFactory(RuntimeError("db down")))  # type: ignore[arg-type]
        with pytest.raises(DatabaseError):
            await svc.assess([malicious_process(0)], at(0))
        svc._session_factory = factory  # the database recovers
        decision = await svc.assess([], at(1))  # the evidence is still held
        assert decision.defense_state is D
        assert decision.state_changed is True
        assert decision.transition_id is not None
        assert len(await rows(factory, DefenseStateChange)) == 1

    async def test_cancellation_rolls_back_and_propagates(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = ThreatAssessmentService(CONFIG, _FailingFactory(asyncio.CancelledError()))  # type: ignore[arg-type]
        with pytest.raises(asyncio.CancelledError):
            await svc.assess([malicious_process(0)], at(0))
        assert svc.state is R


class TestRestartAndReset:
    async def test_state_is_restored_from_the_last_persisted_transition(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        first = service(factory)
        await first.assess([malicious_process(0)], at(0))
        assert first.state is D

        restarted = service(factory)
        assert restarted.state is R
        assert await restarted.restore_state(at(1)) is D
        assert restarted.state is D

    async def test_restore_on_an_empty_database_stays_relaxed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        assert await service(factory).restore_state(at(0)) is R

    async def test_restored_machine_still_obeys_the_cooldown(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        first = service(factory)
        await first.assess([malicious_process(0)], at(0))
        restarted = service(factory)
        await restarted.restore_state(at(100))
        # The score has decayed well below the exit threshold, but descent is still
        # gradual: the restored machine starts a fresh cooldown, one level at a time.
        assert (await restarted.assess([], at(100))).defense_state is D
        assert (await restarted.assess([], at(130))).defense_state is A

    async def test_reset_forgets_evidence_and_returns_to_relaxed(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        await svc.assess([malicious_process(0)], at(0))
        svc.reset()
        assert svc.state is R
        assert (await svc.assess([], at(1))).threat_score == 0.0
