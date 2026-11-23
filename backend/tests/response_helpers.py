"""Builders for response-layer tests. Deterministic: no wall clock."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database.engine import create_all_tables
from database.models import DetectionEvent, Incident, ResponseAction
from database.repositories import DetectionEventRepository
from models.enums import ActionType, Classification, DefenseState, Severity
from tests.threat_helpers import at
from threat.decision import Decision, recommended_actions_for
from threat.evidence import SignalCategory
from threat.reasons import ReasonCode
from threat.scorer import ScoreBreakdown, SignalSummary
from threat.state_machine import StateEvaluation

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)


def signal(event_id: int | None, event_type: str = "suspicious_process") -> SignalSummary:
    return SignalSummary(
        category=SignalCategory.EXECUTION,
        event_type=event_type,
        severity=Severity.CRITICAL,
        classification=Classification.HIGH_CONFIDENCE,
        confidence=0.95,
        peak_confidence=0.95,
        strength=1.0,
        freshness=1.0,
        count=1,
        escalated=False,
        is_synthetic=True,
        event_id=event_id,
    )


def decision(
    t: float,
    state: DefenseState,
    *,
    situation_id: int | None = None,
    previous: DefenseState | None = None,
    new_situation: bool = False,
    actions: Iterable[ActionType] | None = None,
    event_ids: Iterable[int] = (),
    score: float = 0.6,
    reasons: tuple[ReasonCode, ...] = (ReasonCode.CRITICAL_EVENT,),
    ended: int | None = None,
    recovered: float | None = None,
    ended_reason: str = "QUIET_FOR_REOPEN_WINDOW",
) -> Decision:
    """A Decision at T0+t. Actions default to what the decision layer would recommend."""
    now = at(t)
    previous_state = state if previous is None else previous
    recommended = (
        tuple(actions)
        if actions is not None
        else recommended_actions_for(state, new_evidence=True, record_incident=new_situation)
    )
    signals = tuple(signal(e) for e in event_ids)
    breakdown = ScoreBreakdown(
        calculated_at=now,
        severity_contribution=score,
        confidence_contribution=0.0,
        repetition_contribution=0.0,
        escalation_contribution=0.0,
        correlation_contribution=0.0,
        cross_domain_contribution=0.0,
        raw_total=score,
        score_before_decay=score,
        decay=0.0,
        final_score=score,
        signals=signals,
        signal_count=len(signals),
        active_categories=(SignalCategory.EXECUTION,) if signals else (),
        reason_codes=reasons,
        active_max_severity=Severity.CRITICAL if signals else None,
        severe_active=bool(signals),
        corroborating_categories=1 if signals else 0,
    )
    evaluation = StateEvaluation(
        previous_state=previous_state,
        new_state=state,
        previous_score=None,
        score=score,
        evaluated_at=now,
        reason_codes=(),
    )
    return Decision(
        calculated_at=now,
        threat_score=score,
        defense_state=state,
        previous_state=previous_state,
        state_changed=previous_state != state,
        reason_codes=reasons,
        recommended_actions=recommended,
        breakdown=breakdown,
        evaluation=evaluation,
        situation_id=situation_id,
        new_situation=new_situation,
        ended_situation_id=ended,
        ended_situation_recovered_at=(
            None if ended is None else at(t if recovered is None else recovered)
        ),
        ended_situation_reason=None if ended is None else ended_reason,
    )


async def new_database() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    return eng, async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def database() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng, factory = await new_database()
    try:
        yield factory
    finally:
        await eng.dispose()


async def persisted_event(factory: async_sessionmaker[AsyncSession], t: float = 0.0) -> int:
    """Persist one detection event and return its id."""
    async with factory() as session, session.begin():
        event = await DetectionEventRepository(session).insert(
            DetectionEvent(
                detected_at=at(t),
                rule_id="DET-SYN-001",
                rule_name="Synthetic security event",
                severity="CRITICAL",
                metric_key="synthetic:suspicious_process",
                is_synthetic=True,
                event_type="suspicious_process",
                classification="HIGH_CONFIDENCE",
                confidence=0.95,
            )
        )
    return event.id


async def actions(factory: async_sessionmaker[AsyncSession]) -> list[ResponseAction]:
    async with factory() as session:
        rows = await session.execute(select(ResponseAction).order_by(ResponseAction.id))
        return list(rows.scalars().all())


async def incidents(factory: async_sessionmaker[AsyncSession]) -> list[Incident]:
    async with factory() as session:
        rows = await session.execute(select(Incident).order_by(Incident.id))
        return list(rows.scalars().all())
