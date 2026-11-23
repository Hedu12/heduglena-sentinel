"""
Read-only queries for explanations and incident views.

SELECT statements only: this module cannot insert, update or delete anything
(tests/security/test_ai_boundary.py checks it). Sessions are opened by the
callers and never committed.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import (
    AIExplanationRecord,
    DefenseStateChange,
    DetectionEvent,
    Incident,
    ResponseAction,
    ThreatScore,
)


async def incident(session: AsyncSession, incident_id: str) -> Incident | None:
    result = await session.execute(select(Incident).where(Incident.incident_id == incident_id))
    return result.scalar_one_or_none()


async def incidents(session: AsyncSession, limit: int) -> list[Incident]:
    result = await session.execute(
        select(Incident).order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def transitions_from(
    session: AsyncSession, first_id: int, until: datetime | None, limit: int
) -> list[DefenseStateChange]:
    """The newest `limit` transitions with id >= first_id (and not after `until`), oldest first."""
    query = select(DefenseStateChange).where(DefenseStateChange.id >= first_id)
    if until is not None:
        query = query.where(DefenseStateChange.changed_at <= until)
    query = query.order_by(DefenseStateChange.id.desc()).limit(limit)
    rows = list((await session.execute(query)).scalars().all())
    return rows[::-1]


async def events_by_ids(session: AsyncSession, ids: Iterable[int]) -> list[DetectionEvent]:
    wanted = sorted(set(ids))
    if not wanted:
        return []
    result = await session.execute(select(DetectionEvent).where(DetectionEvent.id.in_(wanted)))
    return list(result.scalars().all())


async def actions_for_situation(
    session: AsyncSession, situation_id: int, until: datetime | None, limit: int
) -> list[ResponseAction]:
    """The newest `limit` response records of a situation, oldest first."""
    query = select(ResponseAction).where(ResponseAction.situation_id == situation_id)
    if until is not None:
        query = query.where(ResponseAction.executed_at <= until)
    query = query.order_by(ResponseAction.id.desc()).limit(limit)
    rows = list((await session.execute(query)).scalars().all())
    return rows[::-1]


async def latest_score(session: AsyncSession) -> ThreatScore | None:
    result = await session.execute(
        select(ThreatScore)
        .order_by(ThreatScore.calculated_at.desc(), ThreatScore.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def explanations(
    session: AsyncSession, incident_id: str, limit: int
) -> list[AIExplanationRecord]:
    """Newest first."""
    result = await session.execute(
        select(AIExplanationRecord)
        .where(AIExplanationRecord.incident_id == incident_id)
        .order_by(AIExplanationRecord.id.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def recorded_trigger_keys(
    session: AsyncSession, incident_id: str, keys: Iterable[str]
) -> set[str]:
    """Which of `keys` already have an explanation record for the incident."""
    wanted = sorted(set(keys))
    if not wanted:
        return set()
    result = await session.execute(
        select(AIExplanationRecord.trigger_key).where(
            AIExplanationRecord.incident_id == incident_id,
            AIExplanationRecord.trigger_key.in_(wanted),
        )
    )
    return {k for k in result.scalars().all() if k is not None}


async def latest_triggered_explanation(
    session: AsyncSession, incident_id: str
) -> AIExplanationRecord | None:
    """The incident's explanation record with the latest decision time (any status)."""
    result = await session.execute(
        select(AIExplanationRecord)
        .where(
            AIExplanationRecord.incident_id == incident_id,
            AIExplanationRecord.decision_at.is_not(None),
        )
        .order_by(AIExplanationRecord.decision_at.desc(), AIExplanationRecord.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def transitions_before(
    session: AsyncSession, transition_id: int, limit: int
) -> list[DefenseStateChange]:
    """The newest `limit` transitions with id < transition_id, in (changed_at, id) order."""
    result = await session.execute(
        select(DefenseStateChange)
        .where(DefenseStateChange.id < transition_id)
        .order_by(DefenseStateChange.id.desc())
        .limit(limit)
    )
    rows = list(result.scalars().all())
    return sorted(rows, key=lambda c: (c.changed_at, c.id))


async def latest_valid_explanation(
    session: AsyncSession, incident_id: str
) -> AIExplanationRecord | None:
    result = await session.execute(
        select(AIExplanationRecord)
        .where(
            AIExplanationRecord.incident_id == incident_id,
            AIExplanationRecord.status == "VALID",
        )
        .order_by(AIExplanationRecord.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()
