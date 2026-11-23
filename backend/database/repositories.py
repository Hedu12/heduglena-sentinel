"""
Data-access layer (repository pattern).

Each repository class owns the queries for one table family.
Route handlers and domain services call repositories; they never
construct SQLAlchemy queries directly (architecture principle P-06).

All write operations are INSERT-only on audit tables (P-07).
The Baseline repository is the sole exception — it uses UPSERT
because a baseline is a live accumulator, not an event record.

No business logic lives here. Repositories are pure data access.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import (
    AIExplanationRecord,
    Baseline,
    DefenseStateChange,
    DetectionEvent,
    Incident,
    ResponseAction,
    TelemetrySample,
    ThreatScore,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TelemetrySampleRepository
# ---------------------------------------------------------------------------


class TelemetrySampleRepository:
    """Read/write access for telemetry_samples. INSERT-only writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, sample: TelemetrySample) -> TelemetrySample:
        """Persist a new telemetry sample and return it with its assigned id."""
        self._s.add(sample)
        await self._s.flush()
        await self._s.refresh(sample)
        return sample

    async def get_latest(self) -> TelemetrySample | None:
        """Return the most recent sample, or None if the table is empty."""
        result = await self._s.execute(
            select(TelemetrySample).order_by(TelemetrySample.collected_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def get_since(self, since: datetime, limit: int = 500) -> Sequence[TelemetrySample]:
        """Return samples collected after `since`, newest-first, up to limit."""
        result = await self._s.execute(
            select(TelemetrySample)
            .where(TelemetrySample.collected_at > since)
            .order_by(TelemetrySample.collected_at.desc())
            .limit(limit)
        )
        return result.scalars().all()


# ---------------------------------------------------------------------------
# DetectionEventRepository
# ---------------------------------------------------------------------------


class DetectionEventRepository:
    """Read/write access for detection_events. INSERT-only writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, event: DetectionEvent) -> DetectionEvent:
        """Persist a new detection event and return it with its assigned id."""
        self._s.add(event)
        await self._s.flush()
        await self._s.refresh(event)
        return event

    async def get_by_id(self, event_id: int) -> DetectionEvent | None:
        """Return a single event by primary key."""
        return await self._s.get(DetectionEvent, event_id)

    async def get_since(
        self,
        since: datetime,
        severity: str | None = None,
        limit: int = 200,
    ) -> Sequence[DetectionEvent]:
        """
        Return events detected after `since`, optionally filtered by severity.
        Results are newest-first, up to limit.
        """
        q = (
            select(DetectionEvent)
            .where(DetectionEvent.detected_at > since)
            .order_by(DetectionEvent.detected_at.desc())
            .limit(limit)
        )
        if severity is not None:
            q = q.where(DetectionEvent.severity == severity)
        result = await self._s.execute(q)
        return result.scalars().all()

    async def get_recent_for_scoring(self, since: datetime) -> Sequence[DetectionEvent]:
        """
        Return all events since `since`, ordered oldest-first, for the
        threat scorer. No limit — the scorer needs the full window.
        """
        result = await self._s.execute(
            select(DetectionEvent)
            .where(DetectionEvent.detected_at >= since)
            .order_by(DetectionEvent.detected_at.asc())
        )
        return result.scalars().all()

    async def count_by_rule_since(self, rule_id: str, since: datetime) -> int:
        """Count events for a specific rule since a given time (for burst rules)."""
        from sqlalchemy import func

        result = await self._s.execute(
            select(func.count()).where(
                DetectionEvent.rule_id == rule_id,
                DetectionEvent.detected_at >= since,
            )
        )
        return result.scalar_one()


# ---------------------------------------------------------------------------
# IncidentRepository
# ---------------------------------------------------------------------------


class IncidentRepository:
    """Read/write access for incidents."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, incident: Incident) -> Incident:
        """Persist a new incident and return it with its assigned id."""
        self._s.add(incident)
        await self._s.flush()
        await self._s.refresh(incident)
        return incident

    async def get_by_incident_id(self, incident_id: str) -> Incident | None:
        """Look up an incident by its stable string identifier."""
        result = await self._s.execute(select(Incident).where(Incident.incident_id == incident_id))
        return result.scalar_one_or_none()

    async def get_all(self, status: str | None = None, limit: int = 50) -> Sequence[Incident]:
        """Return incidents, optionally filtered by status, newest-first."""
        q = select(Incident).order_by(Incident.created_at.desc()).limit(limit)
        if status is not None:
            q = q.where(Incident.status == status)
        result = await self._s.execute(q)
        return result.scalars().all()

    async def update_status(self, incident_id: str, status: str) -> Incident | None:
        """
        Update an incident's status.

        This is a deliberate UPDATE on a non-audit table (incidents are
        mutable records, unlike detection events or threat scores).
        Returns the updated incident or None if not found.
        """
        from sqlalchemy import update

        await self._s.execute(
            update(Incident).where(Incident.incident_id == incident_id).values(status=status)
        )
        await self._s.flush()
        return await self.get_by_incident_id(incident_id)

    async def resolve_if_open(
        self,
        incident_id: str,
        *,
        recovered_at: datetime,
        resolved_at: datetime,
        resolution: str,
    ) -> bool:
        """
        Mark an OPEN incident resolved. True if this call resolved it.

        Conditional on status = 'open', so it is idempotent (a second call changes
        nothing) and never overrides an analyst's 'investigating' status.
        """
        from sqlalchemy import update

        result = await self._s.execute(
            update(Incident)
            .where(Incident.incident_id == incident_id, Incident.status == "open")
            .values(
                status="resolved",
                recovered_at=recovered_at,
                resolved_at=resolved_at,
                resolution=resolution,
            )
        )
        await self._s.flush()
        return bool(getattr(result, "rowcount", 0) == 1)


# ---------------------------------------------------------------------------
# ThreatScoreRepository
# ---------------------------------------------------------------------------


class ThreatScoreRepository:
    """Read/write access for threat_scores. INSERT-only writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, score: ThreatScore) -> ThreatScore:
        """Persist a new score reading."""
        self._s.add(score)
        await self._s.flush()
        await self._s.refresh(score)
        return score

    async def get_latest(self) -> ThreatScore | None:
        """Return the most recent score reading."""
        result = await self._s.execute(
            select(ThreatScore).order_by(ThreatScore.calculated_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def get_since(self, since: datetime, limit: int = 3600) -> Sequence[ThreatScore]:
        """
        Return score readings since `since`, oldest-first (for timeline charts).
        Default limit 3600 covers one reading per second for one hour.
        """
        result = await self._s.execute(
            select(ThreatScore)
            .where(ThreatScore.calculated_at > since)
            .order_by(ThreatScore.calculated_at.asc())
            .limit(limit)
        )
        return result.scalars().all()


# ---------------------------------------------------------------------------
# DefenseStateChangeRepository
# ---------------------------------------------------------------------------


class DefenseStateChangeRepository:
    """Read/write access for defense_state_changes. INSERT-only writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, change: DefenseStateChange) -> DefenseStateChange:
        """Persist a state transition record."""
        self._s.add(change)
        await self._s.flush()
        await self._s.refresh(change)
        return change

    async def get_latest(self) -> DefenseStateChange | None:
        """Return the most recent state change, or None."""
        result = await self._s.execute(
            select(DefenseStateChange).order_by(DefenseStateChange.changed_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def get_all(self, limit: int = 100) -> Sequence[DefenseStateChange]:
        """Return state change history, newest-first."""
        result = await self._s.execute(
            select(DefenseStateChange).order_by(DefenseStateChange.changed_at.desc()).limit(limit)
        )
        return result.scalars().all()


# ---------------------------------------------------------------------------
# ResponseActionRepository
# ---------------------------------------------------------------------------


class ResponseActionRepository:
    """Read/write access for response_actions. INSERT-only writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, action: ResponseAction) -> ResponseAction:
        """
        Persist a response action.

        is_simulated defaults to True at the model level. The caller
        (ResponseGuard verdict) must explicitly pass is_simulated=False
        for live actions. This double-default is intentional (P-05).

        When triggering_event_id is provided, the relationship object is
        also set so SQLAlchemy's unit-of-work does not null the FK column
        during flush (MappedAsDataclass + relationship FK interaction).
        """
        # If a triggering_event_id is set, we need the ORM to know the
        # relationship object to prevent it nulling the FK during flush.
        # Load the event inline if not already attached.
        if action.triggering_event_id is not None and action.triggering_event is None:
            from database.models import DetectionEvent as _DE

            event_obj = await self._s.get(_DE, action.triggering_event_id)
            if event_obj is not None:
                object.__setattr__(action, "triggering_event", event_obj)

        self._s.add(action)
        await self._s.flush()
        await self._s.refresh(action)
        return action

    async def get_since(self, since: datetime, limit: int = 200) -> Sequence[ResponseAction]:
        """Return actions since `since`, newest-first."""
        result = await self._s.execute(
            select(ResponseAction)
            .where(ResponseAction.executed_at > since)
            .order_by(ResponseAction.executed_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

    async def get_all(self, limit: int = 200) -> Sequence[ResponseAction]:
        """Return all actions, newest-first."""
        result = await self._s.execute(
            select(ResponseAction).order_by(ResponseAction.executed_at.desc()).limit(limit)
        )
        return result.scalars().all()

    async def get_by_idempotency_key(self, key: str) -> ResponseAction | None:
        """The action already recorded for this (scope, decision), if any."""
        result = await self._s.execute(
            select(ResponseAction).where(ResponseAction.idempotency_key == key)
        )
        return result.scalar_one_or_none()

    async def has_success(self, once_key: str) -> bool:
        """True if a once-per-scope action has already succeeded."""
        result = await self._s.execute(
            select(ResponseAction.id)
            .where(ResponseAction.once_key == once_key, ResponseAction.status == "SUCCEEDED")
            .limit(1)
        )
        return result.first() is not None

    async def attempts_between(
        self, scope_key: str, start: datetime, end: datetime, limit: int = 100
    ) -> Sequence[ResponseAction]:
        """Attempts (any status) for a scope with start <= executed_at <= end, oldest first."""
        result = await self._s.execute(
            select(ResponseAction)
            .where(
                ResponseAction.scope_key == scope_key,
                ResponseAction.executed_at >= start,
                ResponseAction.executed_at <= end,
            )
            .order_by(ResponseAction.executed_at.asc(), ResponseAction.id.asc())
            .limit(limit)
        )
        return result.scalars().all()

    async def get_for_situation(self, situation_id: int) -> Sequence[ResponseAction]:
        """Every action recorded for one situation, oldest first."""
        result = await self._s.execute(
            select(ResponseAction)
            .where(ResponseAction.situation_id == situation_id)
            .order_by(ResponseAction.executed_at.asc(), ResponseAction.id.asc())
        )
        return result.scalars().all()


# ---------------------------------------------------------------------------
# AIExplanationRepository
# ---------------------------------------------------------------------------


class AIExplanationRepository:
    """Read/write access for ai_explanations."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def insert(self, record: AIExplanationRecord) -> AIExplanationRecord:
        """Persist an AI explanation record (both raw and sanitised)."""
        self._s.add(record)
        await self._s.flush()
        await self._s.refresh(record)
        return record

    async def get_by_incident_id(self, incident_id: str) -> AIExplanationRecord | None:
        """Return the most recent explanation for an incident."""
        result = await self._s.execute(
            select(AIExplanationRecord)
            .where(AIExplanationRecord.incident_id == incident_id)
            .order_by(AIExplanationRecord.generated_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_all_for_incident(self, incident_id: str) -> Sequence[AIExplanationRecord]:
        """Return all explanation records for an incident (audit purpose)."""
        result = await self._s.execute(
            select(AIExplanationRecord)
            .where(AIExplanationRecord.incident_id == incident_id)
            .order_by(AIExplanationRecord.generated_at.asc())
        )
        return result.scalars().all()


# ---------------------------------------------------------------------------
# BaselineRepository
# ---------------------------------------------------------------------------


class BaselineRepository:
    """
    Read/write access for baselines.

    This is the only repository that uses UPSERT (not pure INSERT) because
    a baseline is a continuously updated accumulator, not an event record.
    See spec §8.4.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def upsert(self, baseline: Baseline) -> Baseline:
        """
        Insert a new baseline or update the existing one for metric_key.

        Uses SQLite's INSERT OR REPLACE semantics via SQLAlchemy's
        dialect-specific insert to maintain the UNIQUE constraint on
        metric_key.
        """
        stmt = (
            sqlite_insert(Baseline)
            .values(
                metric_key=baseline.metric_key,
                sample_count=baseline.sample_count,
                mean=baseline.mean,
                std_dev=baseline.std_dev,
                updated_at=baseline.updated_at,
            )
            .on_conflict_do_update(
                index_elements=["metric_key"],
                set_={
                    "sample_count": baseline.sample_count,
                    "mean": baseline.mean,
                    "std_dev": baseline.std_dev,
                    "updated_at": baseline.updated_at,
                },
            )
        )
        await self._s.execute(stmt)
        await self._s.flush()
        return await self.get_by_metric_key(baseline.metric_key) or baseline

    async def get_by_metric_key(self, metric_key: str) -> Baseline | None:
        """Return the baseline for a given metric, or None."""
        result = await self._s.execute(select(Baseline).where(Baseline.metric_key == metric_key))
        return result.scalar_one_or_none()

    async def get_all(self) -> Sequence[Baseline]:
        """Return all baselines."""
        result = await self._s.execute(select(Baseline).order_by(Baseline.metric_key))
        return result.scalars().all()


# ---------------------------------------------------------------------------
# Convenience helper: create all repositories from a session
# ---------------------------------------------------------------------------


class UnitOfWork:
    """
    Groups all repositories sharing one session.

    Usage::

        async with session_factory() as session:
            async with session.begin():
                uow = UnitOfWork(session)
                event = await uow.events.insert(DetectionEvent(...))
                await uow.scores.insert(ThreatScore(...))
        # commit happens automatically on context exit

    The session is passed in rather than created here so the caller owns
    the transaction boundary (required for atomic multi-table writes, NFR-02).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.telemetry = TelemetrySampleRepository(session)
        self.events = DetectionEventRepository(session)
        self.incidents = IncidentRepository(session)
        self.scores = ThreatScoreRepository(session)
        self.state_changes = DefenseStateChangeRepository(session)
        self.actions = ResponseActionRepository(session)
        self.explanations = AIExplanationRepository(session)
        self.baselines = BaselineRepository(session)
