"""
IncidentReadService: read-only incident, evidence and explanation views for the API.

Thin route handlers call this service (P-06). Everything here is SELECT-only;
there is no method that writes, and nothing a client sends can reach the
security pipeline or the AI layer through it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TypeVar

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database.models import (
    AIExplanationRecord,
    DetectionEvent,
    Incident,
    ResponseAction,
    ThreatScore,
)
from explanation import queries
from explanation.context_builder import guard_verdict, situation_of
from explanation.fallback import fallback_explanation
from explanation.views import (
    Availability,
    EvidenceSchema,
    ExplanationContentSchema,
    ExplanationSchema,
    ExplanationStateSchema,
    IncidentDetailSchema,
    IncidentSummarySchema,
    ReasonSchema,
    ScoreBreakdownSchema,
    SimulationSchema,
    TransitionSchema,
)
from models.enums import (
    ActionType,
    DefenseState,
    ExplanationFailure,
    ExplanationStatus,
    ExplanationTrigger,
    IncidentStatus,
)
from threat.reasons import REASON_TEXT, ReasonCode

MAX_LIST = 100
MAX_ITEMS = 50


def _aware(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _reason(code: str | None) -> ReasonSchema | None:
    if code is None or code not in ReasonCode.__members__:
        return None
    return ReasonSchema(code=code, description=REASON_TEXT[ReasonCode(code)])


_E = TypeVar(
    "_E", ActionType, DefenseState, ExplanationFailure, ExplanationStatus, ExplanationTrigger
)


def _enum_or_none(kind: type[_E], value: str | None) -> _E | None:
    try:
        return kind(value) if value is not None else None
    except ValueError:
        return None


def _summary(row: Incident) -> IncidentSummarySchema:
    return IncidentSummarySchema(
        incident_id=row.incident_id,
        status=IncidentStatus(row.status),
        created_at=_aware(row.created_at) or row.created_at,
        defense_state_at_creation=DefenseState(row.defense_state),
        threat_score_at_creation=row.threat_score_at_creation,
        recovered_at=_aware(row.recovered_at),
        resolved_at=_aware(row.resolved_at),
        resolution=row.resolution,
        summary=row.summary,
    )


def _evidence(row: DetectionEvent) -> EvidenceSchema:
    return EvidenceSchema(
        detected_at=_aware(row.detected_at) or row.detected_at,
        rule_name=row.rule_name,
        event_type=row.event_type,
        classification=row.classification,
        severity=row.severity,
        confidence=row.confidence,
        metric_key=row.metric_key,
        metric_value=row.metric_value,
        threshold_value=row.threshold_value,
        is_synthetic=row.is_synthetic,
    )


def _simulation(row: ResponseAction) -> SimulationSchema | None:
    action = _enum_or_none(ActionType, row.action_type)
    state = _enum_or_none(DefenseState, row.defense_state)
    if action is None or state is None or row.status is None:
        return None
    verdict, outcome = guard_verdict(row)
    return SimulationSchema(
        executed_at=_aware(row.executed_at) or row.executed_at,
        action_type=action,
        defense_state=state,
        status=row.status,
        guard_verdict=verdict,
        guard_reason=row.guard_reason,
        simulation_outcome=outcome,
        dry_run_description=row.dry_run_description,
        is_simulated=row.is_simulated,
    )


def _explanation(row: AIExplanationRecord) -> ExplanationSchema:
    content: ExplanationContentSchema | None = None
    if row.status == ExplanationStatus.VALID.value and row.content:
        try:
            content = ExplanationContentSchema.model_validate_json(row.content)
        except ValidationError:
            content = None  # never show content that does not match the contract
    return ExplanationSchema(
        generated_at=_aware(row.generated_at) or row.generated_at,
        trigger=_enum_or_none(ExplanationTrigger, row.trigger),
        provider=row.provider,
        model=row.model,
        status=_enum_or_none(ExplanationStatus, row.status),
        failure_reason=_enum_or_none(ExplanationFailure, row.failure_reason),
        latency_ms=row.latency_ms,
        content=content,
    )


class IncidentReadService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_incidents(self, limit: int = 50) -> list[IncidentSummarySchema]:
        async with self._session_factory() as session:
            rows = await queries.incidents(session, max(1, min(limit, MAX_LIST)))
        return [_summary(r) for r in rows]

    async def incident_detail(self, incident_id: str) -> IncidentDetailSchema | None:
        situation = situation_of(incident_id)
        if situation is None:
            return None
        async with self._session_factory() as session:
            incident = await queries.incident(session, incident_id)
            if incident is None:
                return None
            transitions = await queries.transitions_from(
                session, situation, _aware(incident.resolved_at), MAX_ITEMS
            )
            actions = await queries.actions_for_situation(session, situation, None, MAX_ITEMS)
            event_ids = self._event_ids(incident, actions)
            events = await queries.events_by_ids(session, event_ids)
            score = await queries.latest_score(session)
            ai = await self._ai_state(session, incident)
        return IncidentDetailSchema(
            incident=_summary(incident),
            current_score=self._score(score) if score is not None else None,
            evidence=[
                _evidence(e)
                for e in sorted(events, key=lambda e: (e.detected_at, e.id), reverse=True)
            ][:MAX_ITEMS],
            transitions=[
                TransitionSchema(
                    changed_at=_aware(t.changed_at) or t.changed_at,
                    from_state=DefenseState(t.from_state),
                    to_state=DefenseState(t.to_state),
                    trigger_score=t.trigger_score,
                    reason=_reason(t.reason),
                )
                for t in transitions
            ],
            simulations=[s for s in (_simulation(a) for a in actions) if s is not None],
            ai=ai,
        )

    async def explanation_state(self, incident_id: str) -> ExplanationStateSchema | None:
        if situation_of(incident_id) is None:
            return None
        async with self._session_factory() as session:
            incident = await queries.incident(session, incident_id)
            if incident is None:
                return None
            return await self._ai_state(session, incident)

    # ── Internals ──────────────────────────────────────────────────────────

    @staticmethod
    def _event_ids(incident: Incident, actions: list[ResponseAction]) -> list[int]:
        ids: set[int] = set()
        try:
            opening = json.loads(incident.event_ids or "[]")
        except ValueError:
            opening = []
        if isinstance(opening, list):
            ids.update(i for i in opening if isinstance(i, int))
        ids.update(a.triggering_event_id for a in actions if a.triggering_event_id is not None)
        return sorted(ids)[-MAX_ITEMS:]

    @staticmethod
    def _score(row: ThreatScore) -> ScoreBreakdownSchema:
        try:
            data = json.loads(row.breakdown or "{}")
        except ValueError:
            data = {}
        data = data if isinstance(data, dict) else {}

        def num(key: str) -> float:
            value = data.get(key)
            return float(value) if isinstance(value, int | float) else 0.0

        codes = data.get("reason_codes")
        return ScoreBreakdownSchema(
            calculated_at=_aware(row.calculated_at) or row.calculated_at,
            score=row.score,
            defense_state=_enum_or_none(DefenseState, row.defense_state),
            severity=num("severity_contribution"),
            confidence=num("confidence_contribution"),
            repetition=num("repetition_contribution"),
            escalation=num("escalation_contribution"),
            correlation=num("correlation_contribution"),
            cross_domain=num("cross_domain_contribution"),
            decay=num("decay"),
            active_categories=[c for c in data.get("active_categories", []) if isinstance(c, str)][
                :16
            ],
            reasons=[
                r
                for r in (_reason(c) for c in (codes if isinstance(codes, list) else []))
                if r is not None
            ],
        )

    @staticmethod
    async def _ai_state(session: AsyncSession, incident: Incident) -> ExplanationStateSchema:
        attempts = await queries.explanations(session, incident.incident_id, 1)
        valid = await queries.latest_valid_explanation(session, incident.incident_id)
        latest = attempts[0] if attempts else None
        availability: Availability
        if valid is not None:
            availability = "AVAILABLE"
        elif latest is None:
            availability = "PENDING"
        else:
            availability = "UNAVAILABLE"
        return ExplanationStateSchema(
            incident_id=incident.incident_id,
            availability=availability,
            explanation=_explanation(valid) if valid is not None else None,
            latest_attempt=_explanation(latest) if latest is not None else None,
            fallback_text=fallback_explanation(
                incident.incident_id, incident.defense_state, incident.threat_score_at_creation
            ),
        )
