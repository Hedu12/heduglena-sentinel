"""
ExplanationContextBuilder: authoritative security state -> sanitised IncidentContext.

Read-only. It reads the incident, its state transitions, the decision's
evidence and the situation's simulated responses, and keeps only what an
explanation needs (AS-02). Removed on the way:

  * identifiers: situation ids, event ids, record ids, scope/once/idempotency
    keys (free text such as dry-run descriptions is scrubbed of
    "situation <n>" and "event <n>"); the incident id SIT-n is the one
    identifier kept, as the spec permits;
  * raw lifecycle and parameter JSON (only the derived guard verdict and the
    simulation outcome code are kept);
  * raw telemetry, event_data envelopes (only the synthetic subject label is
    kept, marked untrusted), paths, configuration.

assemble_context() is pure, so it can be tested with hostile rows directly.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.context import (
    EvidenceContext,
    IncidentContext,
    IncidentInfo,
    ReasonContext,
    ResponseContext,
    ScoreBreakdownContext,
    TransitionContext,
)
from core.config import Settings
from database.models import DefenseStateChange, DetectionEvent, Incident, ResponseAction
from explanation import queries
from models.enums import (
    ActionType,
    Classification,
    DefenseState,
    ExplanationTrigger,
    IncidentStatus,
    Severity,
)
from threat.decision import Decision
from threat.reasons import REASON_TEXT, ReasonCode

_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SCRUB = (
    (re.compile(r"\bsituation\s+\d+\b", re.IGNORECASE), "the current situation"),
    (re.compile(r"\b(?:detection\s+)?event\s+\d+\b", re.IGNORECASE), "a detection event"),
    (re.compile(r"\brecord\s+\d+\b", re.IGNORECASE), "a record"),
    (re.compile(r"\b[sS]\d+:[A-Za-z_:]+"), "a response scope"),
)


def incident_ref(situation_id: int) -> str:
    """The incident id of a situation. Must match response.actions.incident_id_for (tested)."""
    return f"SIT-{situation_id}"


def situation_of(incident_id: str) -> int | None:
    match = re.fullmatch(r"SIT-(\d{1,12})", incident_id)
    return int(match.group(1)) if match else None


def scrub(text: str | None) -> str | None:
    """Remove internal identifiers from Sentinel's own free text."""
    if text is None:
        return None
    for pattern, replacement in _SCRUB:
        text = pattern.sub(replacement, text)
    return text.strip() or None


def iso(moment: datetime) -> str:
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def _unit(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _code(value: str | None) -> str | None:
    return value if value is not None and _CODE.match(value) else None


def _reason(code: str | None) -> ReasonContext | None:
    if code is None or code not in ReasonCode.__members__:
        return None
    reason = ReasonCode(code)
    return ReasonContext(code=reason.value, description=REASON_TEXT[reason])


_E = TypeVar("_E", Severity, Classification, DefenseState, ActionType, IncidentStatus)


def _enum(kind: type[_E], value: str | None) -> _E | None:
    try:
        return kind(value) if value is not None else None
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ContextLimits:
    events: int
    transitions: int
    actions: int

    @classmethod
    def from_settings(cls, settings: Settings) -> ContextLimits:
        return cls(
            events=settings.ai_max_context_events,
            transitions=settings.ai_max_context_transitions,
            actions=settings.ai_max_context_actions,
        )


def _subject(event: DetectionEvent) -> str | None:
    try:
        envelope = json.loads(event.event_data or "{}")
    except ValueError:
        return None
    evidence = envelope.get("evidence") if isinstance(envelope, dict) else None
    subject = evidence.get("latest_subject") if isinstance(evidence, dict) else None
    return subject if isinstance(subject, str) and subject.strip() else None


def _evidence(
    decision: Decision, events: Sequence[DetectionEvent], limit: int
) -> list[EvidenceContext]:
    signals = {s.event_id: s for s in decision.breakdown.signals if s.event_id is not None}
    out: list[EvidenceContext] = []
    for event in sorted(events, key=lambda e: (e.detected_at, e.id), reverse=True):
        severity = _enum(Severity, event.severity)
        if severity is None:
            continue
        signal = signals.get(event.id)
        detected = (
            event.detected_at if event.detected_at.tzinfo else event.detected_at.replace(tzinfo=UTC)
        )
        out.append(
            EvidenceContext(
                event_type=event.event_type or "unspecified",
                category=signal.category.value if signal else None,
                classification=_enum(Classification, event.classification),
                severity=severity,
                confidence=_unit(event.confidence) if event.confidence is not None else None,
                metric_key=event.metric_key or "unspecified",
                observed_value=event.metric_value,
                threshold=event.threshold_value,
                detected_at=iso(detected),
                age_seconds=max(0.0, round((decision.calculated_at - detected).total_seconds(), 1)),
                is_synthetic=bool(event.is_synthetic),
                occurrences=max(1, signal.count) if signal else 1,
                untrusted_subject=_subject(event),
            )
        )
        if len(out) >= limit:
            break
    return out


def _lifecycle_statuses(row: ResponseAction) -> tuple[list[str], str | None]:
    """Statuses in order, and the terminal step's detail. The raw JSON goes no further."""
    try:
        steps = json.loads(row.lifecycle or "[]")
    except ValueError:
        return [], None
    if not isinstance(steps, list):
        return [], None
    statuses = [s.get("status") for s in steps if isinstance(s, dict)]
    last = steps[-1] if steps and isinstance(steps[-1], dict) else {}
    detail = last.get("detail")
    return [s for s in statuses if isinstance(s, str)], detail if isinstance(detail, str) else None


GuardVerdictCode = Literal["AUTHORIZED", "DENIED", "NOT_EVALUATED"]
TerminalStatus = Literal["SUCCEEDED", "BLOCKED", "FAILED"]
_TERMINAL: dict[str, TerminalStatus] = {
    "SUCCEEDED": "SUCCEEDED",
    "BLOCKED": "BLOCKED",
    "FAILED": "FAILED",
}


def guard_verdict(row: ResponseAction) -> tuple[GuardVerdictCode, str | None]:
    """
    What ResponseGuard decided for a recorded action, and the simulation outcome
    code if it succeeded. Derived from the lifecycle; the raw JSON goes no further.
    """
    statuses, detail = _lifecycle_statuses(row)
    verdict: GuardVerdictCode
    if "AUTHORIZED" in statuses:
        verdict = "AUTHORIZED"
    elif row.action_class is not None:
        verdict = "DENIED"  # the guard evaluated it and refused
    else:
        verdict = "NOT_EVALUATED"  # stopped by a precondition before the guard
    return verdict, (_code(detail) if row.status == "SUCCEEDED" else None)


def _response(row: ResponseAction) -> ResponseContext | None:
    action = _enum(ActionType, row.action_type)
    state = _enum(DefenseState, row.defense_state)
    status = _TERMINAL.get(row.status or "")
    if action is None or state is None or status is None:
        return None
    verdict, outcome = guard_verdict(row)
    return ResponseContext(
        action_type=action,
        defense_state=state,
        status=status,
        guard_verdict=verdict,
        guard_reason=scrub(row.guard_reason),
        simulation_outcome=outcome,
        dry_run_description=scrub(row.dry_run_description) or "No description recorded.",
        at=iso(row.executed_at),
    )


def _transition(row: DefenseStateChange) -> TransitionContext | None:
    from_state = _enum(DefenseState, row.from_state)
    to_state = _enum(DefenseState, row.to_state)
    if from_state is None or to_state is None:
        return None
    return TransitionContext(
        from_state=from_state,
        to_state=to_state,
        trigger_score=_unit(row.trigger_score),
        previous_score=_unit(row.previous_score) if row.previous_score is not None else None,
        reason=_reason(row.reason),
        at=iso(row.changed_at),
    )


def _incident(incident_id: str, row: Incident | None) -> IncidentInfo:
    if row is None:
        return IncidentInfo(incident_id=incident_id, recorded=False)
    return IncidentInfo(
        incident_id=incident_id,
        recorded=True,
        status=_enum(IncidentStatus, row.status),
        created_at=iso(row.created_at),
        recovered_at=iso(row.recovered_at) if row.recovered_at else None,
        resolved_at=iso(row.resolved_at) if row.resolved_at else None,
        resolution=_code(row.resolution),
    )


def assemble_context(
    *,
    trigger: ExplanationTrigger,
    decision: Decision,
    situation_id: int,
    incident: Incident | None,
    transitions: Sequence[DefenseStateChange],
    events: Sequence[DetectionEvent],
    actions: Sequence[ResponseAction],
    limits: ContextLimits,
) -> IncidentContext:
    """Pure: the sanitised context for one explanation."""
    b = decision.breakdown
    return IncidentContext(
        trigger=trigger,
        incident=_incident(incident_ref(situation_id), incident),
        defense_state=decision.defense_state,
        previous_state=decision.previous_state,
        threat_score=_unit(decision.threat_score),
        evaluated_at=iso(decision.calculated_at),
        score_breakdown=ScoreBreakdownContext(
            final_score=_unit(b.final_score),
            score_before_decay=_unit(b.score_before_decay),
            severity=_unit(b.severity_contribution),
            confidence=_unit(b.confidence_contribution),
            repetition=_unit(b.repetition_contribution),
            escalation=_unit(b.escalation_contribution),
            correlation=_unit(b.correlation_contribution),
            cross_domain=_unit(b.cross_domain_contribution),
            decay=_unit(abs(b.decay)),
            active_categories=[c.value for c in b.active_categories][:16],
            corroborating_categories=min(16, max(0, b.corroborating_categories)),
        ),
        reasons=[r for r in (_reason(c.value) for c in decision.reason_codes) if r][:16],
        transitions=[t for t in (_transition(r) for r in transitions) if t][-limits.transitions :],
        evidence=_evidence(decision, events, limits.events),
        responses=[r for r in (_response(a) for a in actions) if r][-limits.actions :],
    )


class ExplanationContextBuilder:
    """Reads authoritative records (never writes) and assembles the context."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], limits: ContextLimits
    ) -> None:
        self._session_factory = session_factory
        self._limits = limits

    async def build(
        self, trigger: ExplanationTrigger, decision: Decision, situation_id: int
    ) -> IncidentContext:
        event_ids = [s.event_id for s in decision.breakdown.signals if s.event_id is not None]
        async with self._session_factory() as session:
            incident = await queries.incident(session, incident_ref(situation_id))
            transitions = await queries.transitions_from(
                session, situation_id, decision.calculated_at, self._limits.transitions
            )
            events = await queries.events_by_ids(session, event_ids)
            actions = await queries.actions_for_situation(
                session, situation_id, decision.calculated_at, self._limits.actions
            )
        return assemble_context(
            trigger=trigger,
            decision=decision,
            situation_id=situation_id,
            incident=incident,
            transitions=transitions,
            events=events,
            actions=actions,
            limits=self._limits,
        )
