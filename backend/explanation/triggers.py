"""
ExplanationTriggerPolicy: when a decision deserves an explanation.

Pure and deterministic: no I/O and no clock (time comes from the decisions).
Its memory is not kept in process: the caller derives a TriggerMemory from the
persisted ai_explanations records (trigger keys, decision times, evidence marks),
so the same situation produces the same trigger decisions before and after a
restart. Nothing in the security pipeline consults this policy.

Triggers, at most one per handled batch, the most significant first:

  A  INCIDENT_CREATED    the decision that opened the situation (once per situation);
  B  STATE_TRANSITION    a change of defense state inside the situation, including
                         recovery back to RELAXED (once per persisted transition);
  C  NEW_EVIDENCE        new evidence materially changed the situation: a new signal
                         category, a higher maximum severity, or a score at least
                         `evidence_score_delta` above the last explained score;
  D  AGGRESSIVE_REFRESH  while AGGRESSIVE, at most once per `aggressive_refresh_seconds`
                         after the last explanation of the situation.

A decision not newer than the situation's last recorded explanation is stale
(for example redelivered after a restart) and triggers nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from models.enums import DefenseState, ExplanationTrigger, Severity
from threat.decision import Decision

CREATED_KEY = ExplanationTrigger.INCIDENT_CREATED.value
MAX_PENDING_TRANSITIONS = 16
_SEVERITY_ORDER = list(Severity)


def _iso(moment: datetime) -> str:
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def transition_key(decision: Decision) -> str:
    """Stable identity of the state transition a decision made."""
    if decision.transition_id is not None:
        return f"STATE_TRANSITION:{decision.transition_id}"
    return (
        f"STATE_TRANSITION:{_iso(decision.calculated_at)}:"
        f"{decision.previous_state.value}>{decision.defense_state.value}"
    )


@dataclass(frozen=True, slots=True)
class EvidenceMark:
    """What an explanation was based on; persisted with it (evidence_state)."""

    decision_at: datetime
    categories: frozenset[str]
    severity_rank: int
    score: float

    @classmethod
    def of(cls, decision: Decision) -> EvidenceMark:
        severity = decision.breakdown.active_max_severity
        return cls(
            decision_at=decision.calculated_at,
            categories=frozenset(c.value for c in decision.breakdown.active_categories),
            severity_rank=_SEVERITY_ORDER.index(severity) if severity is not None else -1,
            score=round(decision.threat_score, 6),
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "categories": sorted(self.categories),
                "severity_rank": self.severity_rank,
                "score": self.score,
            },
            sort_keys=True,
        )

    @classmethod
    def from_record(cls, decision_at: datetime, evidence_state: str | None) -> EvidenceMark:
        """Rebuild a mark from a stored record. Unreadable state counts as 'nothing known'."""
        try:
            data = json.loads(evidence_state or "{}")
        except ValueError:
            data = {}
        data = data if isinstance(data, dict) else {}
        categories = data.get("categories")
        rank = data.get("severity_rank")
        score = data.get("score")
        return cls(
            decision_at=decision_at if decision_at.tzinfo else decision_at.replace(tzinfo=UTC),
            categories=frozenset(c for c in categories if isinstance(c, str))
            if isinstance(categories, list)
            else frozenset(),
            severity_rank=rank if isinstance(rank, int) and not isinstance(rank, bool) else -1,
            score=float(score) if isinstance(score, int | float) else 0.0,
        )


@dataclass(frozen=True, slots=True)
class TriggerMemory:
    """What is already explained for one situation, derived from persisted records."""

    created: bool = False
    # Which of the trigger keys asked about are already recorded.
    explained: frozenset[str] = frozenset()
    # The most recent recorded explanation (any status).
    last: EvidenceMark | None = None


@dataclass(slots=True)
class PendingExplanation:
    """Decisions of one situation waiting for the worker, coalesced."""

    situation_id: int | None  # None: a recovery whose situation is resolved from the database
    decision: Decision  # the newest decision
    opened: bool = False
    transition_keys: list[str] = field(default_factory=list)

    @classmethod
    def start(cls, situation_id: int | None, decision: Decision) -> PendingExplanation:
        pending = cls(situation_id, decision)
        pending.absorb(decision)
        return pending

    def absorb(self, decision: Decision) -> None:
        if decision.calculated_at >= self.decision.calculated_at:
            self.decision = decision
        self.opened = self.opened or decision.new_situation
        if decision.state_changed:
            key = transition_key(decision)
            if key not in self.transition_keys:
                self.transition_keys.append(key)
                del self.transition_keys[:-MAX_PENDING_TRANSITIONS]

    def keys(self) -> list[str]:
        """Every persisted trigger key the policy may need to look up."""
        return [CREATED_KEY, *self.transition_keys]


@dataclass(frozen=True, slots=True)
class TriggerRequest:
    situation_id: int
    trigger: ExplanationTrigger
    decision: Decision
    trigger_key: str
    mark: EvidenceMark


class ExplanationTriggerPolicy:
    def __init__(self, *, aggressive_refresh_seconds: float, evidence_score_delta: float) -> None:
        if aggressive_refresh_seconds <= 0 or evidence_score_delta <= 0:
            raise ValueError("refresh interval and score delta must be positive")
        self._refresh = aggressive_refresh_seconds
        self._delta = evidence_score_delta

    def decide(
        self, situation_id: int, pending: PendingExplanation, memory: TriggerMemory
    ) -> TriggerRequest | None:
        """The explanation this batch calls for, given what is already recorded."""
        d = pending.decision
        mark = EvidenceMark.of(d)

        def request(trigger: ExplanationTrigger, key: str) -> TriggerRequest:
            return TriggerRequest(situation_id, trigger, d, key, mark)

        last = memory.last
        if last is not None and d.calculated_at <= last.decision_at:
            return None  # stale: already explained up to this point
        if pending.opened and not memory.created:
            return request(ExplanationTrigger.INCIDENT_CREATED, CREATED_KEY)
        unexplained = [k for k in pending.transition_keys if k not in memory.explained]
        if unexplained:
            return request(ExplanationTrigger.STATE_TRANSITION, unexplained[-1])
        stamp = _iso(d.calculated_at)
        if last is None:
            if d.breakdown.signal_count > 0:
                return request(ExplanationTrigger.NEW_EVIDENCE, f"NEW_EVIDENCE:{stamp}")
            return None
        if (
            mark.categories - last.categories
            or mark.severity_rank > last.severity_rank
            or mark.score - last.score >= self._delta
        ):
            return request(ExplanationTrigger.NEW_EVIDENCE, f"NEW_EVIDENCE:{stamp}")
        elapsed = (d.calculated_at - last.decision_at).total_seconds()
        if d.defense_state is DefenseState.AGGRESSIVE and elapsed >= self._refresh:
            return request(ExplanationTrigger.AGGRESSIVE_REFRESH, f"AGGRESSIVE_REFRESH:{stamp}")
        return None
