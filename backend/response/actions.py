"""
Response action models: plans, lifecycle, and outcomes.

These are plain, immutable value objects. Nothing here performs I/O or acts
on the host. The persisted form is database.models.ResponseAction.

    PlannedAction   what the planner proposes for one recommended action
    ActionLifecycle the validated status history of one attempt
    ActionOutcome   what happened to one planned action (executed, blocked,
                    failed, or skipped and why)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from models.enums import ActionStatus, ActionType, DefenseState


class Scope(StrEnum):
    """How often an action may run."""

    PER_SITUATION = "PER_SITUATION"  # once per security situation
    PER_SITUATION_STATE = "PER_SITUATION_STATE"  # once per state entered within a situation
    COOLDOWN = "COOLDOWN"  # repeatable, at most once per cooldown (no situation)


class SkipReason(StrEnum):
    """Why a planned action produced no new record."""

    ALREADY_PROCESSED = "ALREADY_PROCESSED"  # this decision was handled before (idempotency)
    DUPLICATE = "DUPLICATE"  # the once-per-scope action already succeeded
    COOLDOWN = "COOLDOWN"  # a recent attempt in the same scope
    PERSIST_FAILED = "PERSIST_FAILED"  # the record could not be saved; safe to retry


TERMINAL_STATUSES: frozenset[ActionStatus] = frozenset(
    {ActionStatus.SUCCEEDED, ActionStatus.FAILED, ActionStatus.BLOCKED}
)

_ALLOWED: dict[ActionStatus, frozenset[ActionStatus]] = {
    ActionStatus.PLANNED: frozenset({ActionStatus.AUTHORIZED, ActionStatus.BLOCKED}),
    ActionStatus.AUTHORIZED: frozenset({ActionStatus.EXECUTING, ActionStatus.BLOCKED}),
    ActionStatus.EXECUTING: frozenset({ActionStatus.SUCCEEDED, ActionStatus.FAILED}),
    ActionStatus.SUCCEEDED: frozenset(),
    ActionStatus.FAILED: frozenset(),
    ActionStatus.BLOCKED: frozenset(),
}


class LifecycleError(ValueError):
    """An illegal status transition was attempted."""


@dataclass(frozen=True, slots=True)
class LifecycleStep:
    status: ActionStatus
    at: datetime
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status.value, "at": self.at.isoformat(), "detail": self.detail}


@dataclass(slots=True)
class ActionLifecycle:
    """
    The status history of one attempt. Every transition is validated, so a
    record can never claim, for example, SUCCEEDED without having been
    AUTHORIZED and EXECUTING first.
    """

    steps: list[LifecycleStep] = field(default_factory=list)

    @classmethod
    def planned(cls, at: datetime, detail: str = "") -> ActionLifecycle:
        return cls([LifecycleStep(ActionStatus.PLANNED, at, detail)])

    @property
    def status(self) -> ActionStatus:
        return self.steps[-1].status

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def advance(self, status: ActionStatus, at: datetime, detail: str = "") -> None:
        if status not in _ALLOWED[self.status]:
            raise LifecycleError(f"illegal transition {self.status.value} -> {status.value}")
        self.steps.append(LifecycleStep(status, at, detail))

    def to_json(self) -> str:
        return json.dumps([s.to_dict() for s in self.steps], sort_keys=True)


@dataclass(frozen=True, slots=True)
class PlannedAction:
    """One action the planner proposes, with everything needed to run and audit it."""

    action_type: ActionType
    defense_state: DefenseState
    planned_at: datetime
    situation_id: int | None
    scope: Scope
    scope_key: str
    once_key: str | None
    idempotency_key: str
    triggering_event_id: int | None
    threat_score: float
    reason_codes: tuple[str, ...]
    evidence_event_ids: tuple[int, ...] = ()

    def parameters(self) -> dict[str, object]:
        """Structured parameters recorded with the action (no free text from evidence)."""
        return {
            "situation_id": self.situation_id,
            "scope": self.scope.value,
            "threat_score": self.threat_score,
            "reason_codes": list(self.reason_codes),
            "triggering_event_id": self.triggering_event_id,
        }


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    """What happened to one planned action."""

    planned: PlannedAction
    status: ActionStatus | None = None  # terminal status when a record was written
    skip_reason: SkipReason | None = None
    detail: str = ""
    record_id: int | None = None
    incident_id: str | None = None

    @property
    def recorded(self) -> bool:
        return self.record_id is not None

    @property
    def succeeded(self) -> bool:
        return self.status is ActionStatus.SUCCEEDED


def incident_id_for(situation_id: int) -> str:
    """The one incident a security situation can have."""
    return f"SIT-{situation_id}"


@dataclass(frozen=True, slots=True)
class ResponseResult:
    """The response layer's handling of one decision."""

    decided_at: datetime
    situation_id: int | None
    outcomes: tuple[ActionOutcome, ...]
    # Set when handling this decision resolved an incident (at most once per incident).
    resolved_incident_id: str | None = None
    # True if resolving an ended situation's incident could not be saved.
    resolution_failed: bool = False

    @property
    def complete(self) -> bool:
        """False if any record could not be saved (re-submitting the decision is safe)."""
        if self.resolution_failed:
            return False
        return all(o.skip_reason is not SkipReason.PERSIST_FAILED for o in self.outcomes)

    def by_action(self) -> dict[ActionType, ActionOutcome]:
        return {o.planned.action_type: o for o in self.outcomes}
