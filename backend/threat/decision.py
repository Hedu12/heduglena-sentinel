"""
Decision: the structured output of the decision layer.

A Decision *recommends*; it never executes. recommended_actions holds only
ActionType values, the same vocabulary the ResponseGuard authorises. A later
response component must submit each action to ResponseGuard, which remains
the only gate between a decision and any effect (P-05). This module imports
nothing that can run a command, touch the network, or call the guard.

Recommended actions follow the spec's state table (section 9.2) and are
cumulative. In raised states they are level-triggered: the response layer
de-duplicates repeated recommendations per situation. Two are edge-triggered:
RECORD_INCIDENT (only when a situation opens) and the RELAXED alert (only when
an evaluation brings new evidence).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models.enums import ActionType, DefenseState
from threat.reasons import ReasonCode
from threat.scorer import ScoreBreakdown
from threat.state_machine import StateEvaluation

_ALERT_ACTIONS: tuple[ActionType, ...] = (
    ActionType.GENERATE_ALERT,
    ActionType.INCREASE_MONITORING,
    ActionType.RECORD_INCIDENT,
)
_DEFENSIVE_ACTIONS: tuple[ActionType, ...] = (
    *_ALERT_ACTIONS,
    ActionType.SIMULATE_IP_BLOCK,
    ActionType.SIMULATE_PROCESS_ISOLATE,
)
_AGGRESSIVE_ACTIONS: tuple[ActionType, ...] = (
    *_DEFENSIVE_ACTIONS,
    ActionType.SIMULATE_QUARANTINE,
)


def recommended_actions_for(
    state: DefenseState, *, new_evidence: bool, record_incident: bool = False
) -> tuple[ActionType, ...]:
    """
    Actions appropriate to a defense state.

    RELAXED recommends an alert only when this evaluation brought NEW evidence
    (at least one new detection event). Old evidence that is merely decaying,
    for example after a situation has recovered, has already been alerted on
    and recommends nothing. `new_evidence` does not affect raised states.

    RECORD_INCIDENT is edge-triggered: it is included only when
    `record_incident` is True, which the caller sets at the single moment a new
    security situation opens. It is never part of the steady-state posture, so a
    long incident cannot re-recommend it on every evaluation.
    """
    if state is DefenseState.AGGRESSIVE:
        actions = _AGGRESSIVE_ACTIONS
    elif state is DefenseState.DEFENSIVE:
        actions = _DEFENSIVE_ACTIONS
    elif state is DefenseState.ALERT:
        actions = _ALERT_ACTIONS
    else:
        return (ActionType.GENERATE_ALERT,) if new_evidence else ()
    if record_incident:
        return actions
    return tuple(a for a in actions if a is not ActionType.RECORD_INCIDENT)


@dataclass(frozen=True, slots=True)
class Decision:
    """What Sentinel concluded at one instant, with the evidence for it."""

    calculated_at: datetime
    threat_score: float
    defense_state: DefenseState
    previous_state: DefenseState
    state_changed: bool
    reason_codes: tuple[ReasonCode, ...]
    recommended_actions: tuple[ActionType, ...]
    breakdown: ScoreBreakdown
    evaluation: StateEvaluation
    score_record_id: int | None = None
    transition_id: int | None = None
    # The security situation in progress (None while RELAXED). Stable across
    # evaluations and restarts, so a response layer can ensure one incident per id.
    situation_id: int | None = None
    # True only on the decision that opened a new situation.
    new_situation: bool = False
    # The most recent situation that is over for good (it can no longer resume),
    # repeated on every decision until a later one ends, so its incident can be
    # resolved idempotently even if one decision is lost.
    ended_situation_id: int | None = None
    ended_situation_recovered_at: datetime | None = None
    ended_situation_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "calculated_at": self.calculated_at.isoformat(),
            "threat_score": self.threat_score,
            "defense_state": self.defense_state.value,
            "previous_state": self.previous_state.value,
            "state_changed": self.state_changed,
            "reason_codes": [c.value for c in self.reason_codes],
            "recommended_actions": [a.value for a in self.recommended_actions],
            "score_record_id": self.score_record_id,
            "transition_id": self.transition_id,
            "situation_id": self.situation_id,
            "new_situation": self.new_situation,
            "ended_situation_id": self.ended_situation_id,
            "ended_situation_recovered_at": (
                self.ended_situation_recovered_at.isoformat()
                if self.ended_situation_recovered_at is not None
                else None
            ),
            "ended_situation_reason": self.ended_situation_reason,
            "breakdown": self.breakdown.to_dict(),
        }


def merge_reasons(*groups: tuple[ReasonCode, ...]) -> tuple[ReasonCode, ...]:
    """Concatenate reason codes, keeping first occurrences in order."""
    seen: dict[ReasonCode, None] = {}
    for group in groups:
        for code in group:
            seen.setdefault(code)
    return tuple(seen)
