"""
ExplanationEvalCase: one benchmark situation and the facts an explanation must preserve.

The context is a production IncidentContext, so a case can contain only what
the AI receives in production (AS-02). Expected facts are machine-readable and
about meaning, not wording. They are written per case, but check_consistency()
proves every expected fact against the case's own context, so "expected" can
never disagree with what Sentinel actually decided.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ai.context import IncidentContext
from models.enums import ActionType, DefenseState, IncidentStatus

Transition = Annotated[str, Field(pattern=r"^[A-Z]+>[A-Z]+$")]


class ExpectedFacts(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    current_state: DefenseState
    threat_score_min: float = Field(ge=0.0, le=1.0)
    threat_score_max: float = Field(ge=0.0, le=1.0)
    incident_status: IncidentStatus | None = None
    # Detection event types the explanation must mention.
    required_evidence: tuple[str, ...] = ()
    # "FROM>TO" transitions the explanation must mention, in that order.
    required_transitions: tuple[Transition, ...] = ()
    # Simulated actions the explanation must mention.
    simulated_actions: tuple[ActionType, ...] = ()
    # Actions ResponseGuard denied: if mentioned, they must not be described as done.
    denied_actions: tuple[ActionType, ...] = ()
    # Reason codes, at least one of which (code or description) must be mentioned.
    required_reasons: tuple[str, ...] = ()
    # Text whose presence means the model followed injected instructions (lower case).
    forbidden_phrases: tuple[str, ...] = ()
    # Hostile evidence present: overriding the state or inventing evidence is CRITICAL_FAIL.
    adversarial: bool = False

    @model_validator(mode="after")
    def _ordered_range(self) -> ExpectedFacts:
        if self.threat_score_min > self.threat_score_max:
            raise ValueError("threat_score_min must not exceed threat_score_max")
        return self


class ExplanationEvalCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    title: str = Field(min_length=1, max_length=120)
    category: str = Field(pattern=r"^[a-z_]{1,32}$")
    context: IncidentContext
    expected: ExpectedFacts


def check_consistency(case: ExplanationEvalCase) -> list[str]:
    """Every expected fact that the case's own context does not support. Empty if sound."""
    ctx, exp = case.context, case.expected
    problems: list[str] = []
    if ctx.defense_state is not exp.current_state:
        problems.append("current_state differs from the context")
    if not exp.threat_score_min <= ctx.threat_score <= exp.threat_score_max:
        problems.append("threat score outside the expected range")
    if exp.incident_status is not None and ctx.incident.status is not exp.incident_status:
        problems.append("incident status differs from the context")
    event_types = {e.event_type for e in ctx.evidence}
    problems += [
        f"evidence {t} not in context" for t in exp.required_evidence if t not in event_types
    ]
    transitions = {f"{t.from_state.value}>{t.to_state.value}" for t in ctx.transitions}
    problems += [
        f"transition {t} not in context" for t in exp.required_transitions if t not in transitions
    ]
    done = {r.action_type for r in ctx.responses if r.status == "SUCCEEDED"}
    problems += [f"action {a} not simulated" for a in exp.simulated_actions if a not in done]
    denied = {r.action_type for r in ctx.responses if r.guard_verdict == "DENIED"}
    problems += [f"action {a} not denied" for a in exp.denied_actions if a not in denied]
    reasons = {r.code for r in ctx.reasons}
    problems += [f"reason {c} not in context" for c in exp.required_reasons if c not in reasons]
    return problems
