"""
IncidentContext: the only data an AI provider ever receives.

It is built by the security domain (explanation.context_builder) from
authoritative records, never by the AI layer. Every field is an enum, a bounded
number, an ISO timestamp, or sanitised bounded text. There are deliberately no
fields for internal identifiers (situation ids, event or record ids, scope or
idempotency keys), raw lifecycle or parameter JSON, raw telemetry, paths or
configuration, and extra="forbid" makes adding one an explicit schema change.
The incident id (SIT-n) is the single identifier allowed, as the spec permits.

Every string is sanitised on construction (control, format and separator
characters removed, unpaired surrogates dropped, whitespace collapsed, length
capped), whatever the caller passed. Untrusted labels, such as a synthetic
event's subject, are additionally named `untrusted_*` so neither the model nor a
reviewer can mistake them for Sentinel's own words.

A prompt receives the context only through to_prompt_json(): plain JSON from
model_dump_json() (AS-08), with '<', '>' and '&' escaped, so no value can close
the delimited data block the prompt wraps around it.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field

from models.enums import (
    ActionType,
    Classification,
    DefenseState,
    ExplanationTrigger,
    IncidentStatus,
    Severity,
)

CONTEXT_SCHEMA_VERSION = 1

# Hard caps, as defined in AS-02 (tests/security/test_as02_sync.py keeps them in step).
LABEL_MAX = 64
SENTENCE_MAX = 300
MAX_EVIDENCE = 10
MAX_TRANSITIONS = 8
MAX_RESPONSES = 10
MAX_REASONS = 16
MAX_CATEGORIES = 16


def clean_text(value: str, max_length: int) -> str:
    """Printable, single-line, bounded text. Never raises."""
    kept: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        # C* = control, format (bidi overrides), surrogate, private use, unassigned.
        kept.append(" " if category in {"Zl", "Zp"} or category.startswith("C") else char)
    return " ".join("".join(kept).split())[:max_length].rstrip()


def _text(max_length: int) -> BeforeValidator:
    def sanitise(value: object) -> object:
        return clean_text(value, max_length) if isinstance(value, str) else value

    return BeforeValidator(sanitise)


def _rounded(value: float) -> float:
    return round(value, 3)


def _finite(value: float | None) -> float | None:
    if value is None:
        return None
    if not math.isfinite(value):
        raise ValueError("value must be finite")
    return round(value, 3)


Label = Annotated[str, _text(LABEL_MAX), Field(min_length=1, max_length=LABEL_MAX)]
Sentence = Annotated[str, _text(SENTENCE_MAX), Field(min_length=1, max_length=SENTENCE_MAX)]
Code = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
Timestamp = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T[0-9:.+\-Z]{8,32}$")]
Unit = Annotated[float, Field(ge=0.0, le=1.0), AfterValidator(_rounded)]
Measurement = Annotated[float | None, Field(ge=-1e15, le=1e15), AfterValidator(_finite)]
IncidentId = Annotated[str, Field(pattern=r"^SIT-\d{1,12}$")]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class IncidentInfo(_Frozen):
    incident_id: IncidentId
    # False until the response layer has recorded the incident row.
    recorded: bool
    status: IncidentStatus | None = None
    created_at: Timestamp | None = None
    recovered_at: Timestamp | None = None
    resolved_at: Timestamp | None = None
    resolution: Code | None = None


class ScoreBreakdownContext(_Frozen):
    final_score: Unit
    score_before_decay: Unit
    severity: Unit
    confidence: Unit
    repetition: Unit
    escalation: Unit
    correlation: Unit
    cross_domain: Unit
    decay: Unit
    active_categories: list[Code] = Field(default_factory=list, max_length=MAX_CATEGORIES)
    corroborating_categories: int = Field(default=0, ge=0, le=MAX_CATEGORIES)


class ReasonContext(_Frozen):
    code: Code
    description: Sentence


class TransitionContext(_Frozen):
    from_state: DefenseState
    to_state: DefenseState
    trigger_score: Unit
    previous_score: Unit | None = None
    reason: ReasonContext | None = None
    at: Timestamp


class EvidenceContext(_Frozen):
    event_type: Label
    category: Code | None = None
    classification: Classification | None = None
    severity: Severity
    confidence: Unit | None = None
    metric_key: Label
    observed_value: Measurement = None
    threshold: Measurement = None
    detected_at: Timestamp
    age_seconds: float = Field(ge=0.0, le=1e9)
    is_synthetic: bool
    occurrences: int = Field(default=1, ge=1, le=1_000_000)
    # Attacker-influenced label (for example a process name). Data, never instructions.
    untrusted_subject: Label | None = None


class ResponseContext(_Frozen):
    action_type: ActionType
    defense_state: DefenseState
    status: Literal["SUCCEEDED", "BLOCKED", "FAILED"]
    guard_verdict: Literal["AUTHORIZED", "DENIED", "NOT_EVALUATED"]
    guard_reason: Sentence | None = None
    simulation_outcome: Code | None = None
    # Every response in Sentinel is simulated; the schema cannot express anything else.
    simulated: Literal[True] = True
    dry_run_description: Sentence
    at: Timestamp


class IncidentContext(_Frozen):
    """The sanitised, bounded explanation context for one incident."""

    schema_version: Literal[1] = 1  # CONTEXT_SCHEMA_VERSION
    trigger: ExplanationTrigger
    incident: IncidentInfo
    defense_state: DefenseState
    previous_state: DefenseState
    threat_score: Unit
    evaluated_at: Timestamp
    score_breakdown: ScoreBreakdownContext
    reasons: list[ReasonContext] = Field(default_factory=list, max_length=MAX_REASONS)
    transitions: list[TransitionContext] = Field(default_factory=list, max_length=MAX_TRANSITIONS)
    evidence: list[EvidenceContext] = Field(default_factory=list, max_length=MAX_EVIDENCE)
    responses: list[ResponseContext] = Field(default_factory=list, max_length=MAX_RESPONSES)

    def to_prompt_json(self) -> str:
        """JSON for a prompt: serialised, never interpolated (AS-08), delimiter-safe."""
        raw = self.model_dump_json()
        return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

    def fingerprint(self) -> str:
        """
        Identity of the situation as explained. Excludes what changes merely with
        the passage of time (evaluation time, evidence age) and why it was
        requested, so an unchanged situation is not explained twice.
        """
        stable = self.model_dump(
            mode="json",
            exclude={
                "trigger": True,
                "evaluated_at": True,
                "evidence": {"__all__": {"age_seconds"}},
            },
        )
        encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
