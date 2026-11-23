"""
Read-only incident and explanation views served by the API (Phase 6).

Mirrored by frontend/src/types/api.ts (P-08). These views deliberately omit
internal security-control fields: scope, once and idempotency keys, raw
lifecycle and parameter JSON, raw provider output, context fingerprints,
untrusted labels and configuration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from models.enums import (
    ActionType,
    DefenseState,
    ExplanationConfidence,
    ExplanationFailure,
    ExplanationStatus,
    ExplanationTrigger,
    IncidentStatus,
)


class _View(BaseModel):
    model_config = ConfigDict(frozen=True)


class ReasonSchema(_View):
    code: str
    description: str


class IncidentSummarySchema(_View):
    incident_id: str
    status: IncidentStatus
    created_at: datetime
    defense_state_at_creation: DefenseState
    threat_score_at_creation: float
    recovered_at: datetime | None
    resolved_at: datetime | None
    resolution: str | None
    summary: str | None


class ScoreBreakdownSchema(_View):
    calculated_at: datetime
    score: float
    defense_state: DefenseState | None
    severity: float
    confidence: float
    repetition: float
    escalation: float
    correlation: float
    cross_domain: float
    decay: float
    active_categories: list[str]
    reasons: list[ReasonSchema]


class EvidenceSchema(_View):
    detected_at: datetime
    rule_name: str
    event_type: str
    classification: str
    severity: str
    confidence: float | None
    metric_key: str
    metric_value: float | None
    threshold_value: float | None
    is_synthetic: bool


class TransitionSchema(_View):
    changed_at: datetime
    from_state: DefenseState
    to_state: DefenseState
    trigger_score: float
    reason: ReasonSchema | None


GuardVerdict = Literal["AUTHORIZED", "DENIED", "NOT_EVALUATED"]


class SimulationSchema(_View):
    executed_at: datetime
    action_type: ActionType
    defense_state: DefenseState
    status: str
    guard_verdict: GuardVerdict
    guard_reason: str | None
    simulation_outcome: str | None
    dry_run_description: str
    is_simulated: bool


class ExplanationContentSchema(_View):
    summary: str
    what_happened: str
    why_it_matters: str
    evidence: list[str]
    current_state: str
    recommended_human_attention: str
    confidence: ExplanationConfidence


class ExplanationSchema(_View):
    generated_at: datetime
    trigger: ExplanationTrigger | None
    provider: str
    model: str | None
    status: ExplanationStatus | None
    failure_reason: ExplanationFailure | None
    latency_ms: int | None
    # Present only for VALID explanations.
    content: ExplanationContentSchema | None


Availability = Literal["AVAILABLE", "PENDING", "UNAVAILABLE"]


class ExplanationStateSchema(_View):
    """What the dashboard shows in the AI panel for one incident."""

    incident_id: str
    # AVAILABLE: a validated explanation exists. PENDING: none attempted yet.
    # UNAVAILABLE: attempts were made, none produced a valid explanation.
    availability: Availability
    # The latest VALID explanation (it may be older than the latest attempt).
    explanation: ExplanationSchema | None
    latest_attempt: ExplanationSchema | None
    # Deterministic non-AI text; always present.
    fallback_text: str


class IncidentDetailSchema(_View):
    incident: IncidentSummarySchema
    current_score: ScoreBreakdownSchema | None
    evidence: list[EvidenceSchema]
    transitions: list[TransitionSchema]
    simulations: list[SimulationSchema]
    ai: ExplanationStateSchema


class AIStatusSchema(_View):
    provider: str
    # False when the deterministic null provider is configured.
    language_model_configured: bool
    explanation_only: Literal[True] = True
