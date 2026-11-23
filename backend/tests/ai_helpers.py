"""Builders for AI-layer tests. Deterministic: no network, no wall clock."""

from __future__ import annotations

import json
from typing import Any

from ai.context import (
    EvidenceContext,
    IncidentContext,
    IncidentInfo,
    ReasonContext,
    ResponseContext,
    ScoreBreakdownContext,
    TransitionContext,
)
from ai.explainer import ExplainerLimits
from models.enums import (
    ActionType,
    Classification,
    DefenseState,
    ExplanationTrigger,
    IncidentStatus,
    Severity,
)

TS = "2025-01-01T12:00:00+00:00"

LIMITS = ExplainerLimits(
    timeout_seconds=0.05,
    max_attempts=2,
    max_output_tokens=500,
    max_raw_chars=8000,
    max_field_chars=2000,
    max_context_chars=24_000,
)


def evidence(**overrides: Any) -> EvidenceContext:
    base: dict[str, Any] = {
        "event_type": "suspicious_process",
        "category": "EXECUTION",
        "classification": Classification.HIGH_CONFIDENCE,
        "severity": Severity.CRITICAL,
        "confidence": 0.95,
        "metric_key": "synthetic:suspicious_process",
        "observed_value": 1.0,
        "threshold": 1.0,
        "detected_at": TS,
        "age_seconds": 5.0,
        "is_synthetic": True,
        "occurrences": 1,
        "untrusted_subject": "simulated-malware",
    }
    base.update(overrides)
    return EvidenceContext(**base)


def context(**overrides: Any) -> IncidentContext:
    base: dict[str, Any] = {
        "trigger": ExplanationTrigger.INCIDENT_CREATED,
        "incident": IncidentInfo(
            incident_id="SIT-1", recorded=True, status=IncidentStatus.OPEN, created_at=TS
        ),
        "defense_state": DefenseState.AGGRESSIVE,
        "previous_state": DefenseState.DEFENSIVE,
        "threat_score": 0.89,
        "evaluated_at": TS,
        "score_breakdown": ScoreBreakdownContext(
            final_score=0.89,
            score_before_decay=0.9,
            severity=0.45,
            confidence=0.14,
            repetition=0.05,
            escalation=0.05,
            correlation=0.15,
            cross_domain=0.05,
            decay=0.01,
            active_categories=["EXECUTION", "AUTHENTICATION"],
            corroborating_categories=2,
        ),
        "reasons": [ReasonContext(code="CRITICAL_EVENT", description="critical event active")],
        "transitions": [
            TransitionContext(
                from_state=DefenseState.DEFENSIVE,
                to_state=DefenseState.AGGRESSIVE,
                trigger_score=0.89,
                at=TS,
            )
        ],
        "evidence": [evidence()],
        "responses": [
            ResponseContext(
                action_type=ActionType.SIMULATE_QUARANTINE,
                defense_state=DefenseState.AGGRESSIVE,
                status="SUCCEEDED",
                guard_verdict="AUTHORIZED",
                guard_reason="Authorized",
                simulation_outcome="WOULD_QUARANTINE",
                dry_run_description="Quarantine the affected resource. Simulation only.",
                at=TS,
            )
        ],
    }
    base.update(overrides)
    return IncidentContext(**base)


def answer(**overrides: Any) -> str:
    """A valid provider answer, as JSON text."""
    base: dict[str, Any] = {
        "summary": "Incident SIT-1 is open and Sentinel is AGGRESSIVE.",
        "what_happened": "Repeated authentication failures were followed by a critical event.",
        "why_it_matters": "Two independent signal categories corroborate the threat.",
        "evidence": ["CRITICAL suspicious_process event", "ten authentication failures"],
        "current_state": "AGGRESSIVE, threat score 0.89, incident open.",
        "recommended_human_attention": "Review the evidence and the simulated quarantine.",
        "confidence": "HIGH",
    }
    base.update(overrides)
    return json.dumps(base)
