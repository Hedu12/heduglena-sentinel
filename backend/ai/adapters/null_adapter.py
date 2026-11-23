"""
NullProvider: the default provider (AI_PROVIDER=null). See AS-09.

No network, no model, fully deterministic. It renders a structured explanation
from the sanitised context using fixed sentence templates, and its answer goes
through exactly the same validation as a real model's. It never repeats
attacker-influenced labels (untrusted_* fields), so hostile evidence cannot be
reflected into its output.
"""

from __future__ import annotations

import json

from ai.context import EvidenceContext, IncidentContext
from ai.protocols import ExplanationRequest, ProviderResponse

NULL_PROVIDER_NAME = "null"
NULL_MODEL_NAME = "deterministic-template"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


def _number(value: float | None) -> str:
    return "n/a" if value is None else f"{value:g}"


def _evidence_line(e: EvidenceContext) -> str:
    classification = e.classification.value if e.classification else "unclassified"
    return _clip(
        f"{e.severity.value} {e.event_type} ({classification}): {e.metric_key} observed "
        f"{_number(e.observed_value)}, threshold {_number(e.threshold)}, "
        f"seen {e.occurrences} time(s)",
        300,
    )


def deterministic_explanation(context: IncidentContext) -> dict[str, object]:
    """A schema-valid explanation built only from Sentinel's own fields."""
    incident = context.incident
    status = incident.status.value if incident.status else "not yet recorded"
    score = f"{context.threat_score:.2f}"

    steps = [
        f"{t.from_state.value} to {t.to_state.value} at {t.at} (score {t.trigger_score:.2f})"
        for t in context.transitions[-8:]
    ]
    what = (
        "Defense state transitions: " + "; ".join(steps) + "."
        if steps
        else "No defense state transitions are recorded for this incident yet."
    )
    reasons = [r.description for r in context.reasons]
    why = (
        "Sentinel's reasons: " + "; ".join(reasons) + "."
        if reasons
        else "Sentinel recorded no reason codes for this evaluation."
    )
    evidence = [_evidence_line(e) for e in context.evidence[:8]] or [
        "No detection events are attached to this evaluation."
    ]
    responses = ", ".join(f"{r.action_type.value} {r.status}" for r in context.responses[-6:])
    current = (
        f"Defense state {context.defense_state.value} (previously "
        f"{context.previous_state.value}), threat score {score}, incident {status}."
    )
    return {
        "summary": _clip(
            f"Incident {incident.incident_id} is {status}; Sentinel is in "
            f"{context.defense_state.value} with threat score {score}.",
            400,
        ),
        "what_happened": _clip(what, 1200),
        "why_it_matters": _clip(why, 1200),
        "evidence": evidence,
        "current_state": _clip(current, 400),
        "recommended_human_attention": _clip(
            "Review the listed evidence and the simulated responses"
            + (f" ({responses})" if responses else "")
            + ". Every response was a simulation; no host was modified.",
            1200,
        ),
        "confidence": "MEDIUM",
    }


class NullProvider:
    """Deterministic, offline provider. Safe for CI, demos and tests."""

    name = NULL_PROVIDER_NAME

    async def generate_explanation(self, request: ExplanationRequest) -> ProviderResponse:
        text = json.dumps(deterministic_explanation(request.context), ensure_ascii=False)
        return ProviderResponse(text=text, model=NULL_MODEL_NAME)
