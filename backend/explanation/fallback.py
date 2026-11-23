"""Deterministic, non-AI fallback text (AS-06). Built only from Sentinel's own values."""

from __future__ import annotations

FALLBACK_NOTICE = (
    "AI explanation unavailable; authoritative reason codes and threat evidence remain available."
)


def fallback_explanation(incident_id: str, defense_state: str, threat_score: float | None) -> str:
    score = "unknown" if threat_score is None else f"{threat_score:.2f}"
    return (
        f"{FALLBACK_NOTICE} Manual analyst review required. Incident ID: {incident_id}. "
        f"Defense state: {defense_state}. Threat score: {score}."
    )
