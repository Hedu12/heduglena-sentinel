"""
Machine-readable reason codes and their display text.

Codes are the source of truth for *why* a score or state is what it is.
Display text is derived from codes for people; nothing parses it.
"""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    # Score reasons
    NO_ACTIVE_EVIDENCE = "NO_ACTIVE_EVIDENCE"
    CRITICAL_EVENT = "CRITICAL_EVENT"
    HIGH_SEVERITY_EVENT = "HIGH_SEVERITY_EVENT"
    HIGH_CONFIDENCE_EVIDENCE = "HIGH_CONFIDENCE_EVIDENCE"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    INFORMATIONAL_ANOMALY = "INFORMATIONAL_ANOMALY"
    SYNTHETIC_SECURITY_EVENT = "SYNTHETIC_SECURITY_EVENT"
    REPEATED_ACTIVITY = "REPEATED_ACTIVITY"
    ESCALATING_ACTIVITY = "ESCALATING_ACTIVITY"
    CROSS_SIGNAL_CORRELATION = "CROSS_SIGNAL_CORRELATION"
    CROSS_DOMAIN_CORRELATION = "CROSS_DOMAIN_CORRELATION"
    EVIDENCE_DECAYING = "EVIDENCE_DECAYING"
    # State-machine reasons
    DWELL_SATISFIED = "DWELL_SATISFIED"
    SEVERE_ESCALATION_BYPASS = "SEVERE_ESCALATION_BYPASS"
    ACTIVE_THREAT_FLOOR = "ACTIVE_THREAT_FLOOR"
    DE_ESCALATION_COOLDOWN_ELAPSED = "DE_ESCALATION_COOLDOWN_ELAPSED"
    DWELL_PENDING = "DWELL_PENDING"
    COOLDOWN_PENDING = "COOLDOWN_PENDING"
    HYSTERESIS_HOLD = "HYSTERESIS_HOLD"
    AGGRESSIVE_NEEDS_CORROBORATION = "AGGRESSIVE_NEEDS_CORROBORATION"


REASON_TEXT: dict[ReasonCode, str] = {
    ReasonCode.NO_ACTIVE_EVIDENCE: "no active detection evidence",
    ReasonCode.CRITICAL_EVENT: "critical-severity detection event is active",
    ReasonCode.HIGH_SEVERITY_EVENT: "high-severity detection event is active",
    ReasonCode.HIGH_CONFIDENCE_EVIDENCE: "high-confidence evidence of a security-relevant event",
    ReasonCode.SUSPICIOUS_ACTIVITY: "suspicious activity detected",
    ReasonCode.INFORMATIONAL_ANOMALY: "unusual activity, insufficient evidence of malice",
    ReasonCode.SYNTHETIC_SECURITY_EVENT: "synthetic security event (demonstration)",
    ReasonCode.REPEATED_ACTIVITY: "repeated activity from the same signal",
    ReasonCode.ESCALATING_ACTIVITY: "activity escalated to higher severity or confidence",
    ReasonCode.CROSS_SIGNAL_CORRELATION: "multiple independent signal categories are active",
    ReasonCode.CROSS_DOMAIN_CORRELATION: "resource anomaly correlated with a security event",
    ReasonCode.EVIDENCE_DECAYING: "older evidence is losing weight",
    ReasonCode.DWELL_SATISFIED: "score stayed above the entry threshold for the dwell time",
    ReasonCode.SEVERE_ESCALATION_BYPASS: "severe escalation skipped the dwell time",
    ReasonCode.ACTIVE_THREAT_FLOOR: "an active high-severity threat keeps the state raised",
    ReasonCode.DE_ESCALATION_COOLDOWN_ELAPSED: "score stayed below exit threshold for the cooldown",
    ReasonCode.DWELL_PENDING: "score is above the entry threshold, dwell time not yet elapsed",
    ReasonCode.COOLDOWN_PENDING: "score is below the exit threshold, cooldown not yet elapsed",
    ReasonCode.HYSTERESIS_HOLD: "score is inside the hysteresis band, state held",
    ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION: (
        "bypass into AGGRESSIVE withheld: too few independent signal categories"
    ),
}


def reason_text(codes: tuple[ReasonCode, ...] | list[ReasonCode]) -> list[str]:
    """Human-readable text for a sequence of reason codes."""
    return [REASON_TEXT[code] for code in codes]
