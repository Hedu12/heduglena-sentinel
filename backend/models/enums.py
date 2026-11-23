"""
Shared enumerations used across the domain.

Defined here (in models) so they can be imported by both the domain
modules and the API layer without creating circular dependencies.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Detection event severity levels, ordered from lowest to highest."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DefenseState(StrEnum):
    """
    Four adaptive defense postures.
    See .kiro/specs/sentinel-spec.md section 9 for full state machine definition.
    """

    RELAXED = "RELAXED"
    ALERT = "ALERT"
    DEFENSIVE = "DEFENSIVE"
    AGGRESSIVE = "AGGRESSIVE"


class ActionType(StrEnum):
    """Response actions available to the response engine."""

    GENERATE_ALERT = "GENERATE_ALERT"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    RECORD_INCIDENT = "RECORD_INCIDENT"
    SIMULATE_IP_BLOCK = "SIMULATE_IP_BLOCK"
    SIMULATE_PROCESS_ISOLATE = "SIMULATE_PROCESS_ISOLATE"
    SIMULATE_QUARANTINE = "SIMULATE_QUARANTINE"


class ActionClass(StrEnum):
    """
    Broad classification of an action's impact.
    LIVE_PROTECTIVE actions require LIVE_ACTIONS=true.
    """

    INFORMATIONAL = "INFORMATIONAL"
    MONITORING = "MONITORING"
    SIMULATED_PROTECTIVE = "SIMULATED_PROTECTIVE"
    LIVE_PROTECTIVE = "LIVE_PROTECTIVE"


class ActionStatus(StrEnum):
    """
    Lifecycle of one response action.

    PLANNED -> AUTHORIZED -> EXECUTING -> SUCCEEDED | FAILED
    PLANNED -> BLOCKED          (refused by ResponseGuard or a precondition)
    AUTHORIZED -> BLOCKED       (refused by the live-execution protection)

    Only terminal statuses (BLOCKED, SUCCEEDED, FAILED) are persisted: a row is
    written once, when the action has finished, and never updated (P-07).
    """

    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class RuleCondition(StrEnum):
    """Detection rule evaluation strategies."""

    THRESHOLD = "THRESHOLD"
    DEVIATION = "DEVIATION"
    SYNTHETIC = "SYNTHETIC"
    COMPOSITE = "COMPOSITE"
    SUSTAINED = "SUSTAINED"


class SyntheticEventType(StrEnum):
    """
    Allowlist of valid synthetic event types for the demo injection endpoint.
    Unknown types must be rejected with HTTP 422. See SR-03.
    """

    CPU_SPIKE = "cpu_spike"
    MEMORY_PRESSURE = "memory_pressure"
    AUTH_FAILURE = "auth_failure"
    SUSPICIOUS_PROCESS = "suspicious_process"
    NETWORK_SURGE = "network_surge"
    DISK_IO_SPIKE = "disk_io_spike"
    ACCESS_DENIED = "access_denied"
    CONNECTION_BURST = "connection_burst"


class Classification(StrEnum):
    """
    How much evidence supports a detection (Phase 3 detection philosophy).

    INFORMATIONAL: something unusual, insufficient evidence of malice.
    SUSPICIOUS: repeated or multiple indicators of potentially malicious activity.
    HIGH_CONFIDENCE: evidence strongly indicates a security-relevant event.
    """

    INFORMATIONAL = "INFORMATIONAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"


class IncidentStatus(StrEnum):
    """
    Lifecycle of an incident.

    OPEN          created when a security situation opens.
    INVESTIGATING set by an analyst; Sentinel never sets or clears it.
    RESOLVED      the situation is over for good: it recovered to RELAXED and did
                  not resume within the reopen window, or a new situation replaced it.
                  Sentinel resolves only OPEN incidents automatically.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class ExplanationTrigger(StrEnum):
    """
    Why an explanation was requested (Phase 6). Ordered by significance: when
    requests are coalesced, the most significant trigger is kept.
    """

    INCIDENT_CREATED = "INCIDENT_CREATED"
    STATE_TRANSITION = "STATE_TRANSITION"
    NEW_EVIDENCE = "NEW_EVIDENCE"
    AGGRESSIVE_REFRESH = "AGGRESSIVE_REFRESH"


class ExplanationStatus(StrEnum):
    """Outcome of one explanation attempt. Only VALID content is ever displayed."""

    VALID = "VALID"
    REJECTED = "REJECTED"  # the provider answered, but the output failed validation
    FAILED = "FAILED"  # no usable answer (timeout, provider error, no context)


class ExplanationFailure(StrEnum):
    """Machine-readable reason an explanation is not VALID. Never raw exception text."""

    TIMEOUT = "TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    EMPTY_RESPONSE = "EMPTY_RESPONSE"
    OVERSIZED_OUTPUT = "OVERSIZED_OUTPUT"
    MALFORMED_JSON = "MALFORMED_JSON"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    UNSAFE_CONTENT = "UNSAFE_CONTENT"
    VALIDATOR_REDACTED = "VALIDATOR_REDACTED"
    CONTEXT_UNAVAILABLE = "CONTEXT_UNAVAILABLE"


class ExplanationConfidence(StrEnum):
    """The model's self-reported confidence in its explanation (not evidence)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EventStatus(StrEnum):
    """
    Initial lifecycle status of a detection event.

    Detection events are append-only (P-07), so status is set at creation.
    Triage state belongs on the incident record, not on the event.
    """

    OPEN = "open"
