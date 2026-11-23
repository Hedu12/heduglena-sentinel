"""
ORM table models for HEDUGLENA Sentinel.

All tables implement the schema defined in sentinel-spec.md §12.
Key invariants:

- P-07: Audit tables are APPEND-ONLY. No UPDATE logic lives here.
- P-05: response_actions.is_simulated defaults to True (safe default).
- SR-06: No secrets or credentials are stored.
- Timestamps use DateTime(timezone=True) — always UTC-aware.
- lazy="raise" on relationships prevents silent N+1 queries.

Models use MappedAsDataclass (via Base) so that mapped_column(default=X)
applies at Python __init__ time for scalar defaults.

FK column rule: foreign-key columns that callers supply values for are
declared as Mapped[Optional[int]] with no default= so SQLAlchemy does not
overwrite the caller-supplied value during flush. See SQLAlchemy docs on
MappedAsDataclass and "Applying ORM Mappings to an Existing dataclass".
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from models.enums import (
    ActionClass,
    Classification,
    DefenseState,
    EventStatus,
    ExplanationStatus,
    ExplanationTrigger,
    IncidentStatus,
    Severity,
)


def _in_list(column: str, enum_cls: type[StrEnum]) -> str:
    """Build a CHECK expression from enum members (constants, never user input)."""
    values = ", ".join(f"'{member.value}'" for member in enum_cls)
    return f"{column} IN ({values})"


# ---------------------------------------------------------------------------
# telemetry_samples
# ---------------------------------------------------------------------------


class TelemetrySample(Base):
    """
    One point-in-time snapshot of host metrics.

    Null values indicate that a metric failed to read (graceful degradation,
    spec AC-F01-4). collected_at is the only required field.
    """

    __tablename__ = "telemetry_samples"

    # Required ——————————————————————————————————————————————————————————————
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Optional metric fields — scalar default=None survives flush correctly ——
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    memory_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    disk_read_rate: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    disk_write_rate: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    net_bytes_sent: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    net_bytes_recv: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    process_count: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK — excluded from __init__ ———————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (Index("ix_telemetry_samples_collected_at", "collected_at"),)


# ---------------------------------------------------------------------------
# detection_events
# ---------------------------------------------------------------------------


class DetectionEvent(Base):
    """
    A single rule firing against a telemetry sample or synthetic event.

    Append-only (P-07). is_synthetic defaults False — real telemetry is
    the base case; synthetic injection via demo API sets it True.
    """

    __tablename__ = "detection_events"

    # Required ——————————————————————————————————————————————————————————————
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    metric_key: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    metric_value: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    threshold_value: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Structured JSON envelope: {"schema_version", "source_kind", "evidence": {...}}.
    event_data: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Phase 3 detection fields ———————————————————————————————————————————————
    # Source telemetry sample (None for synthetic events). Plain FK column with
    # no relationship, so the ORM never rewrites it during flush.
    telemetry_sample_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey(
            "telemetry_samples.id",
            ondelete="SET NULL",
            name="fk_detection_events_telemetry_sample_id",
        ),
        nullable=True,
        default=None,
    )
    # Machine-readable event kind, e.g. "cpu_sustained_high".
    event_type: Mapped[str] = mapped_column(
        Text, nullable=False, default="unspecified", server_default="unspecified"
    )
    # INFORMATIONAL | SUSPICIOUS | HIGH_CONFIDENCE (models.enums.Classification).
    classification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default=Classification.INFORMATIONAL.value,
        server_default=Classification.INFORMATIONAL.value,
    )
    # Detector confidence in [0.0, 1.0]; None means "not assessed".
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    # Status at creation. Events are append-only, so this is never updated.
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default=EventStatus.OPEN.value,
        server_default=EventStatus.OPEN.value,
    )

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    # Relationship (init=False — read-only navigation from DetectionEvent) —
    # viewonly=True prevents this relationship from writing triggering_event_id.
    # The FK column is owned exclusively by ResponseAction.triggering_event.
    response_actions: Mapped[list[ResponseAction]] = relationship(
        "ResponseAction",
        lazy="raise",
        init=False,
        default_factory=list,
        foreign_keys="[ResponseAction.triggering_event_id]",
        viewonly=True,
        overlaps="triggering_event",
    )

    __table_args__ = (
        Index("ix_detection_events_detected_at", "detected_at"),
        Index("ix_detection_events_rule_id", "rule_id"),
        Index("ix_detection_events_severity", "severity"),
        Index("ix_detection_events_telemetry_sample_id", "telemetry_sample_id"),
        CheckConstraint(_in_list("severity", Severity), name="ck_detection_events_severity"),
        CheckConstraint(
            _in_list("classification", Classification), name="ck_detection_events_classification"
        ),
        CheckConstraint(_in_list("status", EventStatus), name="ck_detection_events_status"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_detection_events_confidence_range",
        ),
    )


# ---------------------------------------------------------------------------
# incidents
# ---------------------------------------------------------------------------


class Incident(Base):
    """
    A named, correlated security incident grouping related detection events.

    incident_id is a stable string UUID used as FK in ai_explanations.
    status (open → investigating → resolved) and the resolution fields are the
    only mutable data, and each is written at most once by Sentinel: resolution
    is a conditional UPDATE that applies only to an OPEN incident.
    """

    __tablename__ = "incidents"

    # Required ——————————————————————————————————————————————————————————————
    incident_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    defense_state: Mapped[str] = mapped_column(Text, nullable=False)
    threat_score_at_creation: Mapped[float] = mapped_column(Float, nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    status: Mapped[str] = mapped_column(Text, nullable=False, default=IncidentStatus.OPEN.value)
    event_ids: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # When the defense state returned to RELAXED for the last time in the situation.
    recovered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # When Sentinel confirmed the situation was over and resolved the incident.
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (
        Index("ix_incidents_created_at", "created_at"),
        Index("ix_incidents_status", "status"),
        CheckConstraint(_in_list("status", IncidentStatus), name="ck_incidents_status"),
    )


# ---------------------------------------------------------------------------
# threat_scores
# ---------------------------------------------------------------------------


class ThreatScore(Base):
    """
    One threat-score calculation result.

    Append-only (P-07). Full history kept for timeline chart (AC-F03-4).
    score is in [0.0, 1.0] — enforced by the scorer, not the DB.
    """

    __tablename__ = "threat_scores"

    # Required ——————————————————————————————————————————————————————————————
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    contributing_events: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # Phase 4: posture at calculation time, and the structured score breakdown (JSON).
    defense_state: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    breakdown: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (
        Index("ix_threat_scores_calculated_at", "calculated_at"),
        CheckConstraint("score >= 0.0 AND score <= 1.0", name="ck_threat_scores_range"),
        CheckConstraint(
            f"defense_state IS NULL OR {_in_list('defense_state', DefenseState)}",
            name="ck_threat_scores_state",
        ),
    )


# ---------------------------------------------------------------------------
# defense_state_changes
# ---------------------------------------------------------------------------


class DefenseStateChange(Base):
    """
    One recorded transition of the defense state machine.

    Append-only (P-07). Tamper-evident audit trail. See AC-F04-3.

    Python attributes from_state/to_state map to DB columns
    previous_state/new_state. The name 'new_state' conflicts with
    SQLAlchemy's internal InstanceState instrumentation when used as a
    Python attribute name on MappedAsDataclass models.
    """

    __tablename__ = "defense_state_changes"

    # Required ——————————————————————————————————————————————————————————————
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    from_state: Mapped[str] = mapped_column("previous_state", Text, nullable=False)
    to_state: Mapped[str] = mapped_column("new_state", Text, nullable=False)
    trigger_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    trigger_event_ids: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # Phase 4: score before this evaluation, the primary reason code, and the
    # structured evidence (JSON) behind the transition.
    previous_score: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (
        Index("ix_defense_state_changes_changed_at", "changed_at"),
        CheckConstraint(
            _in_list("previous_state", DefenseState), name="ck_defense_state_changes_from"
        ),
        CheckConstraint(_in_list("new_state", DefenseState), name="ck_defense_state_changes_to"),
        CheckConstraint(
            "previous_state <> new_state", name="ck_defense_state_changes_is_transition"
        ),
        CheckConstraint(
            "trigger_score >= 0.0 AND trigger_score <= 1.0",
            name="ck_defense_state_changes_trigger_score",
        ),
        CheckConstraint(
            "previous_score IS NULL OR (previous_score >= 0.0 AND previous_score <= 1.0)",
            name="ck_defense_state_changes_previous_score",
        ),
    )


# ---------------------------------------------------------------------------
# response_actions
# ---------------------------------------------------------------------------


class ResponseAction(Base):
    """
    One executed (or simulated) response action.

    Append-only (P-07).
    is_simulated defaults True (P-05, SR-01) — safe default. Callers must
    explicitly pass is_simulated=False for live actions (ResponseGuard).
    dry_run_description always documents what this action would have done live.

    triggering_event_id is Mapped[Optional[int]] with no default= so that
    a caller-supplied FK value is not overwritten during flush.
    """

    __tablename__ = "response_actions"

    # Required ——————————————————————————————————————————————————————————————
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    defense_state: Mapped[str] = mapped_column(Text, nullable=False)
    dry_run_description: Mapped[str] = mapped_column(Text, nullable=False)
    # FK declared without default= so caller-supplied values survive flush.
    triggering_event_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("detection_events.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Optional / defaulted ——————————————————————————————————————————————————
    # Safe default: simulated. Never default to live execution (P-05, SR-01).
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    parameters: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    result: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Phase 5 response-engine fields ——————————————————————————————————————————
    # Nullable so rows written before Phase 5 stay valid; the response service
    # always sets them.
    # Security situation the action belongs to (None for out-of-situation alerts).
    situation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    # Terminal lifecycle status: BLOCKED | SUCCEEDED | FAILED.
    status: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # ResponseGuard's classification of the action at authorization time.
    action_class: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # ResponseGuard's (or the precondition's) reason for its verdict.
    guard_reason: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # What an action is deduplicated and cooled down against, e.g. "s12:SIMULATE_IP_BLOCK".
    scope_key: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # Set for once-per-scope actions; at most one SUCCEEDED row may share it.
    once_key: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # One row per (scope, decision): processing the same decision twice is a no-op.
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # JSON list of lifecycle steps: [{"status", "at", "detail"}, ...].
    lifecycle: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    # Relationship ——————————————————————————————————————————————————————————
    # One-way write: ResponseAction owns triggering_event_id.
    # DetectionEvent.response_actions is viewonly and uses overlaps= to
    # prevent SQLAlchemy from treating both as competing FK owners.
    triggering_event: Mapped[DetectionEvent | None] = relationship(
        "DetectionEvent",
        lazy="raise",
        init=False,
        default=None,
        foreign_keys="[ResponseAction.triggering_event_id]",
        overlaps="response_actions",
    )

    __table_args__ = (
        Index("ix_response_actions_executed_at", "executed_at"),
        Index("ix_response_actions_action_type", "action_type"),
        Index("ix_response_actions_scope_key", "scope_key"),
        Index("ix_response_actions_situation_id", "situation_id"),
        # Idempotency: one row per (scope, decision), enforced by the database.
        Index("uq_response_actions_idempotency_key", "idempotency_key", unique=True),
        # Deduplication: at most one SUCCEEDED row per once-key, enforced by the database.
        Index(
            "uq_response_actions_once_success",
            "once_key",
            unique=True,
            sqlite_where=text("status = 'SUCCEEDED'"),
            postgresql_where=text("status = 'SUCCEEDED'"),
        ),
        CheckConstraint(
            "status IS NULL OR status IN ('BLOCKED', 'SUCCEEDED', 'FAILED')",
            name="ck_response_actions_terminal_status",
        ),
        CheckConstraint(
            f"action_class IS NULL OR {_in_list('action_class', ActionClass)}",
            name="ck_response_actions_action_class",
        ),
        CheckConstraint(
            _in_list("defense_state", DefenseState), name="ck_response_actions_defense_state"
        ),
    )


# ---------------------------------------------------------------------------
# ai_explanations
# ---------------------------------------------------------------------------


# Hard cap on the stored raw provider answer (audit artifact, AS-07). Also a CHECK.
RAW_RESPONSE_MAX_CHARS = 16_000


class AIExplanationRecord(Base):
    """
    Audit record for every AI provider call (AS-07).

    Both raw_response (pre-validation) and explanation (sanitised) stored.
    explanation is shown on the dashboard. raw_response is for audit only.
    """

    __tablename__ = "ai_explanations"

    # Required ——————————————————————————————————————————————————————————————
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    incident_id: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    model: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    response_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Phase 6 explanation audit fields ——————————————————————————————————————
    # Nullable so rows written before Phase 6 stay valid.
    # Linkage to the security situation. Stored here, never sent to the model.
    situation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    # ExplanationTrigger: why the explanation was requested.
    trigger: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # ExplanationStatus: VALID | REJECTED | FAILED. Only VALID content is displayed.
    status: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # ExplanationFailure code, plus a fixed rule/step code. Never raw model or exception text.
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    failure_detail: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    attempts: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    # SHA-256 of the explained context, for deduplication.
    context_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # The validated structured explanation (JSON): the canonical explanation.
    # NULL unless status is VALID. raw_response, by contrast, is an audit artifact.
    content: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Phase 6.1 restart-stable trigger memory ———————————————————————————————
    # What the explanation was triggered by, unique per incident (for example
    # "INCIDENT_CREATED" or "STATE_TRANSITION:<transition id>").
    trigger_key: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # Decision time the explanation describes (not the wall clock).
    decision_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # Evidence the explanation was based on (JSON: categories, severity rank, score).
    evidence_state: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (
        Index("ix_ai_explanations_incident_id", "incident_id"),
        Index("ix_ai_explanations_generated_at", "generated_at"),
        CheckConstraint(
            f"status IS NULL OR {_in_list('status', ExplanationStatus)}",
            name="ck_ai_explanations_status",
        ),
        CheckConstraint(
            f"trigger IS NULL OR {_in_list('trigger', ExplanationTrigger)}",
            name="ck_ai_explanations_trigger",
        ),
        CheckConstraint(
            "status IS NULL OR status = 'VALID' OR content IS NULL",
            name="ck_ai_explanations_content_only_when_valid",
        ),
        CheckConstraint(
            f"raw_response IS NULL OR length(raw_response) <= {RAW_RESPONSE_MAX_CHARS}",
            name="ck_ai_explanations_raw_response_size",
        ),
        # One explanation per trigger per incident, whatever restarts or races happen.
        Index(
            "uq_ai_explanations_trigger_key",
            "incident_id",
            "trigger_key",
            unique=True,
            sqlite_where=text("trigger_key IS NOT NULL"),
            postgresql_where=text("trigger_key IS NOT NULL"),
        ),
        Index("ix_ai_explanations_situation_decision", "situation_id", "decision_at"),
    )


# ---------------------------------------------------------------------------
# baselines
# ---------------------------------------------------------------------------


class Baseline(Base):
    """
    Rolling statistical baseline per telemetry metric (spec §8.4).

    ONE table that uses UPSERT — a baseline is a live accumulator.
    UNIQUE on metric_key enforces one row per metric.
    """

    __tablename__ = "baselines"

    # Required ——————————————————————————————————————————————————————————————
    metric_key: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Optional / defaulted ——————————————————————————————————————————————————
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mean: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    std_dev: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # PK ————————————————————————————————————————————————————————————————————
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, init=False, default=None
    )

    __table_args__ = (
        UniqueConstraint("metric_key", name="uq_baselines_metric_key"),
        Index("ix_baselines_metric_key", "metric_key"),
    )
