"""
Public read models of the running pipeline, and the read service behind them.

These schemas are the only shapes the runtime API and the live stream expose.
They mirror frontend/src/types/api.ts (P-08) and deliberately omit internal
fields: scope, once and idempotency keys, lifecycle and parameter JSON,
event_data envelopes, raw telemetry JSON and every AI audit field. Queries go
through the existing repositories, newest first and bounded (P-06).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database.models import DetectionEvent, ResponseAction, TelemetrySample, ThreatScore
from database.repositories import (
    DefenseStateChangeRepository,
    DetectionEventRepository,
    ResponseActionRepository,
    TelemetrySampleRepository,
    ThreatScoreRepository,
)
from models.enums import (
    ActionClass,
    ActionStatus,
    ActionType,
    Classification,
    DefenseState,
    Severity,
)
from response.actions import incident_id_for

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class _Schema(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SystemStatusSchema(_Schema):
    defense_state: DefenseState
    threat_score: float
    timestamp: datetime


class DemoRunSchema(_Schema):
    name: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    events_injected: int
    detections: int


class RuntimeStatusSchema(_Schema):
    """Monitoring health and basic measurements. No configuration values, no error text."""

    monitoring: bool
    healthy: bool
    started_at: datetime | None
    poll_interval_seconds: float
    defense_state: DefenseState
    threat_score: float | None
    last_decision_at: datetime | None
    cycles: int
    failed_cycles: int
    consecutive_failures: int
    telemetry_failures: int
    last_cycle_at: datetime | None
    last_cycle_ms: float | None
    max_cycle_ms: float | None
    last_telemetry_ms: float | None
    last_detection_ms: float | None
    last_decision_ms: float | None
    detections: int
    decisions: int
    actions_recorded: int
    synthetic_events: int
    events_per_minute: float | None
    last_error: str | None
    explanations_pending: int
    live_subscribers: int
    live_messages_dropped: int
    demo_running: str | None
    last_demo_run: DemoRunSchema | None


class TelemetrySnapshotSchema(_Schema):
    id: int
    collected_at: datetime
    cpu_percent: float | None
    memory_percent: float | None
    disk_read_rate: float | None
    disk_write_rate: float | None
    net_bytes_sent: float | None
    net_bytes_recv: float | None
    process_count: int | None


class DetectionEventSchema(_Schema):
    id: int
    detected_at: datetime
    rule_id: str
    rule_name: str
    severity: Severity
    metric_key: str
    metric_value: float | None
    threshold_value: float | None
    is_synthetic: bool
    event_type: str
    classification: Classification
    confidence: float | None
    status: str


class ThreatScoreSchema(_Schema):
    id: int
    calculated_at: datetime
    score: float


class DefenseStateReadingSchema(_Schema):
    current_state: DefenseState
    since: datetime | None
    threat_score_at_transition: float | None


class ActionRecordSchema(_Schema):
    id: int
    executed_at: datetime
    action_type: ActionType
    is_simulated: bool
    defense_state: DefenseState
    result: str | None
    dry_run_description: str
    # The public SIT-n identifier; internal situation and event ids are not exposed.
    incident_id: str | None
    status: ActionStatus | None
    action_class: ActionClass | None
    guard_reason: str | None


def telemetry_view(row: TelemetrySample) -> TelemetrySnapshotSchema:
    return TelemetrySnapshotSchema(
        id=row.id,
        collected_at=row.collected_at,
        cpu_percent=row.cpu_percent,
        memory_percent=row.memory_percent,
        disk_read_rate=row.disk_read_rate,
        disk_write_rate=row.disk_write_rate,
        net_bytes_sent=row.net_bytes_sent,
        net_bytes_recv=row.net_bytes_recv,
        process_count=row.process_count,
    )


def event_view(row: DetectionEvent) -> DetectionEventSchema:
    return DetectionEventSchema(
        id=row.id,
        detected_at=row.detected_at,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        severity=Severity(row.severity),
        metric_key=row.metric_key,
        metric_value=row.metric_value,
        threshold_value=row.threshold_value,
        is_synthetic=row.is_synthetic,
        event_type=row.event_type,
        classification=Classification(row.classification),
        confidence=row.confidence,
        status=row.status,
    )


def score_view(row: ThreatScore) -> ThreatScoreSchema:
    return ThreatScoreSchema(id=row.id, calculated_at=row.calculated_at, score=row.score)


def action_view(row: ResponseAction) -> ActionRecordSchema:
    return ActionRecordSchema(
        id=row.id,
        executed_at=row.executed_at,
        action_type=ActionType(row.action_type),
        is_simulated=row.is_simulated,
        defense_state=DefenseState(row.defense_state),
        result=row.result,
        dry_run_description=row.dry_run_description,
        incident_id=incident_id_for(row.situation_id) if row.situation_id is not None else None,
        status=ActionStatus(row.status) if row.status else None,
        action_class=ActionClass(row.action_class) if row.action_class else None,
        guard_reason=row.guard_reason,
    )


class RuntimeReadService:
    """Bounded, read-only queries for the runtime API. Builds no query itself."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def latest_telemetry(self) -> TelemetrySnapshotSchema | None:
        async with self._factory() as session:
            row = await TelemetrySampleRepository(session).get_latest()
        return telemetry_view(row) if row else None

    async def latest_score(self) -> ThreatScoreSchema | None:
        async with self._factory() as session:
            row = await ThreatScoreRepository(session).get_latest()
        return score_view(row) if row else None

    async def current_state(self) -> DefenseStateReadingSchema:
        async with self._factory() as session:
            change = await DefenseStateChangeRepository(session).get_latest()
        if change is None:
            return DefenseStateReadingSchema(
                current_state=DefenseState.RELAXED, since=None, threat_score_at_transition=None
            )
        return DefenseStateReadingSchema(
            current_state=DefenseState(change.to_state),
            since=change.changed_at,
            threat_score_at_transition=change.trigger_score,
        )

    async def recent_events(self, limit: int) -> list[DetectionEventSchema]:
        async with self._factory() as session:
            rows: Sequence[DetectionEvent] = await DetectionEventRepository(session).get_since(
                _EPOCH, limit=limit
            )
        return [event_view(r) for r in rows]

    async def recent_actions(self, limit: int) -> list[ActionRecordSchema]:
        async with self._factory() as session:
            rows = await ResponseActionRepository(session).get_all(limit=limit)
        return [action_view(r) for r in rows]
