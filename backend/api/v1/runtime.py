"""
Read-only runtime endpoints: status, runtime health, state, score, telemetry,
detection events and simulated response actions.

Every route is a GET over the public read models in core/runtime_views.py. None
accepts input that reaches the security pipeline. Handlers stay thin (P-06).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.runtime import SentinelRuntime
from core.runtime_views import (
    ActionRecordSchema,
    DefenseStateReadingSchema,
    DetectionEventSchema,
    RuntimeReadService,
    RuntimeStatusSchema,
    SystemStatusSchema,
    TelemetrySnapshotSchema,
    ThreatScoreSchema,
)
from database.engine import get_session_factory

router = APIRouter(prefix="/api/v1", tags=["runtime"])

Limit = Annotated[int, Query(ge=1, le=200)]


def get_runtime(request: Request) -> SentinelRuntime:
    runtime: SentinelRuntime | None = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="runtime not started")
    return runtime


def session_factory_or_503(request: Request) -> async_sessionmaker[AsyncSession]:
    """
    The database session factory, or 503 while no runtime is attached.

    A runtime is attached only after its database schema is complete and it has
    started (app/lifecycle.py), so reads never reach a database that is still being
    created or migrated, as during a demo reset.
    """
    if getattr(request.app.state, "runtime", None) is None:
        raise HTTPException(status_code=503, detail="runtime not started")
    try:
        return get_session_factory()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="runtime not started") from None


def get_runtime_reads(request: Request) -> RuntimeReadService:
    return RuntimeReadService(session_factory_or_503(request))


Runtime = Annotated[SentinelRuntime, Depends(get_runtime)]
Reads = Annotated[RuntimeReadService, Depends(get_runtime_reads)]


@router.get("/status", response_model=SystemStatusSchema)
async def system_status(runtime: Runtime) -> SystemStatusSchema:
    last = runtime.last_decision
    if last is None:
        raise HTTPException(status_code=503, detail="no decision yet")
    return SystemStatusSchema(
        defense_state=last.defense_state,
        threat_score=last.threat_score,
        timestamp=last.calculated_at,
    )


@router.get("/runtime", response_model=RuntimeStatusSchema)
async def runtime_status(runtime: Runtime) -> RuntimeStatusSchema:
    return runtime.status_view()


@router.get("/state/current", response_model=DefenseStateReadingSchema)
async def current_state(reads: Reads) -> DefenseStateReadingSchema:
    return await reads.current_state()


@router.get("/score/current", response_model=ThreatScoreSchema)
async def current_score(reads: Reads) -> ThreatScoreSchema:
    score = await reads.latest_score()
    if score is None:
        raise HTTPException(status_code=404, detail="no threat score yet")
    return score


@router.get("/telemetry/latest", response_model=TelemetrySnapshotSchema)
async def latest_telemetry(reads: Reads) -> TelemetrySnapshotSchema:
    sample = await reads.latest_telemetry()
    if sample is None:
        raise HTTPException(status_code=404, detail="no telemetry yet")
    return sample


@router.get("/events", response_model=list[DetectionEventSchema])
async def recent_events(reads: Reads, limit: Limit = 50) -> list[DetectionEventSchema]:
    return await reads.recent_events(limit)


@router.get("/actions", response_model=list[ActionRecordSchema])
async def recent_actions(reads: Reads, limit: Limit = 50) -> list[ActionRecordSchema]:
    return await reads.recent_actions(limit)
