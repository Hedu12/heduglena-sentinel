"""
Read-only incident and AI-explanation endpoints (Phase 6).

Every route is a GET. There is no endpoint that accepts explanation text, so a
client cannot feed AI output (or anything else) back into the security
pipeline through this router. Handlers validate input and call
IncidentReadService (P-06); they build no queries themselves.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from core.config import settings
from database.engine import get_session_factory
from explanation.incident_view import IncidentReadService
from explanation.views import (
    AIStatusSchema,
    ExplanationStateSchema,
    IncidentDetailSchema,
    IncidentSummarySchema,
)

router = APIRouter(prefix="/api/v1", tags=["incidents"])

IncidentId = Annotated[str, Path(pattern=r"^SIT-\d{1,12}$", max_length=16)]


def get_incident_reads() -> IncidentReadService:
    return IncidentReadService(get_session_factory())


Reads = Annotated[IncidentReadService, Depends(get_incident_reads)]


@router.get("/incidents", response_model=list[IncidentSummarySchema])
async def list_incidents(
    reads: Reads, limit: Annotated[int, Query(ge=1, le=100)] = 50
) -> list[IncidentSummarySchema]:
    return await reads.list_incidents(limit)


@router.get("/incidents/{incident_id}", response_model=IncidentDetailSchema)
async def get_incident(incident_id: IncidentId, reads: Reads) -> IncidentDetailSchema:
    detail = await reads.incident_detail(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return detail


@router.get("/ai/explain/{incident_id}", response_model=ExplanationStateSchema)
async def get_explanation(incident_id: IncidentId, reads: Reads) -> ExplanationStateSchema:
    state = await reads.explanation_state(incident_id)
    if state is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return state


@router.get("/ai/status", response_model=AIStatusSchema)
async def ai_status() -> AIStatusSchema:
    return AIStatusSchema(
        provider=settings.ai_provider,
        language_model_configured=settings.ai_provider != "null",
    )
