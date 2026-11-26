"""
Demo endpoints: inject synthetic security events and start demo scenarios.

Synthetic only (SR-08): every event is an allowlisted security synthetic type,
marked source="demo", and enters through the detection intake (P-10). When
DEMO_MODE=false every route answers 403 before any input is read. Requests are
rate-limited (TM-02).

POST /api/v1/demo/reset starts a clean demo session (app/demo_reset.py). It takes no
input of any kind, so a client cannot choose a defense state, a threat score or an
incident; the new session's state is established by the runtime's own restore.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.v1.runtime import get_runtime
from app.demo_reset import DemoResetBusy, DemoResetUnavailable, reset_demo_session
from app.runtime import SentinelRuntime
from core.config import settings
from core.demo import MAX_INJECT_COUNT, SCENARIOS, ScenarioBusyError, UnknownScenarioError
from detection.synthetic import SECURITY_SYNTHETIC_TYPES
from models.enums import DefenseState, SyntheticEventType


def require_demo_mode() -> None:
    if not settings.demo_mode:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="demo mode is disabled")


router = APIRouter(
    prefix="/api/v1/demo",
    tags=["demo"],
    dependencies=[Depends(require_demo_mode)],
)

Runtime = Annotated[SentinelRuntime, Depends(get_runtime)]


def rate_limited(runtime: Runtime) -> None:
    if not runtime.demo.limiter.allow():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many demo requests"
        )


class InjectEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: SyntheticEventType
    count: int = Field(default=1, ge=1, le=MAX_INJECT_COUNT)

    @field_validator("event_type")
    @classmethod
    def _security_type(cls, value: SyntheticEventType) -> SyntheticEventType:
        if value not in SECURITY_SYNTHETIC_TYPES:
            allowed = sorted(t.value for t in SECURITY_SYNTHETIC_TYPES)
            raise ValueError(f"event_type must be one of {allowed}")
        return value


class InjectEventResponse(BaseModel):
    injected: int
    event_ids: list[int]


class ScenarioResponse(BaseModel):
    scenario: str
    status: Literal["started"]
    message: str


class ScenarioInfo(BaseModel):
    name: str
    description: str
    synthetic_events: int


@router.get("/scenarios", response_model=list[ScenarioInfo])
async def list_scenarios() -> list[ScenarioInfo]:
    return [
        ScenarioInfo(
            name=s.name,
            description=s.description,
            synthetic_events=sum(st.repeat for st in s.steps),
        )
        for s in SCENARIOS.values()
    ]


@router.post(
    "/inject",
    response_model=InjectEventResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited)],
)
async def inject(body: InjectEventRequest, runtime: Runtime) -> InjectEventResponse:
    detected = await runtime.demo.inject(body.event_type, body.count)
    return InjectEventResponse(injected=body.count, event_ids=[e.id for e in detected])


@router.post(
    "/scenario/{name}",
    response_model=ScenarioResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limited)],
)
async def start_scenario(
    name: Annotated[str, Path(pattern=r"^[a-z][a-z0-9-]{0,31}$")], runtime: Runtime
) -> ScenarioResponse:
    try:
        scenario = runtime.demo.start(name)
    except UnknownScenarioError:
        raise HTTPException(status_code=404, detail="unknown scenario") from None
    except ScenarioBusyError:
        raise HTTPException(status_code=409, detail="a scenario is already running") from None
    return ScenarioResponse(scenario=scenario.name, status="started", message=scenario.description)


class ResetResponse(BaseModel):
    status: Literal["reset"]
    archived_session: str
    defense_state: DefenseState
    message: str


async def no_input(request: Request) -> None:
    """The reset takes no parameters: any query string or body is refused."""
    if request.query_params or await request.body():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="the demo reset takes no parameters",
        )


@router.post(
    "/reset",
    response_model=ResetResponse,
    dependencies=[Depends(no_input), Depends(rate_limited)],
)
async def reset(request: Request) -> ResetResponse:
    """
    DEMO OPERATION. Archive the current demo session and start a clean one.

    The previous session's database is kept intact (renamed, never deleted). The new
    session's defense state is established by the runtime's own restore from an empty
    history; this endpoint sets no state and no score.
    """
    try:
        result = await reset_demo_session(request.app)
    except DemoResetBusy:
        raise HTTPException(status_code=409, detail="a demo reset is already in progress") from None
    except DemoResetUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return ResetResponse(
        status="reset",
        archived_session=result.archived_session,
        defense_state=result.defense_state,
        message="Previous demo session archived intact; a new session started from empty history.",
    )
