"""
Application entry point.

Startup (lifespan): validated settings are loaded at import (core.config); the
database engine is created; an empty database gets its schema from the Alembic
migrations, any other mismatch refuses to start (database/bootstrap.py); then the
runtime restores the persisted defense state and starts the monitoring loop and
the explanation worker (app/runtime.py). The steps live in app/lifecycle.py and are
shared with the demo reset (app/demo_reset.py).

Shutdown: the runtime cancels and awaits every background task and releases the
telemetry provider; then the engine is disposed and awaited. See
.kiro/specs/sentinel-spec.md section 13 for the API architecture.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.v1.demo import router as demo_router
from api.v1.incidents import router as incidents_router
from api.v1.live import router as live_router
from api.v1.runtime import router as runtime_router
from app.lifecycle import start_session, stop_session
from app.runtime import SentinelRuntime
from core.config import Settings, settings
from telemetry.providers.psutil_provider import PsutilTelemetryProvider

VERSION = "0.1.0"


def build_runtime(
    config: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> SentinelRuntime:
    """The production runtime: real host telemetry and the configured AI provider."""
    return SentinelRuntime(config, session_factory, PsutilTelemetryProvider())


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Looked up at startup, so startup and a demo reset build the same runtime.
    app.state.runtime_builder = build_runtime
    try:
        await start_session(app)
        yield
    finally:
        await stop_session(app)


app = FastAPI(
    title="HEDUGLENA Sentinel",
    version=VERSION,
    description="AI-native adaptive cyber-defense agent. See /docs for the full API reference.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(incidents_router)
app.include_router(runtime_router)
app.include_router(demo_router)
app.include_router(live_router)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str


@app.get("/health", tags=["meta"], response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness check. "degraded" when the monitoring runtime is not running or failing."""
    runtime: SentinelRuntime | None = getattr(request.app.state, "runtime", None)
    healthy = runtime is not None and runtime.status_view().healthy
    return HealthResponse(
        status="ok" if healthy else "degraded", service="sentinel", version=VERSION
    )
