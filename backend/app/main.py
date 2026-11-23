"""
Application entry point.

Initializes FastAPI and registers routers. The database engine is created at
startup. See .kiro/specs/sentinel-spec.md section 13 for the API architecture.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.v1.incidents import router as incidents_router
from core.config import settings
from database.engine import create_db_engine, dispose_engine


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    create_db_engine(settings.database_url)
    try:
        yield
    finally:
        dispose_engine()


app = FastAPI(
    title="HEDUGLENA Sentinel",
    version="0.1.0",
    description="AI-native adaptive cyber-defense agent. See /docs for the full API reference.",
    lifespan=lifespan,
)
app.include_router(incidents_router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness check. Returns service name and version."""
    return {"status": "ok", "service": "sentinel", "version": "0.1.0"}
