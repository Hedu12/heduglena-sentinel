"""
Runtime session lifecycle, shared by application startup, shutdown and the demo reset.

    start_session: create the engine -> create or verify the schema (database/bootstrap.py)
                   -> build the runtime -> restore its persisted state -> start monitoring
    stop_session:  detach the runtime -> stop it (live clients told to reconnect, every
                   background task cancelled and awaited) -> dispose the engine

The runtime is built by `app.state.runtime_builder`, set by the application lifespan,
so startup and a demo reset build exactly the same production runtime.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.runtime import SentinelRuntime
from core.config import Settings, settings
from database.bootstrap import ensure_schema
from database.engine import close_db_engine, create_db_engine, get_session_factory

RuntimeBuilder = Callable[[Settings, async_sessionmaker[AsyncSession]], SentinelRuntime]


async def start_session(app: FastAPI) -> SentinelRuntime:
    engine = create_db_engine(settings.database_url)
    await ensure_schema(engine)
    builder: RuntimeBuilder = app.state.runtime_builder
    runtime = builder(settings, get_session_factory())
    await runtime.start()
    app.state.runtime = runtime
    return runtime


async def stop_session(app: FastAPI) -> None:
    runtime: SentinelRuntime | None = getattr(app.state, "runtime", None)
    app.state.runtime = None
    try:
        if runtime is not None:
            await runtime.stop()
    finally:
        await close_db_engine()
