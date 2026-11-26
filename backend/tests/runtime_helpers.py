"""
Shared fixtures for the Phase 2 runtime tests.

A runtime is built exactly as the application builds it, with three test seams:
fake host telemetry, a deterministic clock whose sleep() advances time, and a
temporary SQLite file whose schema is created by the real database/bootstrap.py.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ai.protocols import LLMProvider
from app.runtime import SentinelRuntime
from core.config import Settings
from database.bootstrap import ensure_schema
from database.models import (
    DefenseStateChange,
    DetectionEvent,
    Incident,
    ResponseAction,
    TelemetrySample,
)
from telemetry.providers.fake import FakeTelemetryProvider

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


class FakeClock:
    """now() for every service; sleep() advances it and yields to the event loop."""

    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)
        await asyncio.sleep(0)


def engine_for(path: Path) -> AsyncEngine:
    return create_async_engine(
        f"sqlite+aiosqlite:///{path.as_posix()}", connect_args={"check_same_thread": False}
    )


@asynccontextmanager
async def fresh_database(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = engine_for(tmp_path / "sentinel.db")
    await ensure_schema(engine)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def quiet_settings(**overrides: Any) -> Settings:
    """Default settings with back-to-back demo steps (time is driven by FakeClock)."""
    values: dict[str, Any] = {"demo_step_interval_seconds": 1.0}
    values.update(overrides)
    return Settings(**values)


def build(
    factory: async_sessionmaker[AsyncSession],
    clock: FakeClock,
    *,
    settings: Settings | None = None,
    llm: LLMProvider | None = None,
    provider: FakeTelemetryProvider | None = None,
) -> SentinelRuntime:
    telemetry = provider or FakeTelemetryProvider(
        cpu_percent=20.0, memory_percent=40.0, process_count=100, net_bytes_sent_total=0
    )
    return SentinelRuntime(
        settings or quiet_settings(), factory, telemetry, llm=llm, clock=clock, sleep=clock.sleep
    )


async def cycles(runtime: SentinelRuntime, clock: FakeClock, n: int, step: float = 2.0) -> None:
    """Run n monitoring cycles `step` seconds apart, with telemetry stamped by the clock."""
    for _ in range(n):
        await clock.sleep(step)
        runtime.collector._provider._collected_at = clock.now  # type: ignore[attr-defined]
        await runtime.run_cycle()


async def play(runtime: SentinelRuntime, name: str) -> None:
    runtime.demo.start(name)
    run = await runtime.demo.wait()
    assert run is not None and run.status == "completed", run


async def rows(factory: async_sessionmaker[AsyncSession], model: type[Any]) -> list[Any]:
    async with factory() as session:
        return list((await session.execute(select(model).order_by(model.id))).scalars())


async def actions(factory: async_sessionmaker[AsyncSession]) -> list[ResponseAction]:
    return await rows(factory, ResponseAction)


async def incidents(factory: async_sessionmaker[AsyncSession]) -> list[Incident]:
    return await rows(factory, Incident)


async def transitions(factory: async_sessionmaker[AsyncSession]) -> list[DefenseStateChange]:
    return await rows(factory, DefenseStateChange)


async def detections(factory: async_sessionmaker[AsyncSession]) -> list[DetectionEvent]:
    return await rows(factory, DetectionEvent)


async def samples(factory: async_sessionmaker[AsyncSession]) -> list[TelemetrySample]:
    return await rows(factory, TelemetrySample)
