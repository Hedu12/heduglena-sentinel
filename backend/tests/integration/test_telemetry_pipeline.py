"""
Integration test: full telemetry pipeline.

FakeTelemetryProvider → TelemetryCollector → TelemetrySample → SQLite

Verifies that the persisted sample in the database contains the values
supplied by the fake provider, end-to-end.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import Settings
from database.engine import create_all_tables, drop_all_tables
from database.repositories import TelemetrySampleRepository
from telemetry.collector import TelemetryCollector
from telemetry.providers.fake import FakeTelemetryProvider


@pytest_asyncio.fixture()
async def engine() -> AsyncEngine:  # type: ignore[misc]
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    await create_all_tables(eng)
    yield eng  # type: ignore[misc]
    await drop_all_tables(eng)
    await eng.dispose()


@pytest_asyncio.fixture()
async def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


def _settings() -> Settings:
    return Settings(database_url="sqlite+aiosqlite:///:memory:", poll_interval_seconds=1.0)  # type: ignore[call-arg]


class TestTelemetryPipeline:
    async def test_full_pipeline_persists_sample(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """
        FakeTelemetryProvider → TelemetryCollector → TelemetrySample → SQLite

        End-to-end: the values in the fake provider appear in the DB row.
        """
        provider = FakeTelemetryProvider(
            cpu_percent=73.5,
            memory_percent=55.0,
            process_count=180,
        )
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        result = await collector.collect_once()

        assert result is not None
        assert result.id is not None

        # Independently read from DB to confirm persistence
        async with factory() as session:
            repo = TelemetrySampleRepository(session)
            latest = await repo.get_latest()

        assert latest is not None
        assert latest.id == result.id
        assert latest.cpu_percent == pytest.approx(73.5)
        assert latest.memory_percent == pytest.approx(55.0)
        assert latest.process_count == 180

    async def test_raw_json_contains_expected_keys(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=50.0)
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        result = await collector.collect_once()
        assert result is not None
        assert result.raw_json is not None
        parsed = json.loads(result.raw_json)
        expected_keys = {
            "cpu_percent",
            "memory_percent",
            "process_count",
            "uptime_seconds",
            "net_bytes_sent_total",
            "net_bytes_recv_total",
        }
        for key in expected_keys:
            assert key in parsed, f"Missing key in raw_json: {key}"

    async def test_two_samples_produce_rate_on_second(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """
        Second sample must have net_bytes_sent populated from counter diff.
        """
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=2.0)

        provider = FakeTelemetryProvider(
            net_bytes_sent_total=0,
            net_bytes_recv_total=0,
            collected_at=t0,
        )
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        s1 = await collector.collect_once()
        assert s1 is not None
        assert s1.net_bytes_sent is None  # first sample — no previous

        # Advance counters and timestamp
        provider._net_bytes_sent_total = 4096  # type: ignore[attr-defined]
        provider._collected_at = t1  # type: ignore[attr-defined]
        s2 = await collector.collect_once()
        assert s2 is not None
        # 4096 bytes over 2 seconds → 2048 bytes/s
        assert s2.net_bytes_sent == pytest.approx(2048.0)

    async def test_multiple_samples_stored_in_db(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        for _ in range(3):
            await collector.collect_once()

        async with factory() as session:
            repo = TelemetrySampleRepository(session)
            samples = await repo.get_since(datetime(2000, 1, 1, tzinfo=UTC), limit=100)
        assert len(samples) == 3

    async def test_provider_failure_nothing_stored(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """When the provider raises, no sample is stored (not a silent zero)."""
        provider = FakeTelemetryProvider(raise_on_collect=RuntimeError("offline"))
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        result = await collector.collect_once()
        assert result is None

        async with factory() as session:
            repo = TelemetrySampleRepository(session)
            latest = await repo.get_latest()
        assert latest is None  # nothing was stored

    async def test_invalid_cpu_does_not_prevent_persistence(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Invalid CPU does not prevent the rest of the sample from persisting."""
        provider = FakeTelemetryProvider(cpu_percent=float("nan"), memory_percent=50.0)
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        result = await collector.collect_once()
        assert result is not None
        assert result.cpu_percent is None
        assert result.memory_percent == pytest.approx(50.0)

        async with factory() as session:
            repo = TelemetrySampleRepository(session)
            latest = await repo.get_latest()
        assert latest is not None
        assert latest.cpu_percent is None

    async def test_collector_close_completes_cleanly(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = TelemetryCollector(
            provider=provider, session_factory=factory, settings=_settings()
        )
        await collector.collect_once()
        await collector.close()  # must not raise
        assert provider.close_called
