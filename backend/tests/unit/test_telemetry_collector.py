"""
Unit tests for TelemetryCollector.

Uses FakeTelemetryProvider and an in-memory SQLite session factory so
no real OS calls or network calls are made.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

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
from database.models import TelemetrySample
from telemetry.collector import TelemetryCollector
from telemetry.providers.fake import FakeTelemetryProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
async def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


def _settings(**overrides: object) -> Settings:
    """Build a Settings object with test-friendly defaults."""
    base = {
        "poll_interval_seconds": 1.0,
        "database_url": "sqlite+aiosqlite:///:memory:",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _collector(
    provider: FakeTelemetryProvider,
    session_factory: async_sessionmaker[AsyncSession],
    **setting_overrides: object,
) -> TelemetryCollector:
    return TelemetryCollector(
        provider=provider,
        session_factory=session_factory,
        settings=_settings(**setting_overrides),
    )


# ===========================================================================
# collect_once — happy path
# ===========================================================================


class TestCollectOnceHappyPath:
    async def test_returns_telemetry_sample(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=55.0, memory_percent=70.0)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert isinstance(result, TelemetrySample)

    async def test_cpu_persisted(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        provider = FakeTelemetryProvider(cpu_percent=66.0)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.cpu_percent == pytest.approx(66.0)

    async def test_memory_persisted(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(memory_percent=80.0)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.memory_percent == pytest.approx(80.0)

    async def test_process_count_persisted(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(process_count=150)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.process_count == 150

    async def test_sample_has_assigned_id(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.id is not None
        assert result.id > 0

    async def test_raw_json_stored(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        provider = FakeTelemetryProvider(cpu_percent=42.0)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.raw_json is not None
        import json

        parsed = json.loads(result.raw_json)
        assert "cpu_percent" in parsed

    async def test_provider_called_once(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = _collector(provider, session_factory)
        await collector.collect_once()
        assert provider.collect_call_count == 1

    async def test_multiple_calls_increment_id(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = _collector(provider, session_factory)
        s1 = await collector.collect_once()
        s2 = await collector.collect_once()
        assert s1 is not None and s2 is not None
        assert s2.id > s1.id  # type: ignore[operator]


# ===========================================================================
# collect_once — network rate calculation
# ===========================================================================


class TestCollectOnceRates:
    async def test_first_sample_rates_are_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        # First sample has no previous — rates must be None
        assert result.net_bytes_sent is None
        assert result.net_bytes_recv is None
        assert result.disk_read_rate is None
        assert result.disk_write_rate is None

    async def test_second_sample_has_rates(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """
        Two consecutive samples with known counter values should produce
        non-None rates on the second sample.
        """
        from datetime import timedelta

        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=1.0)

        provider = FakeTelemetryProvider(
            net_bytes_sent_total=0,
            net_bytes_recv_total=0,
            disk_read_bytes_total=0,
            disk_write_bytes_total=0,
            collected_at=t0,
        )
        collector = _collector(provider, session_factory)
        await collector.collect_once()

        # Second call with higher counters and a later timestamp
        provider._net_bytes_sent_total = 8192  # type: ignore[attr-defined]
        provider._net_bytes_recv_total = 16384  # type: ignore[attr-defined]
        provider._disk_read_bytes_total = 4096  # type: ignore[attr-defined]
        provider._collected_at = t1  # type: ignore[attr-defined]
        result2 = await collector.collect_once()

        assert result2 is not None
        assert result2.net_bytes_sent == pytest.approx(8192.0)
        assert result2.net_bytes_recv == pytest.approx(16384.0)
        assert result2.disk_read_rate == pytest.approx(4096.0)

    async def test_counter_reset_produces_none_rate(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        from datetime import timedelta

        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=1.0)

        provider = FakeTelemetryProvider(net_bytes_sent_total=5000, collected_at=t0)
        collector = _collector(provider, session_factory)
        await collector.collect_once()

        # Simulate a counter reset: current < previous
        provider._net_bytes_sent_total = 100  # type: ignore[attr-defined]
        provider._collected_at = t1  # type: ignore[attr-defined]
        result2 = await collector.collect_once()

        assert result2 is not None
        assert result2.net_bytes_sent is None


# ===========================================================================
# collect_once — invalid telemetry
# ===========================================================================


class TestCollectOnceInvalidTelemetry:
    async def test_nan_cpu_stored_as_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=float("nan"))
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.cpu_percent is None

    async def test_inf_memory_stored_as_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(memory_percent=float("inf"))
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.memory_percent is None

    async def test_negative_process_count_stored_as_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(process_count=-5)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.process_count is None

    async def test_cpu_above_100_stored_as_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=200.0)
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.cpu_percent is None

    async def test_one_invalid_field_does_not_discard_sample(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """AC-F01-4: partial failure must not discard the whole sample."""
        provider = FakeTelemetryProvider(
            cpu_percent=float("nan"),
            memory_percent=65.0,
        )
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is not None
        assert result.cpu_percent is None
        assert result.memory_percent == pytest.approx(65.0)


# ===========================================================================
# collect_once — failure handling
# ===========================================================================


class TestCollectOnceFailureHandling:
    async def test_provider_exception_returns_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """P-04: provider failure degrades gracefully — returns None, no crash."""
        provider = FakeTelemetryProvider(raise_on_collect=RuntimeError("sensor fail"))
        collector = _collector(provider, session_factory)
        result = await collector.collect_once()
        assert result is None

    async def test_provider_exception_does_not_raise(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(raise_on_collect=OSError("unavailable"))
        collector = _collector(provider, session_factory)
        # Must not raise — just return None
        try:
            await collector.collect_once()
        except OSError:
            pytest.fail("collect_once() should not propagate provider exceptions")

    async def test_persistence_failure_returns_none(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """DB persistence failure returns None without crashing."""
        provider = FakeTelemetryProvider()

        # Build a session factory that always raises on flush
        failing_session = AsyncMock(spec=AsyncSession)
        failing_session.__aenter__ = AsyncMock(return_value=failing_session)
        failing_session.__aexit__ = AsyncMock(return_value=False)
        failing_session.begin = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=None),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        failing_factory = MagicMock(spec=async_sessionmaker)
        failing_factory.return_value = failing_session
        failing_factory.__call__ = MagicMock(return_value=failing_session)

        # Patch the session context manager to raise
        async def _raise(*args: object, **kwargs: object) -> None:
            raise RuntimeError("DB down")

        failing_session.begin.return_value.__aenter__ = _raise

        collector = TelemetryCollector(
            provider=provider,
            session_factory=failing_factory,
            settings=_settings(),
        )
        result = await collector.collect_once()
        assert result is None

    async def test_cancellation_propagated(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """CancelledError must not be swallowed — it must propagate."""
        provider = FakeTelemetryProvider(raise_on_collect=asyncio.CancelledError())
        collector = _collector(provider, session_factory)
        with pytest.raises(asyncio.CancelledError):
            await collector.collect_once()


# ===========================================================================
# run_until_cancelled
# ===========================================================================


class TestRunUntilCancelled:
    async def test_loop_calls_collect_multiple_times(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        # Use minimum-valid interval; patch sleep to run fast.
        collector = TelemetryCollector(
            provider=provider,
            session_factory=session_factory,
            settings=_settings(poll_interval_seconds=0.25),
        )
        call_target = 3

        sleep_calls = 0

        async def _fast_sleep(seconds: float) -> None:
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= call_target:
                raise asyncio.CancelledError

        with patch("telemetry.collector.asyncio.sleep", side_effect=_fast_sleep):
            with pytest.raises(asyncio.CancelledError):
                await collector.run_until_cancelled()

        assert provider.collect_call_count >= call_target

    async def test_is_running_true_during_loop(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = TelemetryCollector(
            provider=provider,
            session_factory=session_factory,
            settings=_settings(poll_interval_seconds=0.25),
        )
        assert collector.is_running is False

        seen_running: list[bool] = []

        async def _check_then_cancel(seconds: float) -> None:
            seen_running.append(collector.is_running)
            raise asyncio.CancelledError

        with patch("telemetry.collector.asyncio.sleep", side_effect=_check_then_cancel):
            with pytest.raises(asyncio.CancelledError):
                await collector.run_until_cancelled()

        assert True in seen_running
        assert collector.is_running is False

    async def test_provider_exception_does_not_stop_loop(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """P-04: one collection failure must not kill the loop."""
        call_count = 0

        class FailFirstProvider(FakeTelemetryProvider):
            async def collect(self) -> object:  # type: ignore[override]
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise RuntimeError("first call fails")
                return await super().collect()

        provider = FailFirstProvider()
        collector = TelemetryCollector(
            provider=provider,
            session_factory=session_factory,
            settings=_settings(poll_interval_seconds=0.25),
        )

        sleep_calls = 0

        async def _fast_sleep(seconds: float) -> None:
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= 3:
                raise asyncio.CancelledError

        with patch("telemetry.collector.asyncio.sleep", side_effect=_fast_sleep):
            with pytest.raises(asyncio.CancelledError):
                await collector.run_until_cancelled()

        assert call_count >= 2


# ===========================================================================
# close
# ===========================================================================


class TestCollectorClose:
    async def test_close_calls_provider_close(
        self, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider()
        collector = _collector(provider, session_factory)
        assert not provider.close_called
        await collector.close()
        assert provider.close_called
