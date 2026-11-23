"""
Unit tests for telemetry providers.

FakeTelemetryProvider tests are synchronous-friendly and deterministic.
PsutilTelemetryProvider smoke test verifies it returns a valid snapshot
from the actual host — excluded from CI if psutil is unavailable.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from telemetry.protocols import RawTelemetry
from telemetry.providers.fake import FakeTelemetryProvider
from telemetry.providers.psutil_provider import PsutilTelemetryProvider

# ===========================================================================
# FakeTelemetryProvider
# ===========================================================================


class TestFakeTelemetryProvider:
    async def test_collect_returns_raw_telemetry(self) -> None:
        provider = FakeTelemetryProvider()
        raw = await provider.collect()
        assert isinstance(raw, RawTelemetry)

    async def test_collect_returns_configured_cpu(self) -> None:
        provider = FakeTelemetryProvider(cpu_percent=77.5)
        raw = await provider.collect()
        assert raw.cpu_percent == pytest.approx(77.5)

    async def test_collect_returns_configured_memory(self) -> None:
        provider = FakeTelemetryProvider(memory_percent=85.0)
        raw = await provider.collect()
        assert raw.memory_percent == pytest.approx(85.0)

    async def test_collect_returns_configured_process_count(self) -> None:
        provider = FakeTelemetryProvider(process_count=200)
        raw = await provider.collect()
        assert raw.process_count == 200

    async def test_collect_returns_configured_uptime(self) -> None:
        provider = FakeTelemetryProvider(uptime_seconds=7200.0)
        raw = await provider.collect()
        assert raw.uptime_seconds == pytest.approx(7200.0)

    async def test_collect_uses_utc_timestamp(self) -> None:
        provider = FakeTelemetryProvider()
        raw = await provider.collect()
        assert raw.collected_at.tzinfo is not None

    async def test_collect_uses_fixed_timestamp_when_provided(self) -> None:
        fixed = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        provider = FakeTelemetryProvider(collected_at=fixed)
        raw = await provider.collect()
        assert raw.collected_at == fixed

    async def test_collect_increments_call_count(self) -> None:
        provider = FakeTelemetryProvider()
        assert provider.collect_call_count == 0
        await provider.collect()
        await provider.collect()
        assert provider.collect_call_count == 2

    async def test_close_sets_flag(self) -> None:
        provider = FakeTelemetryProvider()
        assert not provider.close_called
        await provider.close()
        assert provider.close_called

    async def test_raise_on_collect(self) -> None:
        provider = FakeTelemetryProvider(raise_on_collect=ValueError("boom"))
        with pytest.raises(ValueError, match="boom"):
            await provider.collect()

    async def test_null_metrics_propagated(self) -> None:
        provider = FakeTelemetryProvider(cpu_percent=None, memory_percent=None)
        raw = await provider.collect()
        assert raw.cpu_percent is None
        assert raw.memory_percent is None

    async def test_cpu_boundary_zero(self) -> None:
        raw = await FakeTelemetryProvider(cpu_percent=0.0).collect()
        assert raw.cpu_percent == pytest.approx(0.0)

    async def test_cpu_boundary_hundred(self) -> None:
        raw = await FakeTelemetryProvider(cpu_percent=100.0).collect()
        assert raw.cpu_percent == pytest.approx(100.0)

    async def test_memory_boundary_zero(self) -> None:
        raw = await FakeTelemetryProvider(memory_percent=0.0).collect()
        assert raw.memory_percent == pytest.approx(0.0)

    async def test_memory_boundary_hundred(self) -> None:
        raw = await FakeTelemetryProvider(memory_percent=100.0).collect()
        assert raw.memory_percent == pytest.approx(100.0)

    async def test_net_counters_returned_as_totals(self) -> None:
        """Net counters must be cumulative totals, not rates."""
        provider = FakeTelemetryProvider(
            net_bytes_sent_total=1_000_000,
            net_bytes_recv_total=2_000_000,
        )
        raw = await provider.collect()
        # They should come back as the raw totals, not divided by time.
        assert raw.net_bytes_sent_total == 1_000_000
        assert raw.net_bytes_recv_total == 2_000_000

    async def test_satisfies_protocol(self) -> None:
        """Runtime-check that FakeTelemetryProvider satisfies the Protocol."""
        from telemetry.protocols import TelemetryProvider

        provider = FakeTelemetryProvider()
        assert isinstance(provider, TelemetryProvider)


# ===========================================================================
# PsutilTelemetryProvider — smoke test on real host
# ===========================================================================


class TestPsutilTelemetryProvider:
    async def test_collect_returns_raw_telemetry(self) -> None:
        """Basic smoke test: psutil returns a RawTelemetry without crashing."""
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        assert isinstance(raw, RawTelemetry)

    async def test_collected_at_is_utc_aware(self) -> None:
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        assert raw.collected_at.tzinfo is not None

    async def test_cpu_percent_valid_or_none(self) -> None:
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        if raw.cpu_percent is not None:
            assert 0.0 <= raw.cpu_percent <= 100.0
            assert math.isfinite(raw.cpu_percent)

    async def test_memory_percent_valid_or_none(self) -> None:
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        if raw.memory_percent is not None:
            assert 0.0 <= raw.memory_percent <= 100.0
            assert math.isfinite(raw.memory_percent)

    async def test_process_count_non_negative_or_none(self) -> None:
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        if raw.process_count is not None:
            assert raw.process_count >= 0

    async def test_net_counters_non_negative_or_none(self) -> None:
        provider = PsutilTelemetryProvider()
        raw = await provider.collect()
        if raw.net_bytes_sent_total is not None:
            assert raw.net_bytes_sent_total >= 0
        if raw.net_bytes_recv_total is not None:
            assert raw.net_bytes_recv_total >= 0

    async def test_close_does_not_raise(self) -> None:
        provider = PsutilTelemetryProvider()
        await provider.close()  # should be a no-op

    async def test_satisfies_protocol(self) -> None:
        from telemetry.protocols import TelemetryProvider

        provider = PsutilTelemetryProvider()
        assert isinstance(provider, TelemetryProvider)
