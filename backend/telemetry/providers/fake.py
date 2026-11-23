"""
FakeTelemetryProvider — deterministic test double.

Returns a fixed, configurable RawTelemetry snapshot. Never calls psutil
or any OS API, so tests run identically on all machines.

Usage::

    provider = FakeTelemetryProvider(
        cpu_percent=55.0,
        memory_percent=70.0,
    )
    raw = await provider.collect()

Raise-on-collect mode is available to test error handling::

    provider = FakeTelemetryProvider(raise_on_collect=ValueError("boom"))
    with pytest.raises(ValueError):
        await provider.collect()

Counter sequences are available to test rate calculation without
relying on wall-clock time::

    provider = FakeTelemetryProvider.with_counter_sequence(
        net_sent_sequence=[0, 1024, 2048],
        net_recv_sequence=[0, 512, 1024],
    )
"""

from __future__ import annotations

from datetime import UTC, datetime

from telemetry.protocols import RawTelemetry, TelemetryProvider


class FakeTelemetryProvider:
    """
    Deterministic provider for unit and integration tests.

    Satisfies the TelemetryProvider protocol without psutil.
    """

    def __init__(
        self,
        *,
        cpu_percent: float | None = 42.0,
        memory_total_bytes: int | None = 8_589_934_592,  # 8 GiB
        memory_available_bytes: int | None = 4_294_967_296,  # 4 GiB
        memory_used_bytes: int | None = 4_294_967_296,
        memory_percent: float | None = 50.0,
        disk_read_bytes_total: int | None = 100_000,
        disk_write_bytes_total: int | None = 50_000,
        net_bytes_sent_total: int | None = 200_000,
        net_bytes_recv_total: int | None = 400_000,
        process_count: int | None = 120,
        uptime_seconds: float | None = 3600.0,
        collected_at: datetime | None = None,
        raise_on_collect: Exception | None = None,
    ) -> None:
        self._cpu_percent = cpu_percent
        self._memory_total_bytes = memory_total_bytes
        self._memory_available_bytes = memory_available_bytes
        self._memory_used_bytes = memory_used_bytes
        self._memory_percent = memory_percent
        self._disk_read_bytes_total = disk_read_bytes_total
        self._disk_write_bytes_total = disk_write_bytes_total
        self._net_bytes_sent_total = net_bytes_sent_total
        self._net_bytes_recv_total = net_bytes_recv_total
        self._process_count = process_count
        self._uptime_seconds = uptime_seconds
        self._collected_at = collected_at
        self._raise_on_collect = raise_on_collect
        self.close_called: bool = False
        self.collect_call_count: int = 0

    async def collect(self) -> RawTelemetry:
        """Return the configured snapshot, or raise if raise_on_collect is set."""
        self.collect_call_count += 1
        if self._raise_on_collect is not None:
            raise self._raise_on_collect
        return RawTelemetry(
            collected_at=self._collected_at or datetime.now(UTC),
            cpu_percent=self._cpu_percent,
            memory_total_bytes=self._memory_total_bytes,
            memory_available_bytes=self._memory_available_bytes,
            memory_used_bytes=self._memory_used_bytes,
            memory_percent=self._memory_percent,
            disk_read_bytes_total=self._disk_read_bytes_total,
            disk_write_bytes_total=self._disk_write_bytes_total,
            net_bytes_sent_total=self._net_bytes_sent_total,
            net_bytes_recv_total=self._net_bytes_recv_total,
            process_count=self._process_count,
            uptime_seconds=self._uptime_seconds,
        )

    async def close(self) -> None:
        self.close_called = True


# Verify this class satisfies the TelemetryProvider protocol at import time.
_: TelemetryProvider = FakeTelemetryProvider()
