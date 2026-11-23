"""
Telemetry domain types and the TelemetryProvider protocol.

The domain never imports psutil directly. All OS-level telemetry
is hidden behind TelemetryProvider so that tests can inject a
deterministic FakeTelemetryProvider (architecture principle P-03).

RawTelemetry is an intermediate value object produced by a provider.
TelemetryCollector transforms it into TelemetrySample for persistence.

Security: RawTelemetry intentionally omits process command-line
arguments, environment variables, and authentication data (SR-06).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass
class NetworkCounters:
    """
    Cumulative network byte counters at one point in time.

    These are monotonically increasing totals, NOT per-second rates.
    The collector derives rates by comparing two consecutive snapshots.
    """

    bytes_sent: int
    bytes_recv: int
    collected_at: datetime


@dataclass
class RawTelemetry:
    """
    Unvalidated, unprocessed telemetry snapshot from a provider.

    Fields that could not be read are None. The validation layer
    decides whether to propagate None or reject the sample.

    Fields NOT present (by design — SR-06, SR-05):
      - process command-line arguments
      - environment variables
      - file contents
      - user credentials or tokens
    """

    collected_at: datetime

    # CPU
    cpu_percent: float | None = None

    # Memory
    memory_total_bytes: int | None = None
    memory_available_bytes: int | None = None
    memory_used_bytes: int | None = None
    memory_percent: float | None = None

    # Disk I/O — cumulative byte counters (must be diffed, not used as rates)
    disk_read_bytes_total: int | None = None
    disk_write_bytes_total: int | None = None

    # Network I/O — cumulative byte counters (must be diffed, not used as rates)
    net_bytes_sent_total: int | None = None
    net_bytes_recv_total: int | None = None

    # Process count — safe headcount only
    process_count: int | None = None

    # System uptime in seconds
    uptime_seconds: float | None = None

    # Arbitrary extra fields for forward-compat; never persisted directly
    extra: dict[str, object] = field(default_factory=dict)


@dataclass
class TelemetryRates:
    """
    Derived per-second rate metrics computed from two consecutive RawTelemetry
    snapshots.

    All rate fields are None when a rate cannot be computed (e.g. first sample,
    counter reset, zero elapsed time).
    """

    disk_read_rate: float | None = None  # bytes/s
    disk_write_rate: float | None = None  # bytes/s
    net_bytes_sent_rate: float | None = None  # bytes/s
    net_bytes_recv_rate: float | None = None  # bytes/s


@runtime_checkable
class TelemetryProvider(Protocol):
    """
    Protocol that all telemetry source adapters must satisfy.

    Implementations: PsutilTelemetryProvider, FakeTelemetryProvider.
    The domain imports only this protocol — never concrete adapters.
    """

    async def collect(self) -> RawTelemetry:
        """
        Collect one telemetry snapshot.

        Must not raise on partial failure — return None for
        individual fields that could not be read.
        Must not perform blocking I/O on the event loop — use
        asyncio.run_in_executor for synchronous psutil calls.
        """
        ...

    async def close(self) -> None:
        """Release any held resources. Called on clean shutdown."""
        ...
