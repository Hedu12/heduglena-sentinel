"""
PsutilTelemetryProvider — production host telemetry via psutil.

All psutil calls are synchronous and potentially blocking. They are
executed in a thread-pool executor so the asyncio event loop is never
blocked (coding-standards §Async).

Security constraints (SR-05, SR-06):
  - No process command-line arguments are collected.
  - No environment variables are collected.
  - No file contents are collected.
  - Privileged calls degrade gracefully with a warning.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

import psutil

from telemetry.protocols import RawTelemetry, TelemetryProvider

logger = logging.getLogger(__name__)


def _collect_sync() -> RawTelemetry:
    """
    Collect all host metrics synchronously.

    This function runs inside a thread-pool executor, never on the
    event loop. Each metric is collected independently so a single
    failure does not abort the entire snapshot.
    """
    collected_at = datetime.now(UTC)

    # CPU ——————————————————————————————————————————————————————————————————
    cpu_percent: float | None = None
    try:
        # interval=None returns the value since the last call (non-blocking).
        cpu_percent = psutil.cpu_percent(interval=None)
    except Exception:
        logger.warning("Telemetry: failed to read cpu_percent", exc_info=True)

    # Memory ———————————————————————————————————————————————————————————————
    memory_total: int | None = None
    memory_available: int | None = None
    memory_used: int | None = None
    memory_percent: float | None = None
    try:
        vm = psutil.virtual_memory()
        memory_total = vm.total
        memory_available = vm.available
        memory_used = vm.used
        memory_percent = vm.percent
    except Exception:
        logger.warning("Telemetry: failed to read virtual_memory", exc_info=True)

    # Disk I/O ——————————————————————————————————————————————————————————————
    disk_read: int | None = None
    disk_write: int | None = None
    try:
        dc = psutil.disk_io_counters()
        if dc is not None:
            disk_read = dc.read_bytes
            disk_write = dc.write_bytes
    except (AttributeError, NotImplementedError, PermissionError):
        logger.warning("Telemetry: disk_io_counters unavailable", exc_info=True)
    except Exception:
        logger.warning("Telemetry: failed to read disk_io_counters", exc_info=True)

    # Network I/O ————————————————————————————————————————————————————————————
    net_sent: int | None = None
    net_recv: int | None = None
    try:
        nc = psutil.net_io_counters()
        if nc is not None:
            net_sent = nc.bytes_sent
            net_recv = nc.bytes_recv
    except (AttributeError, NotImplementedError, PermissionError):
        logger.warning("Telemetry: net_io_counters unavailable", exc_info=True)
    except Exception:
        logger.warning("Telemetry: failed to read net_io_counters", exc_info=True)

    # Process count — safe headcount only, no cmd args (SR-06) ——————————
    process_count: int | None = None
    try:
        process_count = len(psutil.pids())
    except Exception:
        logger.warning("Telemetry: failed to read pids", exc_info=True)

    # Uptime ————————————————————————————————————————————————————————————————
    uptime_seconds: float | None = None
    try:
        uptime_seconds = time.time() - psutil.boot_time()
    except Exception:
        logger.warning("Telemetry: failed to read boot_time", exc_info=True)

    return RawTelemetry(
        collected_at=collected_at,
        cpu_percent=cpu_percent,
        memory_total_bytes=memory_total,
        memory_available_bytes=memory_available,
        memory_used_bytes=memory_used,
        memory_percent=memory_percent,
        disk_read_bytes_total=disk_read,
        disk_write_bytes_total=disk_write,
        net_bytes_sent_total=net_sent,
        net_bytes_recv_total=net_recv,
        process_count=process_count,
        uptime_seconds=uptime_seconds,
    )


class PsutilTelemetryProvider:
    """
    Production telemetry provider using psutil.

    All blocking psutil calls run in a thread executor to avoid
    stalling the asyncio event loop.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        # Seed the CPU percent baseline so the first real reading is valid.
        # psutil.cpu_percent(interval=None) returns 0.0 on first call;
        # a one-shot call with interval=0.1 primes the internal counter.
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            logger.warning("Telemetry: failed to prime cpu_percent", exc_info=True)

    async def collect(self) -> RawTelemetry:
        """Collect one snapshot off the event loop."""
        loop = asyncio.get_running_loop()
        raw: RawTelemetry = await loop.run_in_executor(None, _collect_sync)
        return raw

    async def close(self) -> None:
        """No persistent resources to release."""


# Verify this class satisfies the TelemetryProvider protocol at import time.
_: TelemetryProvider = PsutilTelemetryProvider.__new__(PsutilTelemetryProvider)
