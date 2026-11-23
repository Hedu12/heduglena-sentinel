"""
TelemetryCollector — the collection service.

Responsibilities:
  1. Request a RawTelemetry snapshot from the provider.
  2. Validate / sanitise the snapshot.
  3. Compute derived rate metrics from the previous snapshot.
  4. Build a TelemetrySample domain object.
  5. Persist the sample via the repository.
  6. Return the persisted sample to the caller.

The collector is intentionally stateless between calls except for the
previous snapshot used for rate computation. This makes it easy to test
each step independently.

Lifecycle:
  - `collect_once()` — perform one collection cycle; can be called
    directly in tests or by a background runner.
  - `run_until_cancelled()` — async loop that calls collect_once() at
    the configured interval; cancels cleanly on asyncio.CancelledError.
  - `close()` — release provider resources.
"""

from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import Settings
from database.models import TelemetrySample
from database.repositories import TelemetrySampleRepository
from telemetry.protocols import RawTelemetry, TelemetryProvider
from telemetry.protocols import TelemetryRates as TelemetryRatesType
from telemetry.validation import compute_rates, validate_raw

logger = logging.getLogger(__name__)


class TelemetryCollector:
    """
    Collects, validates, and persists one telemetry sample per cycle.

    Args:
        provider:        Source of raw host metrics (psutil or fake).
        session_factory: Factory that produces AsyncSession instances.
        settings:        Application configuration (poll interval etc.).
    """

    def __init__(
        self,
        provider: TelemetryProvider,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._provider = provider
        self._session_factory = session_factory
        self._settings = settings
        self._previous: RawTelemetry | None = None
        self._running: bool = False

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    async def collect_once(self) -> TelemetrySample | None:
        """
        Run one full collection cycle.

        Returns the persisted TelemetrySample on success.
        Returns None when collection fails but the system should continue.
        Raises TelemetryError only on unrecoverable misconfiguration.
        """
        # 1. Collect raw telemetry from provider.
        try:
            raw = await self._provider.collect()
        except asyncio.CancelledError:
            raise  # propagate cancellation — do not swallow it
        except Exception:
            logger.warning(
                "Telemetry: provider.collect() failed — skipping sample",
                exc_info=True,
            )
            return None

        # 2. Validate / sanitise.
        raw = validate_raw(raw)

        # 3. Compute rates from previous snapshot.
        rates = compute_rates(self._previous, raw)

        # 4. Build TelemetrySample.
        sample = self._build_sample(raw, rates)

        # 5. Persist.
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    repo = TelemetrySampleRepository(session)
                    persisted = await repo.insert(sample)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error(
                "Telemetry: failed to persist sample — collection continues",
                exc_info=True,
            )
            return None

        # 6. Advance the previous-snapshot pointer only after a successful
        #    persist so a failed persist does not corrupt the rate state.
        self._previous = raw

        logger.debug(
            "Telemetry: sample persisted id=%d cpu=%.1f%% mem=%.1f%%",
            persisted.id,
            persisted.cpu_percent or 0.0,
            persisted.memory_percent or 0.0,
        )
        return persisted

    async def run_until_cancelled(self) -> None:
        """
        Collect telemetry in a loop at the configured polling interval.

        Exits cleanly when cancelled via asyncio.CancelledError.
        One collection failure does not stop the loop.
        """
        self._running = True
        logger.info(
            "Telemetry: collection loop started (interval=%.2fs)",
            self._settings.poll_interval_seconds,
        )
        try:
            while True:
                await self.collect_once()
                await asyncio.sleep(self._settings.poll_interval_seconds)
        except asyncio.CancelledError:
            logger.info("Telemetry: collection loop cancelled — shutting down")
            raise
        finally:
            self._running = False

    async def close(self) -> None:
        """Release provider resources."""
        await self._provider.close()
        logger.info("Telemetry: provider closed")

    @property
    def is_running(self) -> bool:
        return self._running

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_sample(raw: RawTelemetry, rates: TelemetryRatesType) -> TelemetrySample:
        """Translate validated raw + rates into the ORM TelemetrySample."""
        raw_dict = {
            "cpu_percent": raw.cpu_percent,
            "memory_total_bytes": raw.memory_total_bytes,
            "memory_available_bytes": raw.memory_available_bytes,
            "memory_used_bytes": raw.memory_used_bytes,
            "memory_percent": raw.memory_percent,
            "disk_read_bytes_total": raw.disk_read_bytes_total,
            "disk_write_bytes_total": raw.disk_write_bytes_total,
            "net_bytes_sent_total": raw.net_bytes_sent_total,
            "net_bytes_recv_total": raw.net_bytes_recv_total,
            "process_count": raw.process_count,
            "uptime_seconds": raw.uptime_seconds,
        }

        return TelemetrySample(
            collected_at=raw.collected_at,
            cpu_percent=raw.cpu_percent,
            memory_percent=raw.memory_percent,
            disk_read_rate=rates.disk_read_rate,
            disk_write_rate=rates.disk_write_rate,
            net_bytes_sent=rates.net_bytes_sent_rate,
            net_bytes_recv=rates.net_bytes_recv_rate,
            process_count=raw.process_count,
            raw_json=json.dumps(raw_dict),
        )
