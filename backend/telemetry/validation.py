"""
Telemetry value validation and sanitisation.

Every raw value from a provider passes through this module before it
reaches the database. The goal is a simple guarantee: values stored in
TelemetrySample are either a valid float/int within the expected range,
or None (meaning "not available"). No NaN, no Inf, no negative
percentages, no fabricated zeros.

Nothing in this module modifies the host system (SR-05).
"""

from __future__ import annotations

import logging
import math
from datetime import UTC

from telemetry.protocols import RawTelemetry, TelemetryRates

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scalar sanitisers
# ---------------------------------------------------------------------------

_PERCENT_MIN = 0.0
_PERCENT_MAX = 100.0


def sanitize_percent(value: float | None, name: str) -> float | None:
    """
    Return a valid percentage float in [0.0, 100.0] or None.

    Rejects NaN, Inf, and out-of-range values.
    """
    if value is None:
        return None
    if math.isnan(value) or math.isinf(value):
        logger.warning("Telemetry: %s is %s — discarding", name, value)
        return None
    if value < _PERCENT_MIN or value > _PERCENT_MAX:
        logger.warning("Telemetry: %s=%s outside [0,100] — discarding", name, value)
        return None
    return value


def sanitize_non_negative_float(value: float | None, name: str) -> float | None:
    """
    Return a valid non-negative float or None.

    Rejects NaN, Inf, and negative values.
    """
    if value is None:
        return None
    if math.isnan(value) or math.isinf(value):
        logger.warning("Telemetry: %s is %s — discarding", name, value)
        return None
    if value < 0.0:
        logger.warning("Telemetry: %s=%s is negative — discarding", name, value)
        return None
    return value


def sanitize_non_negative_int(value: int | None, name: str) -> int | None:
    """Return a valid non-negative int or None."""
    if value is None:
        return None
    if value < 0:
        logger.warning("Telemetry: %s=%s is negative — discarding", name, value)
        return None
    return value


# ---------------------------------------------------------------------------
# Rate calculation
# ---------------------------------------------------------------------------


def compute_rate(
    previous: int | None,
    current: int | None,
    elapsed_seconds: float,
    name: str,
) -> float | None:
    """
    Compute bytes/second from two cumulative counter readings.

    Returns None when:
    - either counter is None
    - elapsed_seconds <= 0 (first sample or clock anomaly)
    - delta is negative (counter reset — treat as unavailable, not error)

    Never returns NaN or Inf.
    """
    if previous is None or current is None:
        return None

    if elapsed_seconds <= 0.0:
        # First sample or impossible elapsed time — rate cannot be computed.
        return None

    delta = current - previous

    if delta < 0:
        # Counter wrapped or reset (e.g. interface restart). Discard rather
        # than return a negative or enormous rate.
        logger.debug(
            "Telemetry: %s counter reset (prev=%d, cur=%d) — rate discarded",
            name,
            previous,
            current,
        )
        return None

    rate = delta / elapsed_seconds

    if math.isnan(rate) or math.isinf(rate):
        logger.warning("Telemetry: computed rate for %s is %s — discarding", name, rate)
        return None

    return rate


def compute_rates(
    previous: RawTelemetry | None,
    current: RawTelemetry,
) -> TelemetryRates:
    """
    Derive per-second I/O rates by comparing two consecutive snapshots.

    If `previous` is None (first sample), all rates are None.
    """
    if previous is None:
        return TelemetryRates()

    elapsed = (current.collected_at - previous.collected_at).total_seconds()

    return TelemetryRates(
        disk_read_rate=compute_rate(
            previous.disk_read_bytes_total,
            current.disk_read_bytes_total,
            elapsed,
            "disk_read",
        ),
        disk_write_rate=compute_rate(
            previous.disk_write_bytes_total,
            current.disk_write_bytes_total,
            elapsed,
            "disk_write",
        ),
        net_bytes_sent_rate=compute_rate(
            previous.net_bytes_sent_total,
            current.net_bytes_sent_total,
            elapsed,
            "net_sent",
        ),
        net_bytes_recv_rate=compute_rate(
            previous.net_bytes_recv_total,
            current.net_bytes_recv_total,
            elapsed,
            "net_recv",
        ),
    )


# ---------------------------------------------------------------------------
# Full sample validation
# ---------------------------------------------------------------------------


def validate_raw(raw: RawTelemetry) -> RawTelemetry:
    """
    Sanitise all fields of a RawTelemetry in place.

    Returns the same object with invalid fields replaced by None.
    collected_at is validated to be a timezone-aware UTC datetime.
    """
    # Ensure timestamp is timezone-aware.
    if raw.collected_at.tzinfo is None:
        # Treat naive datetimes as UTC (should not occur — provider must supply UTC).
        logger.warning("Telemetry: collected_at has no timezone — coercing to UTC")
        raw.collected_at = raw.collected_at.replace(tzinfo=UTC)

    raw.cpu_percent = sanitize_percent(raw.cpu_percent, "cpu_percent")
    raw.memory_percent = sanitize_percent(raw.memory_percent, "memory_percent")

    raw.memory_total_bytes = sanitize_non_negative_int(raw.memory_total_bytes, "memory_total_bytes")
    raw.memory_available_bytes = sanitize_non_negative_int(
        raw.memory_available_bytes, "memory_available_bytes"
    )
    raw.memory_used_bytes = sanitize_non_negative_int(raw.memory_used_bytes, "memory_used_bytes")
    raw.uptime_seconds = sanitize_non_negative_float(raw.uptime_seconds, "uptime_seconds")
    raw.process_count = sanitize_non_negative_int(raw.process_count, "process_count")

    # Cumulative counters — just validate non-negative; rates are computed separately.
    raw.disk_read_bytes_total = sanitize_non_negative_int(
        raw.disk_read_bytes_total, "disk_read_bytes_total"
    )
    raw.disk_write_bytes_total = sanitize_non_negative_int(
        raw.disk_write_bytes_total, "disk_write_bytes_total"
    )
    raw.net_bytes_sent_total = sanitize_non_negative_int(
        raw.net_bytes_sent_total, "net_bytes_sent_total"
    )
    raw.net_bytes_recv_total = sanitize_non_negative_int(
        raw.net_bytes_recv_total, "net_bytes_recv_total"
    )

    return raw
