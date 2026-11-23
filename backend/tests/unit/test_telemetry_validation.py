"""
Unit tests for telemetry validation and rate calculation.

No database, no psutil, no async — pure function tests.
Tests are deterministic and fast (< 1 second total).
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from telemetry.protocols import RawTelemetry
from telemetry.validation import (
    compute_rate,
    compute_rates,
    sanitize_non_negative_float,
    sanitize_non_negative_int,
    sanitize_percent,
    validate_raw,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _raw(**kwargs: object) -> RawTelemetry:
    """Build a RawTelemetry with sane defaults; override via kwargs."""
    defaults: dict[str, object] = {
        "collected_at": _now(),
        "cpu_percent": 42.0,
        "memory_total_bytes": 8_000_000_000,
        "memory_available_bytes": 4_000_000_000,
        "memory_used_bytes": 4_000_000_000,
        "memory_percent": 50.0,
        "disk_read_bytes_total": 100_000,
        "disk_write_bytes_total": 50_000,
        "net_bytes_sent_total": 200_000,
        "net_bytes_recv_total": 400_000,
        "process_count": 100,
        "uptime_seconds": 3600.0,
    }
    defaults.update(kwargs)
    return RawTelemetry(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# sanitize_percent
# ===========================================================================


class TestSanitizePercent:
    def test_valid_middle(self) -> None:
        assert sanitize_percent(55.0, "cpu") == 55.0

    def test_boundary_zero(self) -> None:
        assert sanitize_percent(0.0, "cpu") == 0.0

    def test_boundary_hundred(self) -> None:
        assert sanitize_percent(100.0, "cpu") == 100.0

    def test_none_passthrough(self) -> None:
        assert sanitize_percent(None, "cpu") is None

    def test_nan_rejected(self) -> None:
        assert sanitize_percent(float("nan"), "cpu") is None

    def test_inf_rejected(self) -> None:
        assert sanitize_percent(float("inf"), "cpu") is None

    def test_negative_inf_rejected(self) -> None:
        assert sanitize_percent(float("-inf"), "cpu") is None

    def test_slightly_negative_rejected(self) -> None:
        assert sanitize_percent(-0.001, "cpu") is None

    def test_above_100_rejected(self) -> None:
        assert sanitize_percent(100.001, "cpu") is None

    def test_exactly_negative_rejected(self) -> None:
        assert sanitize_percent(-1.0, "cpu") is None


# ===========================================================================
# sanitize_non_negative_float
# ===========================================================================


class TestSanitizeNonNegativeFloat:
    def test_valid_positive(self) -> None:
        assert sanitize_non_negative_float(1234.5, "uptime") == 1234.5

    def test_zero_accepted(self) -> None:
        assert sanitize_non_negative_float(0.0, "uptime") == 0.0

    def test_none_passthrough(self) -> None:
        assert sanitize_non_negative_float(None, "uptime") is None

    def test_nan_rejected(self) -> None:
        assert sanitize_non_negative_float(float("nan"), "uptime") is None

    def test_inf_rejected(self) -> None:
        assert sanitize_non_negative_float(float("inf"), "uptime") is None

    def test_negative_rejected(self) -> None:
        assert sanitize_non_negative_float(-1.0, "uptime") is None


# ===========================================================================
# sanitize_non_negative_int
# ===========================================================================


class TestSanitizeNonNegativeInt:
    def test_valid_positive(self) -> None:
        assert sanitize_non_negative_int(42, "proc") == 42

    def test_zero_accepted(self) -> None:
        assert sanitize_non_negative_int(0, "proc") == 0

    def test_none_passthrough(self) -> None:
        assert sanitize_non_negative_int(None, "proc") is None

    def test_negative_rejected(self) -> None:
        assert sanitize_non_negative_int(-1, "proc") is None


# ===========================================================================
# compute_rate
# ===========================================================================


class TestComputeRate:
    def test_normal_case(self) -> None:
        # 1024 bytes over 1 second → 1024 bytes/s
        rate = compute_rate(0, 1024, 1.0, "net_sent")
        assert rate == pytest.approx(1024.0)

    def test_zero_delta(self) -> None:
        # No bytes transferred — rate is 0.0, not None
        rate = compute_rate(1000, 1000, 1.0, "net_sent")
        assert rate == pytest.approx(0.0)

    def test_fractional_elapsed(self) -> None:
        # 512 bytes over 0.5 seconds → 1024 bytes/s
        rate = compute_rate(0, 512, 0.5, "net_sent")
        assert rate == pytest.approx(1024.0)

    def test_first_sample_zero_elapsed(self) -> None:
        # elapsed=0 → cannot compute rate
        rate = compute_rate(0, 1024, 0.0, "net_sent")
        assert rate is None

    def test_negative_elapsed(self) -> None:
        rate = compute_rate(0, 1024, -1.0, "net_sent")
        assert rate is None

    def test_counter_reset(self) -> None:
        # current < previous → counter reset → None, not negative
        rate = compute_rate(5000, 100, 1.0, "net_sent")
        assert rate is None

    def test_previous_none(self) -> None:
        rate = compute_rate(None, 1024, 1.0, "net_sent")
        assert rate is None

    def test_current_none(self) -> None:
        rate = compute_rate(0, None, 1.0, "net_sent")
        assert rate is None

    def test_both_none(self) -> None:
        rate = compute_rate(None, None, 1.0, "net_sent")
        assert rate is None

    def test_very_small_elapsed(self) -> None:
        # Very small but > 0 elapsed — result should be a large but finite number
        rate = compute_rate(0, 1, 1e-9, "net_sent")
        assert rate is not None
        assert math.isfinite(rate)
        assert rate > 0

    def test_large_counter_values(self) -> None:
        # Large realistic counter values (TB of data)
        prev = 10_000_000_000_000
        curr = 10_000_001_000_000  # 1 MB more
        rate = compute_rate(prev, curr, 1.0, "net_sent")
        assert rate == pytest.approx(1_000_000.0)


# ===========================================================================
# compute_rates
# ===========================================================================


class TestComputeRates:
    def test_first_sample_all_none(self) -> None:
        rates = compute_rates(None, _raw())
        assert rates.disk_read_rate is None
        assert rates.disk_write_rate is None
        assert rates.net_bytes_sent_rate is None
        assert rates.net_bytes_recv_rate is None

    def test_normal_second_sample(self) -> None:
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=1.0)
        prev = _raw(
            collected_at=t0,
            disk_read_bytes_total=0,
            disk_write_bytes_total=0,
            net_bytes_sent_total=0,
            net_bytes_recv_total=0,
        )
        curr = _raw(
            collected_at=t1,
            disk_read_bytes_total=4096,
            disk_write_bytes_total=2048,
            net_bytes_sent_total=8192,
            net_bytes_recv_total=16384,
        )
        rates = compute_rates(prev, curr)
        assert rates.disk_read_rate == pytest.approx(4096.0)
        assert rates.disk_write_rate == pytest.approx(2048.0)
        assert rates.net_bytes_sent_rate == pytest.approx(8192.0)
        assert rates.net_bytes_recv_rate == pytest.approx(16384.0)

    def test_counter_reset_produces_none_rate(self) -> None:
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=1.0)
        prev = _raw(collected_at=t0, net_bytes_sent_total=5000)
        curr = _raw(collected_at=t1, net_bytes_sent_total=100)
        rates = compute_rates(prev, curr)
        assert rates.net_bytes_sent_rate is None

    def test_zero_delta_produces_zero_rate(self) -> None:
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=2.0)
        prev = _raw(collected_at=t0, net_bytes_sent_total=1000)
        curr = _raw(collected_at=t1, net_bytes_sent_total=1000)
        rates = compute_rates(prev, curr)
        assert rates.net_bytes_sent_rate == pytest.approx(0.0)

    def test_none_counter_in_current_produces_none_rate(self) -> None:
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = t0 + timedelta(seconds=1.0)
        prev = _raw(collected_at=t0, net_bytes_sent_total=1000)
        curr = _raw(collected_at=t1, net_bytes_sent_total=None)
        rates = compute_rates(prev, curr)
        assert rates.net_bytes_sent_rate is None


# ===========================================================================
# validate_raw — full pipeline
# ===========================================================================


class TestValidateRaw:
    def test_valid_sample_unchanged(self) -> None:
        r = _raw(cpu_percent=42.5, memory_percent=60.0, process_count=80)
        validated = validate_raw(r)
        assert validated.cpu_percent == pytest.approx(42.5)
        assert validated.memory_percent == pytest.approx(60.0)
        assert validated.process_count == 80

    def test_cpu_nan_replaced_with_none(self) -> None:
        r = _raw(cpu_percent=float("nan"))
        validated = validate_raw(r)
        assert validated.cpu_percent is None

    def test_cpu_inf_replaced_with_none(self) -> None:
        r = _raw(cpu_percent=float("inf"))
        validated = validate_raw(r)
        assert validated.cpu_percent is None

    def test_cpu_negative_replaced_with_none(self) -> None:
        r = _raw(cpu_percent=-5.0)
        validated = validate_raw(r)
        assert validated.cpu_percent is None

    def test_cpu_above_100_replaced_with_none(self) -> None:
        r = _raw(cpu_percent=101.0)
        validated = validate_raw(r)
        assert validated.cpu_percent is None

    def test_memory_percent_nan_replaced(self) -> None:
        r = _raw(memory_percent=float("nan"))
        validated = validate_raw(r)
        assert validated.memory_percent is None

    def test_negative_process_count_replaced(self) -> None:
        r = _raw(process_count=-1)
        validated = validate_raw(r)
        assert validated.process_count is None

    def test_negative_uptime_replaced(self) -> None:
        r = _raw(uptime_seconds=-100.0)
        validated = validate_raw(r)
        assert validated.uptime_seconds is None

    def test_negative_disk_counter_replaced(self) -> None:
        r = _raw(disk_read_bytes_total=-1)
        validated = validate_raw(r)
        assert validated.disk_read_bytes_total is None

    def test_naive_timestamp_coerced_to_utc(self) -> None:
        naive_dt = datetime(2025, 1, 1, 12, 0, 0)  # no tzinfo
        r = _raw(collected_at=naive_dt)
        validated = validate_raw(r)
        assert validated.collected_at.tzinfo is not None

    def test_valid_boundaries_cpu(self) -> None:
        for v in (0.0, 100.0):
            r = _raw(cpu_percent=v)
            validated = validate_raw(r)
            assert validated.cpu_percent == pytest.approx(v)

    def test_one_field_invalid_others_preserved(self) -> None:
        """AC-F01-4: partial failure does not wipe valid fields."""
        r = _raw(cpu_percent=float("nan"), memory_percent=65.0)
        validated = validate_raw(r)
        assert validated.cpu_percent is None
        assert validated.memory_percent == pytest.approx(65.0)
