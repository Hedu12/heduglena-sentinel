"""
End-to-end detection pipeline tests.

    FakeTelemetryProvider -> TelemetryCollector -> TelemetrySample
        -> DetectionEngine -> DetectionRule -> DetectionEvent -> SQLite

and the deterministic synthetic scenario:

    Normal -> Suspicious activity -> Repeated suspicious activity -> Detection

Timestamps are injected, so the tests never depend on the wall clock.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import Settings
from database.engine import create_all_tables, drop_all_tables
from database.models import DetectionEvent, TelemetrySample
from database.repositories import DetectionEventRepository
from detection.engine import DetectionEngine
from detection.registry import build_default_rules
from models.enums import SyntheticEventType
from telemetry.collector import TelemetryCollector
from telemetry.providers.fake import FakeTelemetryProvider
from tests.detection_helpers import T0, at, syn

AUTH = SyntheticEventType.AUTH_FAILURE
MB = 1_000_000


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    yield async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    await drop_all_tables(eng)
    await eng.dispose()


async def all_events(factory: async_sessionmaker[AsyncSession]) -> list[DetectionEvent]:
    async with factory() as session:
        rows = await DetectionEventRepository(session).get_since(T0.replace(year=2000), limit=1000)
    return sorted(rows, key=lambda e: e.id)


def pipeline(
    factory: async_sessionmaker[AsyncSession], provider: FakeTelemetryProvider, **overrides: object
) -> tuple[TelemetryCollector, DetectionEngine]:
    settings = Settings(**overrides)  # type: ignore[arg-type]
    return (
        TelemetryCollector(provider=provider, session_factory=factory, settings=settings),
        DetectionEngine(build_default_rules(settings), factory),
    )


async def step(
    collector: TelemetryCollector,
    engine: DetectionEngine,
    provider: FakeTelemetryProvider,
    index: int,
) -> list[DetectionEvent]:
    """One monitoring cycle at deterministic time `index`."""
    provider._collected_at = at(index)  # type: ignore[attr-defined]
    sample = await collector.collect_once()
    assert sample is not None
    return await engine.process_sample(sample)


class TestTelemetryToDetectionPipeline:
    async def test_sustained_cpu_produces_one_correlated_event(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=96.2, memory_percent=40.0)
        collector, engine = pipeline(factory, provider, det_cpu_consecutive_samples=3)

        per_cycle = [await step(collector, engine, provider, i) for i in range(5)]

        assert [len(c) for c in per_cycle] == [0, 0, 1, 0, 0]  # fires once, then debounced
        (event,) = await all_events(factory)
        assert event.rule_id == "DET-CPU-001"
        assert event.event_type == "cpu_sustained_high"
        assert event.severity == "MEDIUM"
        assert event.classification == "INFORMATIONAL"
        assert event.status == "open"
        assert event.is_synthetic is False
        assert event.metric_value == pytest.approx(96.2)
        assert event.threshold_value == pytest.approx(90.0)

        # Correlation: the event points at the third telemetry sample, and the
        # evidence lists exactly the three samples that justified it.
        async with factory() as session:
            samples = (
                (await session.execute(select(TelemetrySample).order_by(TelemetrySample.id)))
                .scalars()
                .all()
            )
        assert len(samples) == 5
        assert event.telemetry_sample_id == samples[2].id
        evidence = json.loads(event.event_data or "{}")["evidence"]
        assert evidence["contributing_sample_ids"] == [s.id for s in samples[:3]]
        assert evidence["observed_values"] == [96.2, 96.2, 96.2]

    async def test_normal_telemetry_produces_no_events(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=20.0, memory_percent=40.0, process_count=100)
        collector, engine = pipeline(factory, provider)
        for i in range(30):
            assert await step(collector, engine, provider, i) == []
        assert await all_events(factory) == []

    async def test_sustained_network_uses_rates_not_cumulative_counters(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Cumulative counters are huge (hundreds of GB) but the *rate* is tiny:
        # nothing may fire. Misreading counters as rates would fire immediately.
        provider = FakeTelemetryProvider(cpu_percent=5.0, net_bytes_sent_total=900_000 * MB)
        collector, engine = pipeline(factory, provider, det_net_consecutive_samples=2)
        for i in range(6):
            provider._net_bytes_sent_total = 900_000 * MB + i * 1000  # type: ignore[attr-defined]
            assert await step(collector, engine, provider, i) == []

    async def test_high_network_rate_detected_end_to_end(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=5.0, net_bytes_sent_total=0)
        collector, engine = pipeline(factory, provider, det_net_consecutive_samples=3)
        detections: list[int] = []
        for i in range(6):
            # +120 MB every 2 s = 60 MB/s outbound, above the 50 MB/s default.
            provider._net_bytes_sent_total = i * 120 * MB  # type: ignore[attr-defined]
            if await step(collector, engine, provider, i):
                detections.append(i)
        # Sample 0 has no rate; rates exist from sample 1, so 3 in a row = sample 3.
        assert detections == [3]
        (event,) = await all_events(factory)
        assert event.event_type == "network_throughput_high"
        assert event.metric_value == pytest.approx(60 * MB)
        assert json.loads(event.event_data or "{}")["evidence"]["direction"] == "outbound"

    async def test_counter_reset_breaks_the_network_run(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=5.0, net_bytes_sent_total=0)
        collector, engine = pipeline(factory, provider, det_net_consecutive_samples=3)
        totals = [0, 120, 240, 5, 125, 245, 365]  # reset at index 3 (counter dropped)
        detections = []
        for i, total in enumerate(totals):
            provider._net_bytes_sent_total = total * MB  # type: ignore[attr-defined]
            if await step(collector, engine, provider, i):
                detections.append(i)
        # Rates: None,60,60,None(reset),60,60,60 -> 3 consecutive only at index 6.
        assert detections == [6]

    async def test_process_surge_detected_end_to_end(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=5.0, process_count=100)
        collector, engine = pipeline(factory, provider)
        for i in range(12):
            await step(collector, engine, provider, i)
        provider._process_count = 400  # type: ignore[attr-defined]
        detections = [i for i in range(12, 16) if await step(collector, engine, provider, i)]
        assert detections == [13]  # 2 consecutive samples required
        (event,) = await all_events(factory)
        assert event.rule_id == "DET-PROC-001"

    async def test_telemetry_failure_produces_no_detection(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(raise_on_collect=RuntimeError("offline"))
        collector, engine = pipeline(factory, provider)
        assert await collector.collect_once() is None  # nothing reaches the engine
        assert await all_events(factory) == []


class TestSyntheticScenario:
    """Normal -> suspicious -> repeated suspicious -> detection, all deterministic."""

    async def test_escalating_authentication_failure_scenario(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=15.0, memory_percent=35.0, process_count=90)
        collector, engine = pipeline(factory, provider)

        # 1. Normal: healthy telemetry, no detections.
        for i in range(5):
            assert await step(collector, engine, provider, i) == []

        # 2. Suspicious: failures accumulate below the threshold -> still nothing.
        for s in range(4):
            assert await engine.process_synthetic(syn(AUTH, seconds=20 + s, subject="admin")) == []
        assert await all_events(factory) == []

        # 3. The 5th failure inside the window is a SUSPICIOUS detection.
        (suspicious,) = await engine.process_synthetic(syn(AUTH, seconds=24, subject="admin"))
        assert suspicious.classification == "SUSPICIOUS"
        assert suspicious.severity == "HIGH"
        assert suspicious.event_type == "auth_failure_burst"
        assert suspicious.is_synthetic is True

        # Telemetry keeps flowing through the same engine and stays quiet.
        assert await step(collector, engine, provider, 12) == []

        # 4. Repeated suspicious activity: failures 6-9 are debounced...
        for s in range(25, 29):
            assert await engine.process_synthetic(syn(AUTH, seconds=s, subject="admin")) == []
        # ...and the 10th escalates to a HIGH_CONFIDENCE detection.
        (escalated,) = await engine.process_synthetic(syn(AUTH, seconds=29, subject="admin"))
        assert escalated.classification == "HIGH_CONFIDENCE"
        assert escalated.severity == "CRITICAL"
        assert escalated.confidence > suspicious.confidence

        events = await all_events(factory)
        assert [e.id for e in events] == [suspicious.id, escalated.id]
        assert [e.classification for e in events] == ["SUSPICIOUS", "HIGH_CONFIDENCE"]
        escalated_evidence = json.loads(events[1].event_data or "{}")["evidence"]
        assert escalated_evidence["observed_count"] == 10
        assert escalated_evidence["escalated"] is True
        assert escalated_evidence["latest_subject"] == "admin"

    async def test_telemetry_and_synthetic_events_share_one_pipeline(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=97.0)
        collector, engine = pipeline(factory, provider, det_cpu_consecutive_samples=2)
        await step(collector, engine, provider, 0)
        cpu_events = await step(collector, engine, provider, 1)
        process_events = await engine.process_synthetic(
            syn(SyntheticEventType.SUSPICIOUS_PROCESS, seconds=5, subject="simulated-malware")
        )
        assert len(cpu_events) == 1 and len(process_events) == 1

        stored = await all_events(factory)
        assert {(e.rule_id, e.is_synthetic) for e in stored} == {
            ("DET-CPU-001", False),
            ("DET-SYN-001", True),
        }
        by_rule = {e.rule_id: e for e in stored}
        assert by_rule["DET-CPU-001"].telemetry_sample_id is not None
        assert by_rule["DET-SYN-001"].telemetry_sample_id is None
        assert by_rule["DET-SYN-001"].classification == "HIGH_CONFIDENCE"

    async def test_each_event_carries_complete_structured_fields(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeTelemetryProvider(cpu_percent=97.0)
        collector, engine = pipeline(factory, provider, det_cpu_consecutive_samples=1)
        await step(collector, engine, provider, 0)
        await engine.process_synthetic(syn(SyntheticEventType.SUSPICIOUS_PROCESS, seconds=1))
        for event in await all_events(factory):
            assert event.id is not None
            assert event.rule_id and event.event_type
            assert event.severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert event.detected_at is not None
            assert 0.0 <= (event.confidence or -1) <= 1.0
            assert event.status == "open"
            envelope = json.loads(event.event_data or "")
            assert envelope["evidence"], "evidence must not be empty"
            assert envelope["schema_version"] == 1
