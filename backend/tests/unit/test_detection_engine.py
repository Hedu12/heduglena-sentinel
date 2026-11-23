"""
Unit tests for DetectionEngine: isolation, persistence, determinism, management.

Uses an in-memory SQLite database; no wall clock, no network, no psutil.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import Settings
from core.exceptions import RuleNotFoundError
from database.engine import create_all_tables, drop_all_tables
from database.models import DetectionEvent, TelemetrySample
from database.repositories import DetectionEventRepository, TelemetrySampleRepository
from detection.describe import describe
from detection.engine import DetectionEngine, result_to_event
from detection.registry import build_default_rules
from detection.rules.base import DetectionRule
from detection.rules.resource import CpuAnomalyRule
from detection.synthetic import SyntheticEvent
from detection.types import DetectionResult, TelemetryObservation
from models.enums import Classification, Severity, SyntheticEventType
from tests.detection_helpers import T0, at, syn


@pytest_asyncio.fixture()
async def db() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    yield async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    await drop_all_tables(eng)
    await eng.dispose()


async def add_sample(
    factory: async_sessionmaker[AsyncSession], index: int, **metrics: Any
) -> TelemetrySample:
    async with factory() as session, session.begin():
        return await TelemetrySampleRepository(session).insert(
            TelemetrySample(collected_at=at(index), **metrics)
        )


async def stored(factory: async_sessionmaker[AsyncSession]) -> list[DetectionEvent]:
    async with factory() as session:
        rows = await DetectionEventRepository(session).get_since(T0.replace(year=2000), limit=1000)
    return sorted(rows, key=lambda e: e.id)


def cpu_rule(**kw: Any) -> CpuAnomalyRule:
    return CpuAnomalyRule(
        threshold_percent=90.0,
        consecutive_samples=kw.pop("consecutive_samples", 1),
        cooldown_seconds=kw.pop("cooldown_seconds", 0.0),
    )


class ExplodingRule(DetectionRule):
    """A buggy rule: raises on every input."""

    rule_id = "DET-BOOM-001"
    name = "Exploding"
    description = "always raises"
    severity = Severity.LOW

    def evaluate_telemetry(self, observation: TelemetryObservation) -> list[DetectionResult]:
        return [1 / 0]  # type: ignore[list-item]

    def evaluate_synthetic(self, event: SyntheticEvent) -> list[DetectionResult]:
        raise RuntimeError("synthetic boom")

    def _reset_state(self) -> None:
        pass


class _FailingFactory:
    """A session factory whose sessions cannot be opened."""

    def __call__(self) -> _FailingFactory:
        return self

    async def __aenter__(self) -> AsyncSession:
        raise RuntimeError("database is down")

    async def __aexit__(self, *exc: object) -> bool:
        return False


class TestRuleIsolation:
    async def test_failing_rule_does_not_stop_other_rules(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([ExplodingRule(cooldown_seconds=0), cpu_rule()], db)
        sample = await add_sample(db, 0, cpu_percent=95.0)
        events = await engine.process_sample(sample)
        assert [e.rule_id for e in events] == ["DET-CPU-001"]

    async def test_failing_rule_listed_after_good_rule_still_runs_good_rule(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([cpu_rule(), ExplodingRule(cooldown_seconds=0)], db)
        events = await engine.process_sample(await add_sample(db, 0, cpu_percent=95.0))
        assert len(events) == 1

    async def test_failure_is_logged_with_traceback_not_swallowed(
        self, db: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
    ) -> None:
        engine = DetectionEngine([ExplodingRule(cooldown_seconds=0)], db)
        with caplog.at_level(logging.ERROR, logger="detection.engine"):
            await engine.process_sample(await add_sample(db, 0, cpu_percent=1.0))
        record = next(r for r in caplog.records if "DET-BOOM-001" in r.getMessage())
        assert record.levelno == logging.ERROR
        assert record.exc_info is not None
        assert record.exc_info[0] is ZeroDivisionError

    async def test_failures_are_counted_per_rule(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([ExplodingRule(cooldown_seconds=0), cpu_rule()], db)
        for i in range(3):
            await engine.process_sample(await add_sample(db, i, cpu_percent=1.0))
        assert engine.rule_error_counts == {"DET-BOOM-001": 3}

    async def test_failing_rule_keeps_failing_without_breaking_engine(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([ExplodingRule(cooldown_seconds=0), cpu_rule()], db)
        await engine.process_sample(await add_sample(db, 0, cpu_percent=1.0))
        events = await engine.process_sample(await add_sample(db, 1, cpu_percent=95.0))
        assert len(events) == 1

    async def test_synthetic_path_is_isolated_too(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        settings = Settings(rule_auth_failure_count=1)
        rules = [ExplodingRule(cooldown_seconds=0), *build_default_rules(settings)]
        engine = DetectionEngine(rules, db)
        events = await engine.process_synthetic(syn(SyntheticEventType.AUTH_FAILURE))
        assert [e.rule_id for e in events] == ["DET-SYN-001"]
        assert engine.rule_error_counts == {"DET-BOOM-001": 1}


class TestRuleManagement:
    async def test_disabled_rule_does_not_run(self, db: async_sessionmaker[AsyncSession]) -> None:
        engine = DetectionEngine([cpu_rule()], db)
        engine.set_rule_enabled("DET-CPU-001", False)
        events = await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))
        assert events == []

    async def test_rule_can_be_reenabled_at_runtime(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([cpu_rule()], db)
        engine.set_rule_enabled("DET-CPU-001", False)
        await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))
        engine.set_rule_enabled("DET-CPU-001", True)
        events = await engine.process_sample(await add_sample(db, 1, cpu_percent=99.0))
        assert len(events) == 1

    def test_unknown_rule_raises(self, db: async_sessionmaker[AsyncSession]) -> None:
        engine = DetectionEngine([cpu_rule()], db)
        with pytest.raises(RuleNotFoundError):
            engine.set_rule_enabled("DET-NOPE-999", True)

    def test_duplicate_rule_ids_rejected(self, db: async_sessionmaker[AsyncSession]) -> None:
        with pytest.raises(ValueError):
            DetectionEngine([cpu_rule(), cpu_rule()], db)

    def test_list_rules_reports_state(self, db: async_sessionmaker[AsyncSession]) -> None:
        engine = DetectionEngine(build_default_rules(Settings()), db)
        infos = engine.list_rules()
        assert [i.rule_id for i in infos] == [
            "DET-CPU-001",
            "DET-MEM-001",
            "DET-NET-001",
            "DET-PROC-001",
            "DET-SYN-001",
        ]
        assert all(i.enabled for i in infos)
        engine.set_rule_enabled("DET-NET-001", False)
        assert {i.rule_id: i.enabled for i in engine.list_rules()}["DET-NET-001"] is False

    async def test_reset_clears_rule_state(self, db: async_sessionmaker[AsyncSession]) -> None:
        engine = DetectionEngine([cpu_rule(consecutive_samples=2)], db)
        await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))
        engine.reset()
        events = await engine.process_sample(await add_sample(db, 1, cpu_percent=99.0))
        assert events == []  # run restarted: only 1 consecutive sample


class TestPersistence:
    async def test_event_is_persisted_with_structured_fields(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine([cpu_rule()], db)
        sample = await add_sample(db, 0, cpu_percent=96.2)
        returned = await engine.process_sample(sample)
        (row,) = await stored(db)
        assert row.id == returned[0].id
        assert row.rule_id == "DET-CPU-001"
        assert row.event_type == "cpu_sustained_high"
        assert row.severity == "MEDIUM"
        assert row.classification == "INFORMATIONAL"
        assert row.status == "open"
        assert row.confidence == pytest.approx(0.3)
        assert row.metric_key == "cpu_percent"
        assert row.metric_value == pytest.approx(96.2)
        assert row.threshold_value == pytest.approx(90.0)
        assert row.is_synthetic is False
        assert row.telemetry_sample_id == sample.id
        assert row.detected_at.replace(tzinfo=None) == at(0).replace(tzinfo=None)

    async def test_event_data_envelope(self, db: async_sessionmaker[AsyncSession]) -> None:
        engine = DetectionEngine([cpu_rule()], db)
        await engine.process_sample(await add_sample(db, 0, cpu_percent=96.2))
        (row,) = await stored(db)
        assert row.event_data is not None
        envelope = json.loads(row.event_data)
        assert envelope["schema_version"] == 1
        assert envelope["source_kind"] == "telemetry"
        assert envelope["evidence"]["observed"] == 96.2
        assert envelope["evidence"]["threshold"] == 90.0
        assert envelope["evidence"]["metric"] == "cpu_percent"

    async def test_synthetic_event_persisted_without_telemetry_correlation(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine(build_default_rules(Settings()), db)
        await engine.process_synthetic(syn(SyntheticEventType.SUSPICIOUS_PROCESS, subject="x.exe"))
        (row,) = await stored(db)
        assert row.is_synthetic is True
        assert row.telemetry_sample_id is None
        assert row.classification == "HIGH_CONFIDENCE"
        assert json.loads(row.event_data or "{}")["source_kind"] == "synthetic"

    async def test_multiple_results_persist_in_one_transaction(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        settings = Settings(det_cpu_consecutive_samples=1, det_mem_consecutive_samples=1)
        engine = DetectionEngine(build_default_rules(settings), db)
        sample = await add_sample(db, 0, cpu_percent=95.0, memory_percent=95.0)
        events = await engine.process_sample(sample)
        assert sorted(e.rule_id for e in events) == ["DET-CPU-001", "DET-MEM-001"]
        assert len(await stored(db)) == 2

    async def test_nothing_persisted_when_nothing_detected(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        engine = DetectionEngine(build_default_rules(Settings()), db)
        assert await engine.process_sample(await add_sample(db, 0, cpu_percent=5.0)) == []
        assert await stored(db) == []

    async def test_persist_failure_returns_empty_and_logs(
        self, db: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
    ) -> None:
        engine = DetectionEngine([cpu_rule()], _FailingFactory())  # type: ignore[arg-type]
        sample = await add_sample(db, 0, cpu_percent=99.0)
        with caplog.at_level(logging.ERROR, logger="detection.engine"):
            assert await engine.process_sample(sample) == []
        assert any("failed to persist" in r.getMessage() for r in caplog.records)

    async def test_persist_failure_releases_cooldown_so_event_is_not_lost(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        rule = CpuAnomalyRule(threshold_percent=90.0, consecutive_samples=1, cooldown_seconds=600)
        engine = DetectionEngine([rule], _FailingFactory())  # type: ignore[arg-type]
        await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))  # lost to DB failure
        engine._session_factory = db  # DB recovers
        events = await engine.process_sample(await add_sample(db, 1, cpu_percent=99.0))
        # Without the release, the 600s cooldown would suppress this event.
        assert len(events) == 1

    async def test_successful_persist_keeps_cooldown(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        rule = CpuAnomalyRule(threshold_percent=90.0, consecutive_samples=1, cooldown_seconds=600)
        engine = DetectionEngine([rule], db)
        assert len(await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))) == 1
        assert await engine.process_sample(await add_sample(db, 1, cpu_percent=99.0)) == []

    async def test_cancellation_during_persist_releases_cooldown_and_propagates(
        self, db: async_sessionmaker[AsyncSession]
    ) -> None:
        class _Cancelling(_FailingFactory):
            async def __aenter__(self) -> AsyncSession:
                raise asyncio.CancelledError

        rule = CpuAnomalyRule(threshold_percent=90.0, consecutive_samples=1, cooldown_seconds=600)
        engine = DetectionEngine([rule], _Cancelling())  # type: ignore[arg-type]
        with pytest.raises(asyncio.CancelledError):
            await engine.process_sample(await add_sample(db, 0, cpu_percent=99.0))
        engine._session_factory = db
        assert len(await engine.process_sample(await add_sample(db, 1, cpu_percent=99.0))) == 1


class TestDeterminism:
    async def test_same_sequence_same_events(self) -> None:
        async def run_once() -> list[tuple[Any, ...]]:
            eng = create_async_engine(
                "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
            )
            await create_all_tables(eng)
            factory = async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
            settings = Settings(det_cooldown_seconds=4.0, det_cpu_consecutive_samples=2)
            engine = DetectionEngine(build_default_rules(settings), factory)
            cpu = [10, 95, 96, 97, 20, 95, 95, 95, 95, 95, 95, 95]
            for i, value in enumerate(cpu):
                await engine.process_sample(await add_sample(factory, i, cpu_percent=float(value)))
            for s in range(12):
                await engine.process_synthetic(syn(SyntheticEventType.AUTH_FAILURE, seconds=s))
            rows = await stored(factory)
            await eng.dispose()
            return [
                (r.rule_id, r.event_type, r.severity, r.classification, r.confidence, r.event_data)
                for r in rows
            ]

        first, second = await run_once(), await run_once()
        assert first == second
        assert len(first) >= 3


class TestResultMapping:
    def test_result_to_event_maps_every_field(self) -> None:
        result = DetectionResult(
            rule_id="R-1",
            rule_name="Rule",
            event_type="t",
            severity=Severity.HIGH,
            classification=Classification.SUSPICIOUS,
            confidence=0.7,
            detected_at=at(3),
            metric_key="m",
            metric_value=2.0,
            threshold_value=1.0,
            is_synthetic=True,
            telemetry_sample_id=9,
            evidence={"k": [1, 2]},
        )
        event = result_to_event(result)
        assert (event.rule_id, event.rule_name, event.event_type) == ("R-1", "Rule", "t")
        assert (event.severity, event.classification) == ("HIGH", "SUSPICIOUS")
        assert event.confidence == 0.7
        assert event.is_synthetic is True
        assert event.telemetry_sample_id == 9
        assert json.loads(event.event_data or "")["evidence"] == {"k": [1, 2]}


class TestDescribe:
    def _result(self, event_type: str, evidence: dict[str, Any]) -> DetectionResult:
        return DetectionResult(
            rule_id="R",
            rule_name="Some rule",
            event_type=event_type,
            severity=Severity.LOW,
            classification=Classification.INFORMATIONAL,
            confidence=0.3,
            detected_at=at(0),
            metric_key="m",
            evidence=evidence,
        )

    def test_cpu(self) -> None:
        text = describe(
            self._result(
                "cpu_sustained_high",
                {"observed": 96.2, "threshold": 90.0, "consecutive_samples": 3},
            )
        )
        assert text == "CPU utilization was 96.2% (threshold 90.0%) for 3 consecutive samples."

    def test_network(self) -> None:
        text = describe(
            self._result(
                "network_throughput_high",
                {
                    "observed": 80e6,
                    "threshold": 50e6,
                    "consecutive_samples": 3,
                    "direction": "outbound",
                },
            )
        )
        assert "outbound" in text
        assert "80.00 MB/s" in text

    def test_burst_never_echoes_untrusted_subject(self) -> None:
        text = describe(
            self._result(
                "auth_failure_burst",
                {
                    "observed_count": 5,
                    "threshold": 5,
                    "window_seconds": 60.0,
                    "latest_subject": "EVIL\nINJECTED",
                },
            )
        )
        assert "EVIL" not in text
        assert "5 authentication failures" in text

    def test_unknown_event_type_falls_back(self) -> None:
        assert describe(self._result("brand_new", {})) == "Some rule (brand_new)."

    def test_missing_evidence_falls_back(self) -> None:
        assert describe(self._result("cpu_sustained_high", {})) == "Some rule (cpu_sustained_high)."
