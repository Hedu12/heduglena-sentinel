"""
Schema tests for the Phase 3 detection_events columns and migration.

* ORM level: defaults, constraints, and the telemetry_sample_id round trip.
* Migration level: upgrade/downgrade on a real SQLite file and no drift
  between the migrated schema and the ORM models.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database.base import Base
from database.engine import create_all_tables, drop_all_tables
from database.models import DetectionEvent, TelemetrySample
from database.repositories import DetectionEventRepository, TelemetrySampleRepository
from tests.detection_helpers import T0

BACKEND = Path(__file__).resolve().parents[2]


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    yield async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    await drop_all_tables(eng)
    await eng.dispose()


def event(**overrides: object) -> DetectionEvent:
    base: dict[str, object] = {
        "detected_at": T0,
        "rule_id": "DET-X-001",
        "rule_name": "X",
        "severity": "HIGH",
        "metric_key": "m",
    }
    base.update(overrides)
    return DetectionEvent(**base)  # type: ignore[arg-type]


class TestDetectionEventColumns:
    async def test_defaults(self, factory: async_sessionmaker[AsyncSession]) -> None:
        e = event()
        assert e.event_type == "unspecified"
        assert e.classification == "INFORMATIONAL"
        assert e.status == "open"
        assert e.confidence is None
        assert e.telemetry_sample_id is None

    async def test_telemetry_sample_id_survives_flush_and_reload(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        async with factory() as session, session.begin():
            sample = await TelemetrySampleRepository(session).insert(
                TelemetrySample(collected_at=T0, cpu_percent=50.0)
            )
            saved = await DetectionEventRepository(session).insert(
                event(telemetry_sample_id=sample.id, confidence=0.4, event_type="t")
            )
        assert saved.telemetry_sample_id == sample.id
        async with factory() as session:
            (loaded,) = await DetectionEventRepository(session).get_since(
                T0.replace(year=2000), limit=10
            )
        assert loaded.telemetry_sample_id == sample.id
        assert loaded.confidence == pytest.approx(0.4)
        assert loaded.event_type == "t"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"severity": "BOGUS"},
            {"severity": "high"},
            {"classification": "MALICIOUS"},
            {"status": "closed"},
            {"confidence": 1.01},
            {"confidence": -0.01},
        ],
    )
    async def test_invalid_values_are_rejected_by_the_database(
        self, factory: async_sessionmaker[AsyncSession], overrides: dict[str, object]
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await DetectionEventRepository(session).insert(event(**overrides))

    @pytest.mark.parametrize("confidence", [None, 0.0, 0.5, 1.0])
    async def test_boundary_confidence_accepted(
        self, factory: async_sessionmaker[AsyncSession], confidence: float | None
    ) -> None:
        async with factory() as session, session.begin():
            saved = await DetectionEventRepository(session).insert(event(confidence=confidence))
        assert saved.id is not None

    @pytest.mark.parametrize("severity", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    @pytest.mark.parametrize("classification", ["INFORMATIONAL", "SUSPICIOUS", "HIGH_CONFIDENCE"])
    async def test_every_valid_severity_and_classification_accepted(
        self,
        factory: async_sessionmaker[AsyncSession],
        severity: str,
        classification: str,
    ) -> None:
        async with factory() as session, session.begin():
            saved = await DetectionEventRepository(session).insert(
                event(severity=severity, classification=classification)
            )
        assert saved.id is not None


def _alembic(db_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{db_path.as_posix()}"}
    return subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        cwd=BACKEND,
        env=env,
        timeout=120,
        check=False,
    )


def _columns(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {row[1] for row in conn.execute("PRAGMA table_info(detection_events)")}
    finally:
        conn.close()


PHASE2_REVISION = "532f8b0b7293"  # the schema before detection columns existed
NEW_COLUMNS = {"telemetry_sample_id", "event_type", "classification", "confidence", "status"}


class TestMigration:
    def test_upgrade_from_empty_database(self, tmp_path: Path) -> None:
        db = tmp_path / "fresh.db"
        result = _alembic(db, "upgrade", "head")
        assert result.returncode == 0, result.stderr
        assert NEW_COLUMNS <= _columns(db)

    def test_downgrade_removes_phase3_columns_and_reupgrade_restores_them(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "roundtrip.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        down = _alembic(db, "downgrade", PHASE2_REVISION)
        assert down.returncode == 0, down.stderr
        assert not (NEW_COLUMNS & _columns(db))
        assert _alembic(db, "upgrade", "head").returncode == 0
        assert NEW_COLUMNS <= _columns(db)

    def test_migrated_schema_matches_orm_models(self, tmp_path: Path) -> None:
        db = tmp_path / "drift.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        engine = create_engine(f"sqlite:///{db.as_posix()}")
        try:
            with engine.connect() as conn:
                diff = compare_metadata(
                    MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata
                )
        finally:
            engine.dispose()
        assert diff == []

    def test_migrated_database_enforces_check_constraints(self, tmp_path: Path) -> None:
        db = tmp_path / "checks.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        try:
            insert = (
                "INSERT INTO detection_events "
                "(detected_at, rule_id, rule_name, severity, metric_key, is_synthetic, confidence) "
                "VALUES ('2025-01-01', 'r', 'n', ?, 'm', 0, ?)"
            )
            conn.execute(insert, ("HIGH", 0.5))
            for severity, confidence in (("BOGUS", 0.5), ("HIGH", 2.0)):
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(insert, (severity, confidence))
        finally:
            conn.close()

    def test_head_is_a_single_linear_revision(self, tmp_path: Path) -> None:
        result = _alembic(tmp_path / "heads.db", "heads")
        assert result.returncode == 0, result.stderr
        assert result.stdout.count("(head)") == 1
        # This phase's revision must stay in the linear history (later phases add heads).
        history = _alembic(tmp_path / "history.db", "history")
        assert history.returncode == 0, history.stderr
        assert "a3f1c0de0003" in history.stdout
