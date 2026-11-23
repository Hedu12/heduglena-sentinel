"""Schema and migration tests for the Phase 6 ai_explanations audit columns."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from database.models import AIExplanationRecord
from database.repositories import AIExplanationRepository
from tests.response_helpers import database

BACKEND = Path(__file__).resolve().parents[2]
PREVIOUS = "d6f3b9a40006"
NEW_COLUMNS = {
    "situation_id",
    "trigger",
    "status",
    "failure_reason",
    "failure_detail",
    "latency_ms",
    "attempts",
    "context_fingerprint",
    "content",
}


def _alembic(db: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{db.as_posix()}"}
    return subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        cwd=BACKEND,
        env=env,
        timeout=120,
        check=False,
    )


def _columns(db: Path) -> set[str]:
    conn = sqlite3.connect(db)
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(ai_explanations)")}
    finally:
        conn.close()


def record(**overrides: object) -> AIExplanationRecord:
    fields: dict[str, object] = {
        "generated_at": datetime(2026, 1, 1, tzinfo=UTC),
        "incident_id": "SIT-1",
        "provider": "fake",
        "explanation": "text",
        "status": "VALID",
        "trigger": "INCIDENT_CREATED",
        "content": "{}",
    }
    fields.update(overrides)
    return AIExplanationRecord(**fields)  # type: ignore[arg-type]


class TestConstraints:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"status": "MAYBE"},
            {"trigger": "AI_DECIDED"},
            {"status": "REJECTED", "content": '{"summary": "unsafe"}'},
            {"status": "FAILED", "content": "{}"},
        ],
    )
    async def test_invalid_records_are_refused_by_the_database(
        self, overrides: dict[str, object]
    ) -> None:
        async with database() as factory:
            with pytest.raises(IntegrityError):
                async with factory() as session, session.begin():
                    await AIExplanationRepository(session).insert(record(**overrides))

    async def test_one_record_per_trigger_key_per_incident(self) -> None:
        async with database() as factory:
            async with factory() as session, session.begin():
                repo = AIExplanationRepository(session)
                await repo.insert(record(trigger_key="STATE_TRANSITION:5"))
                await repo.insert(record(incident_id="SIT-2", trigger_key="STATE_TRANSITION:5"))
                await repo.insert(record(trigger_key=None))
                await repo.insert(record(trigger_key=None))  # legacy rows never conflict
            with pytest.raises(IntegrityError):
                async with factory() as session, session.begin():
                    await AIExplanationRepository(session).insert(
                        record(trigger_key="STATE_TRANSITION:5")
                    )

    async def test_pre_phase6_rows_remain_valid(self) -> None:
        async with database() as factory, factory() as session, session.begin():
            legacy = AIExplanationRecord(
                generated_at=datetime(2026, 1, 1, tzinfo=UTC),
                incident_id="inc-1",
                provider="null",
                explanation="legacy",
            )
            saved = await AIExplanationRepository(session).insert(legacy)
            assert saved.status is None and saved.content is None


class TestMigration:
    def test_the_trigger_memory_migration_round_trips(self, tmp_path: Path) -> None:
        db = tmp_path / "triggers.db"
        added = {"trigger_key", "decision_at", "evidence_state"}
        assert _alembic(db, "upgrade", "head").returncode == 0
        assert added <= _columns(db)
        down = _alembic(db, "downgrade", "e7a4c1b20007")
        assert down.returncode == 0, down.stderr
        assert not (added & _columns(db))
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        try:
            insert = (
                "INSERT INTO ai_explanations (generated_at, incident_id, provider, explanation, "
                "trigger_key, raw_response) VALUES ('2026-01-01', 'SIT-1', 'fake', 'x', ?, ?)"
            )
            conn.execute(insert, ("INCIDENT_CREATED", "ok"))
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("INCIDENT_CREATED", "again"))
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("NEW_EVIDENCE:x", "y" * 16_001))
        finally:
            conn.close()

    def test_upgrade_downgrade_and_reupgrade(self, tmp_path: Path) -> None:
        db = tmp_path / "ai.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        assert NEW_COLUMNS <= _columns(db)
        down = _alembic(db, "downgrade", PREVIOUS)
        assert down.returncode == 0, down.stderr
        assert not (NEW_COLUMNS & _columns(db))
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        try:
            insert = (
                "INSERT INTO ai_explanations (generated_at, incident_id, provider, explanation, "
                "status, content) VALUES ('2026-01-01', 'SIT-1', 'fake', 'x', ?, ?)"
            )
            conn.execute(insert, ("VALID", "{}"))
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("REJECTED", "{}"))
        finally:
            conn.close()
