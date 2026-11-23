"""
Schema tests for the Phase 5 response_actions columns, constraints and migration.

The database itself enforces the two guarantees the response engine depends on:
one record per (scope, decision), and at most one SUCCEEDED record per
once-per-scope action.
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
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database.base import Base
from database.models import Incident, ResponseAction
from database.repositories import IncidentRepository, ResponseActionRepository
from tests.response_helpers import database
from tests.threat_helpers import T0

BACKEND = Path(__file__).resolve().parents[2]
PHASE4_REVISION = "b4c9d7e10004"
PHASE5_REVISION = "c5e2a8f30005"
HEAD_REVISION = "f8b5d2c30008"  # Phase 6.1: restart-stable explanation triggers
NEW_COLUMNS = {
    "situation_id",
    "status",
    "action_class",
    "guard_reason",
    "scope_key",
    "once_key",
    "idempotency_key",
    "lifecycle",
}


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with database() as f:
        yield f


_n = {"i": 0}


def row(**overrides: object) -> ResponseAction:
    _n["i"] += 1
    base: dict[str, object] = {
        "executed_at": T0,
        "action_type": "SIMULATE_IP_BLOCK",
        "defense_state": "DEFENSIVE",
        "dry_run_description": "x",
        "triggering_event_id": None,
        "status": "SUCCEEDED",
        "scope_key": "s1:SIMULATE_IP_BLOCK",
        "idempotency_key": f"key-{_n['i']}",
    }
    base.update(overrides)
    return ResponseAction(**base)  # type: ignore[arg-type]


async def insert(
    factory: async_sessionmaker[AsyncSession], action: ResponseAction
) -> ResponseAction:
    async with factory() as session, session.begin():
        return await ResponseActionRepository(session).insert(action)


class TestConstraints:
    async def test_idempotency_key_is_unique(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await insert(factory, row(idempotency_key="same"))
        with pytest.raises(IntegrityError):
            await insert(factory, row(idempotency_key="same"))

    async def test_only_one_success_per_once_key(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await insert(factory, row(once_key="s1:BLOCK", status="SUCCEEDED"))
        with pytest.raises(IntegrityError):
            await insert(factory, row(once_key="s1:BLOCK", status="SUCCEEDED"))

    async def test_failed_and_blocked_attempts_may_repeat_alongside_one_success(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        for status in ("FAILED", "BLOCKED", "FAILED", "SUCCEEDED", "BLOCKED"):
            await insert(factory, row(once_key="s1:BLOCK", status=status))

    async def test_rows_without_a_once_key_never_conflict(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        for _ in range(3):
            await insert(factory, row(once_key=None, status="SUCCEEDED"))

    @pytest.mark.parametrize("status", ["PLANNED", "AUTHORIZED", "EXECUTING", "DONE", "succeeded"])
    async def test_only_terminal_statuses_can_be_persisted(
        self, factory: async_sessionmaker[AsyncSession], status: str
    ) -> None:
        with pytest.raises(IntegrityError):
            await insert(factory, row(status=status))

    async def test_unknown_action_class_rejected(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(IntegrityError):
            await insert(factory, row(action_class="NUCLEAR"))

    async def test_unknown_defense_state_rejected(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(IntegrityError):
            await insert(factory, row(defense_state="PANIC"))

    @pytest.mark.parametrize("status", ["closed", "OPEN", "done", ""])
    async def test_only_known_incident_statuses_can_be_persisted(
        self, factory: async_sessionmaker[AsyncSession], status: str
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await IncidentRepository(session).insert(
                    Incident(
                        incident_id="SIT-x",
                        created_at=T0,
                        defense_state="ALERT",
                        threat_score_at_creation=0.5,
                        status=status,
                    )
                )

    async def test_pre_phase5_style_rows_remain_valid(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        legacy = ResponseAction(
            executed_at=T0,
            action_type="GENERATE_ALERT",
            defense_state="RELAXED",
            dry_run_description="legacy",
            triggering_event_id=None,
        )
        saved = await insert(factory, legacy)
        assert saved.status is None and saved.idempotency_key is None
        assert saved.is_simulated is True


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


def _columns(db: Path) -> set[str]:
    conn = sqlite3.connect(db)
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(response_actions)")}
    finally:
        conn.close()


class TestMigration:
    def test_upgrade_from_empty_adds_the_phase5_columns(self, tmp_path: Path) -> None:
        db = tmp_path / "fresh.db"
        result = _alembic(db, "upgrade", "head")
        assert result.returncode == 0, result.stderr
        assert NEW_COLUMNS <= _columns(db)

    def test_downgrade_and_reupgrade(self, tmp_path: Path) -> None:
        db = tmp_path / "roundtrip.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        down = _alembic(db, "downgrade", PHASE4_REVISION)
        assert down.returncode == 0, down.stderr
        assert not (NEW_COLUMNS & _columns(db))
        assert _alembic(db, "upgrade", "head").returncode == 0
        assert NEW_COLUMNS <= _columns(db)

    def test_migrated_schema_matches_the_orm_models(self, tmp_path: Path) -> None:
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

    def test_migrated_database_enforces_the_dedup_and_idempotency_indexes(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "checks.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        insert = (
            "INSERT INTO response_actions (executed_at, action_type, defense_state, "
            "dry_run_description, is_simulated, status, once_key, idempotency_key) "
            "VALUES ('2025-01-01', 'SIMULATE_IP_BLOCK', 'DEFENSIVE', 'x', 1, ?, ?, ?)"
        )
        try:
            conn.execute(insert, ("FAILED", "s1:B", "k1"))
            conn.execute(insert, ("SUCCEEDED", "s1:B", "k2"))
            for params in [
                ("SUCCEEDED", "s1:B", "k3"),
                ("FAILED", "s1:B", "k1"),
                ("RUNNING", None, "k4"),
            ]:
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(insert, params)
        finally:
            conn.close()

    def test_incident_resolution_migration_round_trips(self, tmp_path: Path) -> None:
        db = tmp_path / "incidents.db"
        resolution = {"recovered_at", "resolved_at", "resolution"}

        def incident_columns() -> set[str]:
            conn = sqlite3.connect(db)
            try:
                return {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
            finally:
                conn.close()

        assert _alembic(db, "upgrade", "head").returncode == 0
        assert resolution <= incident_columns()
        down = _alembic(db, "downgrade", PHASE5_REVISION)
        assert down.returncode == 0, down.stderr
        assert not (resolution & incident_columns())
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        try:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO incidents (incident_id, created_at, status, defense_state, "
                    "threat_score_at_creation) "
                    "VALUES ('SIT-1', '2025-01-01', 'closed', 'ALERT', 0.5)"
                )
        finally:
            conn.close()

    def test_there_is_a_single_head_and_it_is_the_latest_revision(self, tmp_path: Path) -> None:
        result = _alembic(tmp_path / "heads.db", "heads")
        assert result.returncode == 0, result.stderr
        assert result.stdout.count("(head)") == 1
        assert f"{HEAD_REVISION} (head)" in result.stdout
        history = _alembic(tmp_path / "history.db", "history")
        assert PHASE5_REVISION in history.stdout

    def test_an_upgraded_database_is_at_head(self, tmp_path: Path) -> None:
        db = tmp_path / "current.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        current = _alembic(db, "current")
        assert current.returncode == 0, current.stderr
        assert f"{HEAD_REVISION} (head)" in current.stdout
