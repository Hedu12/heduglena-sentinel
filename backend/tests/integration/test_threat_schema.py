"""
Schema tests for the Phase 4 columns, constraints and migration.

Scores and transitions are the audit trail of Sentinel's decisions, so the
database itself refuses impossible values: a score outside [0, 1], an unknown
state, or a "transition" that does not change the state.
"""

from __future__ import annotations

import itertools
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
from database.models import DefenseStateChange, ThreatScore
from database.repositories import DefenseStateChangeRepository, ThreatScoreRepository
from tests.threat_helpers import T0

BACKEND = Path(__file__).resolve().parents[2]
STATES = ["RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE"]
PHASE3_REVISION = "a3f1c0de0003"
HEAD_REVISION = "b4c9d7e10004"


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    eng: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    await create_all_tables(eng)
    yield async_sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    await drop_all_tables(eng)
    await eng.dispose()


def score_row(**overrides: object) -> ThreatScore:
    base: dict[str, object] = {"calculated_at": T0, "score": 0.5}
    base.update(overrides)
    return ThreatScore(**base)  # type: ignore[arg-type]


def change_row(**overrides: object) -> DefenseStateChange:
    base: dict[str, object] = {
        "changed_at": T0,
        "from_state": "RELAXED",
        "to_state": "ALERT",
        "trigger_score": 0.4,
    }
    base.update(overrides)
    return DefenseStateChange(**base)  # type: ignore[arg-type]


class TestThreatScoreConstraints:
    @pytest.mark.parametrize("score", [0.0, 0.25, 1.0])
    async def test_valid_scores_accepted(
        self, factory: async_sessionmaker[AsyncSession], score: float
    ) -> None:
        async with factory() as session, session.begin():
            saved = await ThreatScoreRepository(session).insert(score_row(score=score))
        assert saved.score == score

    @pytest.mark.parametrize("score", [-0.0001, 1.0001, 2.0, -1.0])
    async def test_out_of_range_scores_rejected_by_the_database(
        self, factory: async_sessionmaker[AsyncSession], score: float
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await ThreatScoreRepository(session).insert(score_row(score=score))

    async def test_unknown_defense_state_rejected(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await ThreatScoreRepository(session).insert(score_row(defense_state="PANIC"))

    async def test_state_and_breakdown_are_optional(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        async with factory() as session, session.begin():
            saved = await ThreatScoreRepository(session).insert(score_row())
        assert saved.defense_state is None
        assert saved.breakdown is None

    @pytest.mark.parametrize("state", STATES)
    async def test_every_defense_state_is_accepted(
        self, factory: async_sessionmaker[AsyncSession], state: str
    ) -> None:
        async with factory() as session, session.begin():
            saved = await ThreatScoreRepository(session).insert(
                score_row(defense_state=state, breakdown='{"final_score": 0.5}')
            )
        assert saved.defense_state == state


class TestDefenseStateChangeConstraints:
    @pytest.mark.parametrize(
        ("from_state", "to_state"),
        [(a, b) for a, b in itertools.permutations(STATES, 2)],
    )
    async def test_every_real_transition_is_accepted(
        self, factory: async_sessionmaker[AsyncSession], from_state: str, to_state: str
    ) -> None:
        async with factory() as session, session.begin():
            saved = await DefenseStateChangeRepository(session).insert(
                change_row(from_state=from_state, to_state=to_state)
            )
        assert (saved.from_state, saved.to_state) == (from_state, to_state)

    @pytest.mark.parametrize("state", STATES)
    async def test_a_transition_must_change_the_state(
        self, factory: async_sessionmaker[AsyncSession], state: str
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await DefenseStateChangeRepository(session).insert(
                    change_row(from_state=state, to_state=state)
                )

    @pytest.mark.parametrize(
        "overrides",
        [
            {"from_state": "PANIC"},
            {"to_state": "relaxed"},
            {"to_state": ""},
            {"trigger_score": 1.5},
            {"trigger_score": -0.1},
            {"previous_score": 1.2},
            {"previous_score": -0.2},
        ],
    )
    async def test_invalid_values_rejected(
        self, factory: async_sessionmaker[AsyncSession], overrides: dict[str, object]
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await DefenseStateChangeRepository(session).insert(change_row(**overrides))

    async def test_new_columns_round_trip(self, factory: async_sessionmaker[AsyncSession]) -> None:
        async with factory() as session, session.begin():
            await DefenseStateChangeRepository(session).insert(
                change_row(
                    previous_score=0.3,
                    reason="SEVERE_ESCALATION_BYPASS",
                    evidence='{"schema_version": 1}',
                    trigger_event_ids="[1, 2]",
                )
            )
        async with factory() as session:
            loaded = await DefenseStateChangeRepository(session).get_latest()
        assert loaded is not None
        assert loaded.previous_score == pytest.approx(0.3)
        assert loaded.reason == "SEVERE_ESCALATION_BYPASS"
        assert loaded.evidence == '{"schema_version": 1}'

    async def test_new_columns_are_optional(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        async with factory() as session, session.begin():
            saved = await DefenseStateChangeRepository(session).insert(change_row())
        assert (saved.previous_score, saved.reason, saved.evidence) == (None, None, None)


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


def _columns(db_path: Path, table: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}  # noqa: S608
    finally:
        conn.close()


class TestMigration:
    def test_upgrade_from_empty_adds_the_phase4_columns(self, tmp_path: Path) -> None:
        db = tmp_path / "fresh.db"
        result = _alembic(db, "upgrade", "head")
        assert result.returncode == 0, result.stderr
        assert {"defense_state", "breakdown"} <= _columns(db, "threat_scores")
        assert {"previous_score", "reason", "evidence"} <= _columns(db, "defense_state_changes")

    def test_downgrade_removes_only_the_phase4_columns_and_reupgrade_restores_them(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "roundtrip.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        down = _alembic(db, "downgrade", PHASE3_REVISION)
        assert down.returncode == 0, down.stderr
        assert not ({"defense_state", "breakdown"} & _columns(db, "threat_scores"))
        assert not (
            {"previous_score", "reason", "evidence"} & _columns(db, "defense_state_changes")
        )
        # Phase 3 columns are still there.
        assert {"event_type", "classification"} <= _columns(db, "detection_events")
        assert _alembic(db, "upgrade", "head").returncode == 0
        assert "evidence" in _columns(db, "defense_state_changes")

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

    def test_migrated_database_enforces_the_check_constraints(self, tmp_path: Path) -> None:
        db = tmp_path / "checks.db"
        assert _alembic(db, "upgrade", "head").returncode == 0
        conn = sqlite3.connect(db)
        try:
            score = (
                "INSERT INTO threat_scores (calculated_at, score, defense_state) "
                "VALUES ('2025-01-01', ?, ?)"
            )
            change = (
                "INSERT INTO defense_state_changes "
                "(changed_at, previous_state, new_state, trigger_score) "
                "VALUES ('2025-01-01', ?, ?, ?)"
            )
            conn.execute(score, (0.5, "ALERT"))
            conn.execute(change, ("RELAXED", "ALERT", 0.4))
            for sql, params in [
                (score, (1.5, "ALERT")),
                (score, (0.5, "PANIC")),
                (change, ("ALERT", "ALERT", 0.4)),
                (change, ("RELAXED", "NOPE", 0.4)),
                (change, ("RELAXED", "ALERT", 2.0)),
            ]:
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(sql, params)
        finally:
            conn.close()

    def test_there_is_a_single_linear_head(self, tmp_path: Path) -> None:
        result = _alembic(tmp_path / "heads.db", "heads")
        assert result.returncode == 0, result.stderr
        assert result.stdout.count("(head)") == 1
        # This phase's revision must stay in the linear history (later phases add heads).
        history = _alembic(tmp_path / "history.db", "history")
        assert history.returncode == 0, history.stderr
        assert HEAD_REVISION in history.stdout
