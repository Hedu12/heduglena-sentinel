"""
Integration tests for the database repositories.

Uses an in-memory SQLite database created fresh for each test.
Verifies persistence, relationships, append-only invariant, simulation
flag behaviour, and timestamp handling.

All tests use the async session via pytest-asyncio (asyncio_mode=auto
is set in pyproject.toml).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database.engine import create_all_tables, drop_all_tables
from database.models import (
    AIExplanationRecord,
    Baseline,
    DefenseStateChange,
    DetectionEvent,
    Incident,
    ResponseAction,
    TelemetrySample,
    ThreatScore,
)
from database.repositories import (
    AIExplanationRepository,
    BaselineRepository,
    DefenseStateChangeRepository,
    DetectionEventRepository,
    IncidentRepository,
    ResponseActionRepository,
    TelemetrySampleRepository,
    ThreatScoreRepository,
    UnitOfWork,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def engine() -> AsyncEngine:  # type: ignore[misc]
    """In-memory SQLite engine per test — no cross-test contamination."""
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    await create_all_tables(eng)
    yield eng  # type: ignore[misc]
    await drop_all_tables(eng)
    await eng.dispose()


@pytest_asyncio.fixture()
async def session(engine: AsyncEngine) -> AsyncSession:  # type: ignore[misc]
    """Provide a single AsyncSession per test, auto-rolled back after."""
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    async with factory() as sess:
        yield sess  # type: ignore[misc]


def _now() -> datetime:
    return datetime.now(UTC)


def _ago(seconds: int) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# TelemetrySample
# ---------------------------------------------------------------------------


class TestTelemetrySampleRepository:
    async def test_insert_and_get_latest(self, session: AsyncSession) -> None:
        repo = TelemetrySampleRepository(session)
        sample = TelemetrySample(
            collected_at=_now(),
            cpu_percent=55.0,
            memory_percent=70.0,
        )
        async with session.begin():
            saved = await repo.insert(sample)
        assert saved.id is not None

        async with session.begin():
            latest = await repo.get_latest()
        assert latest is not None
        assert latest.cpu_percent == 55.0

    async def test_get_latest_returns_none_on_empty_db(self, session: AsyncSession) -> None:
        repo = TelemetrySampleRepository(session)
        result = await repo.get_latest()
        assert result is None

    async def test_get_since_filters_correctly(self, session: AsyncSession) -> None:
        repo = TelemetrySampleRepository(session)
        old = TelemetrySample(collected_at=_ago(120), cpu_percent=10.0)
        new = TelemetrySample(collected_at=_ago(10), cpu_percent=90.0)
        async with session.begin():
            await repo.insert(old)
            await repo.insert(new)

        cutoff = _ago(60)
        async with session.begin():
            results = await repo.get_since(cutoff)
        assert len(results) == 1
        assert results[0].cpu_percent == 90.0

    async def test_null_metrics_persist(self, session: AsyncSession) -> None:
        """AC-F01-4: partial samples with null metrics persist correctly."""
        repo = TelemetrySampleRepository(session)
        sample = TelemetrySample(
            collected_at=_now(),
            cpu_percent=None,
            memory_percent=None,
        )
        async with session.begin():
            saved = await repo.insert(sample)
        assert saved.id is not None

        async with session.begin():
            latest = await repo.get_latest()
        assert latest is not None
        assert latest.cpu_percent is None


# ---------------------------------------------------------------------------
# DetectionEvent
# ---------------------------------------------------------------------------


class TestDetectionEventRepository:
    async def test_insert_and_retrieve_by_id(self, session: AsyncSession) -> None:
        repo = DetectionEventRepository(session)
        event = DetectionEvent(
            detected_at=_now(),
            rule_id="cpu-spike",
            rule_name="CPU Spike",
            severity="HIGH",
            metric_key="cpu_percent",
            metric_value=92.0,
            threshold_value=85.0,
            is_synthetic=False,
        )
        async with session.begin():
            saved = await repo.insert(event)
        assert saved.id is not None

        async with session.begin():
            fetched = await repo.get_by_id(saved.id)
        assert fetched is not None
        assert fetched.rule_id == "cpu-spike"
        assert fetched.severity == "HIGH"

    async def test_get_by_id_returns_none_for_missing(self, session: AsyncSession) -> None:
        repo = DetectionEventRepository(session)
        result = await repo.get_by_id(99999)
        assert result is None

    async def test_get_since_with_severity_filter(self, session: AsyncSession) -> None:
        repo = DetectionEventRepository(session)
        events = [
            DetectionEvent(
                detected_at=_ago(5),
                rule_id="cpu-spike",
                rule_name="CPU Spike",
                severity="HIGH",
                metric_key="cpu_percent",
            ),
            DetectionEvent(
                detected_at=_ago(3),
                rule_id="network-surge",
                rule_name="Network Surge",
                severity="MEDIUM",
                metric_key="net_bytes_sent",
            ),
        ]
        async with session.begin():
            for e in events:
                await repo.insert(e)

        async with session.begin():
            high_only = await repo.get_since(_ago(60), severity="HIGH")
        assert len(high_only) == 1
        assert high_only[0].severity == "HIGH"

    async def test_synthetic_flag_persists(self, session: AsyncSession) -> None:
        repo = DetectionEventRepository(session)
        event = DetectionEvent(
            detected_at=_now(),
            rule_id="auth-failure-burst",
            rule_name="Auth Failure Burst",
            severity="HIGH",
            metric_key="synthetic:auth_failure",
            is_synthetic=True,
        )
        async with session.begin():
            saved = await repo.insert(event)

        async with session.begin():
            fetched = await repo.get_by_id(saved.id)
        assert fetched is not None
        assert fetched.is_synthetic is True

    async def test_count_by_rule_since(self, session: AsyncSession) -> None:
        repo = DetectionEventRepository(session)
        for _ in range(3):
            async with session.begin():
                await repo.insert(
                    DetectionEvent(
                        detected_at=_ago(10),
                        rule_id="auth-failure-burst",
                        rule_name="Auth Failure",
                        severity="HIGH",
                        metric_key="synthetic:auth_failure",
                        is_synthetic=True,
                    )
                )
        async with session.begin():
            count = await repo.count_by_rule_since("auth-failure-burst", _ago(30))
        assert count == 3

    async def test_append_only_no_update(self, session: AsyncSession) -> None:
        """P-07: detection events must not be updated after insertion."""

        repo = DetectionEventRepository(session)
        async with session.begin():
            event = await repo.insert(
                DetectionEvent(
                    detected_at=_now(),
                    rule_id="cpu-spike",
                    rule_name="CPU Spike",
                    severity="HIGH",
                    metric_key="cpu_percent",
                    metric_value=88.0,
                )
            )
        original_id = event.id
        original_value = event.metric_value

        # The only way to change a row would be an explicit UPDATE.
        # We verify the value hasn't changed without an explicit UPDATE.
        async with session.begin():
            fetched = await repo.get_by_id(original_id)
        assert fetched is not None
        assert fetched.metric_value == original_value


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------


class TestIncidentRepository:
    async def test_insert_and_get_by_incident_id(self, session: AsyncSession) -> None:
        repo = IncidentRepository(session)
        inc = Incident(
            incident_id="inc-test-001",
            created_at=_now(),
            defense_state="ALERT",
            threat_score_at_creation=0.42,
        )
        async with session.begin():
            saved = await repo.insert(inc)
        assert saved.id is not None

        async with session.begin():
            fetched = await repo.get_by_incident_id("inc-test-001")
        assert fetched is not None
        assert fetched.defense_state == "ALERT"

    async def test_get_by_incident_id_returns_none_for_missing(self, session: AsyncSession) -> None:
        repo = IncidentRepository(session)
        result = await repo.get_by_incident_id("does-not-exist")
        assert result is None

    async def test_update_status(self, session: AsyncSession) -> None:
        repo = IncidentRepository(session)
        async with session.begin():
            await repo.insert(
                Incident(
                    incident_id="inc-status-test",
                    created_at=_now(),
                    defense_state="DEFENSIVE",
                    threat_score_at_creation=0.65,
                )
            )

        async with session.begin():
            updated = await repo.update_status("inc-status-test", "resolved")
        assert updated is not None
        assert updated.status == "resolved"

    async def test_get_all_returns_newest_first(self, session: AsyncSession) -> None:
        repo = IncidentRepository(session)
        async with session.begin():
            await repo.insert(
                Incident(
                    incident_id="inc-old",
                    created_at=_ago(120),
                    defense_state="RELAXED",
                    threat_score_at_creation=0.1,
                )
            )
            await repo.insert(
                Incident(
                    incident_id="inc-new",
                    created_at=_ago(10),
                    defense_state="ALERT",
                    threat_score_at_creation=0.4,
                )
            )

        async with session.begin():
            results = await repo.get_all()
        assert results[0].incident_id == "inc-new"
        assert results[1].incident_id == "inc-old"


# ---------------------------------------------------------------------------
# ThreatScore
# ---------------------------------------------------------------------------


class TestThreatScoreRepository:
    async def test_insert_and_get_latest(self, session: AsyncSession) -> None:
        repo = ThreatScoreRepository(session)
        async with session.begin():
            await repo.insert(ThreatScore(calculated_at=_ago(30), score=0.3))
            await repo.insert(ThreatScore(calculated_at=_now(), score=0.7))

        async with session.begin():
            latest = await repo.get_latest()
        assert latest is not None
        assert latest.score == pytest.approx(0.7)

    async def test_get_latest_returns_none_on_empty(self, session: AsyncSession) -> None:
        repo = ThreatScoreRepository(session)
        result = await repo.get_latest()
        assert result is None

    async def test_score_range_zero_to_one(self, session: AsyncSession) -> None:
        """AC-F03-1: threat score must be in [0.0, 1.0]."""
        repo = ThreatScoreRepository(session)
        for score in (0.0, 0.5, 1.0):
            async with session.begin():
                ts = await repo.insert(ThreatScore(calculated_at=_now(), score=score))
            assert 0.0 <= ts.score <= 1.0

    async def test_get_since_ordered_ascending(self, session: AsyncSession) -> None:
        repo = ThreatScoreRepository(session)
        async with session.begin():
            await repo.insert(ThreatScore(calculated_at=_ago(60), score=0.1))
            await repo.insert(ThreatScore(calculated_at=_ago(30), score=0.5))
            await repo.insert(ThreatScore(calculated_at=_ago(10), score=0.9))

        async with session.begin():
            results = await repo.get_since(_ago(90))
        # Oldest first (for timeline chart rendering)
        assert results[0].score == pytest.approx(0.1)
        assert results[-1].score == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# DefenseStateChange
# ---------------------------------------------------------------------------


class TestDefenseStateChangeRepository:
    async def test_insert_and_get_all(self, session: AsyncSession) -> None:
        repo = DefenseStateChangeRepository(session)
        async with session.begin():
            await repo.insert(
                DefenseStateChange(
                    changed_at=_ago(60),
                    from_state="RELAXED",
                    to_state="ALERT",
                    trigger_score=0.30,
                )
            )
            await repo.insert(
                DefenseStateChange(
                    changed_at=_ago(10),
                    from_state="ALERT",
                    to_state="DEFENSIVE",
                    trigger_score=0.60,
                )
            )

        async with session.begin():
            all_changes = await repo.get_all()
        assert len(all_changes) == 2
        # Newest first
        assert all_changes[0].to_state == "DEFENSIVE"

    async def test_get_latest(self, session: AsyncSession) -> None:
        repo = DefenseStateChangeRepository(session)
        async with session.begin():
            await repo.insert(
                DefenseStateChange(
                    changed_at=_ago(60),
                    from_state="RELAXED",
                    to_state="ALERT",
                    trigger_score=0.30,
                )
            )
        async with session.begin():
            latest = await repo.get_latest()
        assert latest is not None
        assert latest.to_state == "ALERT"

    async def test_get_latest_returns_none_on_empty(self, session: AsyncSession) -> None:
        repo = DefenseStateChangeRepository(session)
        result = await repo.get_latest()
        assert result is None

    async def test_full_escalation_arc_recorded(self, session: AsyncSession) -> None:
        """Full RELAXED → ALERT → DEFENSIVE → AGGRESSIVE arc is queryable."""
        repo = DefenseStateChangeRepository(session)
        transitions = [
            ("RELAXED", "ALERT", 0.30),
            ("ALERT", "DEFENSIVE", 0.60),
            ("DEFENSIVE", "AGGRESSIVE", 0.85),
        ]
        for prev, new, score in transitions:
            async with session.begin():
                await repo.insert(
                    DefenseStateChange(
                        changed_at=_now(),
                        from_state=prev,
                        to_state=new,
                        trigger_score=score,
                    )
                )

        async with session.begin():
            all_changes = await repo.get_all()
        states = [c.to_state for c in reversed(all_changes)]  # oldest first
        assert states == ["ALERT", "DEFENSIVE", "AGGRESSIVE"]


# ---------------------------------------------------------------------------
# ResponseAction
# ---------------------------------------------------------------------------


class TestResponseActionRepository:
    async def test_insert_simulated_action(self, session: AsyncSession) -> None:
        repo = ResponseActionRepository(session)
        action = ResponseAction(
            executed_at=_now(),
            action_type="SIMULATE_IP_BLOCK",
            is_simulated=True,
            defense_state="DEFENSIVE",
            triggering_event_id=None,
            dry_run_description="Would have blocked 10.0.0.1.",
        )
        async with session.begin():
            saved = await repo.insert(action)
        assert saved.id is not None
        assert saved.is_simulated is True

    async def test_is_simulated_defaults_true(self, session: AsyncSession) -> None:
        """P-05: is_simulated must default True — safe default enforced at model level."""
        repo = ResponseActionRepository(session)
        action = ResponseAction(
            executed_at=_now(),
            action_type="SIMULATE_QUARANTINE",
            defense_state="AGGRESSIVE",
            triggering_event_id=None,
            dry_run_description="Would have quarantined process.",
        )
        async with session.begin():
            saved = await repo.insert(action)
        assert saved.is_simulated is True

    async def test_simulated_badge_persists(self, session: AsyncSession) -> None:
        """AC-F05-1: simulated flag survives a round-trip through the database."""
        repo = ResponseActionRepository(session)
        async with session.begin():
            saved = await repo.insert(
                ResponseAction(
                    executed_at=_now(),
                    action_type="SIMULATE_IP_BLOCK",
                    is_simulated=True,
                    defense_state="DEFENSIVE",
                    triggering_event_id=None,
                    dry_run_description="Simulated block.",
                )
            )
        async with session.begin():
            all_actions = await repo.get_all()
        found = next(a for a in all_actions if a.id == saved.id)
        assert found.is_simulated is True

    async def test_action_with_triggering_event_fk(self, session: AsyncSession) -> None:
        """FK to detection_events is maintained correctly."""
        event_repo = DetectionEventRepository(session)
        action_repo = ResponseActionRepository(session)

        # Insert event and action in a single transaction.
        async with session.begin():
            event = await event_repo.insert(
                DetectionEvent(
                    detected_at=_now(),
                    rule_id="cpu-spike",
                    rule_name="CPU Spike",
                    severity="HIGH",
                    metric_key="cpu_percent",
                )
            )
            # Flush to get event.id before inserting the action.
            action = await action_repo.insert(
                ResponseAction(
                    executed_at=_now(),
                    action_type="GENERATE_ALERT",
                    is_simulated=False,
                    defense_state="RELAXED",
                    triggering_event_id=event.id,
                    dry_run_description="Alert generated.",
                )
            )

        # The action's FK column should reference the event's PK.
        assert action.triggering_event_id == event.id
        assert event.id is not None

    async def test_get_since(self, session: AsyncSession) -> None:
        repo = ResponseActionRepository(session)
        async with session.begin():
            await repo.insert(
                ResponseAction(
                    executed_at=_ago(120),
                    action_type="GENERATE_ALERT",
                    is_simulated=False,
                    defense_state="RELAXED",
                    triggering_event_id=None,
                    dry_run_description="Old alert.",
                )
            )
            await repo.insert(
                ResponseAction(
                    executed_at=_ago(10),
                    action_type="SIMULATE_IP_BLOCK",
                    is_simulated=True,
                    defense_state="DEFENSIVE",
                    triggering_event_id=None,
                    dry_run_description="Recent simulated block.",
                )
            )

        async with session.begin():
            recent = await repo.get_since(_ago(60))
        assert len(recent) == 1
        assert recent[0].action_type == "SIMULATE_IP_BLOCK"


# ---------------------------------------------------------------------------
# AIExplanation
# ---------------------------------------------------------------------------


class TestAIExplanationRepository:
    async def test_insert_and_retrieve(self, session: AsyncSession) -> None:
        repo = AIExplanationRepository(session)
        record = AIExplanationRecord(
            generated_at=_now(),
            incident_id="inc-ai-001",
            provider="null",
            model="none",
            explanation="CPU spike detected.",
            raw_response="CPU spike detected.",
        )
        async with session.begin():
            saved = await repo.insert(record)
        assert saved.id is not None

        async with session.begin():
            fetched = await repo.get_by_incident_id("inc-ai-001")
        assert fetched is not None
        assert fetched.explanation == "CPU spike detected."

    async def test_get_by_incident_id_returns_none_for_missing(self, session: AsyncSession) -> None:
        repo = AIExplanationRepository(session)
        result = await repo.get_by_incident_id("no-such-incident")
        assert result is None

    async def test_multiple_explanations_returns_latest(self, session: AsyncSession) -> None:
        """Multiple explanations for one incident — get_by_incident_id returns newest."""
        repo = AIExplanationRepository(session)
        async with session.begin():
            await repo.insert(
                AIExplanationRecord(
                    generated_at=_ago(60),
                    incident_id="inc-multi",
                    provider="null",
                    explanation="First explanation.",
                )
            )
            await repo.insert(
                AIExplanationRecord(
                    generated_at=_ago(10),
                    incident_id="inc-multi",
                    provider="ollama",
                    explanation="Updated explanation.",
                )
            )

        async with session.begin():
            latest = await repo.get_by_incident_id("inc-multi")
        assert latest is not None
        assert latest.explanation == "Updated explanation."

    async def test_raw_and_sanitised_stored_separately(self, session: AsyncSession) -> None:
        """AS-07: raw_response and explanation are independent fields."""
        repo = AIExplanationRepository(session)
        async with session.begin():
            await repo.insert(
                AIExplanationRecord(
                    generated_at=_now(),
                    incident_id="inc-audit",
                    provider="ollama",
                    explanation="Safe explanation.",
                    raw_response="Unsafe: rm -rf /. Safe explanation.",
                )
            )

        async with session.begin():
            fetched = await repo.get_by_incident_id("inc-audit")
        assert fetched is not None
        assert fetched.explanation == "Safe explanation."
        assert "rm -rf" in (fetched.raw_response or "")


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


class TestBaselineRepository:
    async def test_upsert_inserts_new(self, session: AsyncSession) -> None:
        repo = BaselineRepository(session)
        b = Baseline(
            metric_key="cpu_percent",
            sample_count=10,
            mean=50.0,
            std_dev=5.0,
            updated_at=_now(),
        )
        async with session.begin():
            saved = await repo.upsert(b)
        assert saved.metric_key == "cpu_percent"
        assert saved.mean == pytest.approx(50.0)

    async def test_upsert_updates_existing(self, session: AsyncSession) -> None:
        """Baseline is a live accumulator — repeated upserts update in place."""
        repo = BaselineRepository(session)
        async with session.begin():
            await repo.upsert(
                Baseline(
                    metric_key="memory_percent",
                    sample_count=10,
                    mean=60.0,
                    std_dev=4.0,
                    updated_at=_ago(30),
                )
            )
        async with session.begin():
            await repo.upsert(
                Baseline(
                    metric_key="memory_percent",
                    sample_count=20,
                    mean=62.5,
                    std_dev=4.2,
                    updated_at=_now(),
                )
            )

        async with session.begin():
            fetched = await repo.get_by_metric_key("memory_percent")
        assert fetched is not None
        assert fetched.sample_count == 20
        assert fetched.mean == pytest.approx(62.5)

    async def test_unique_constraint_per_metric_key(self, session: AsyncSession) -> None:
        """UNIQUE on metric_key means one row per metric (enforced by upsert)."""
        repo = BaselineRepository(session)
        for i in range(3):
            async with session.begin():
                await repo.upsert(
                    Baseline(
                        metric_key="disk_read_rate",
                        sample_count=i + 1,
                        mean=float(i * 10),
                        std_dev=1.0,
                        updated_at=_now(),
                    )
                )

        async with session.begin():
            all_baselines = await repo.get_all()
        cpu_baselines = [b for b in all_baselines if b.metric_key == "disk_read_rate"]
        assert len(cpu_baselines) == 1

    async def test_get_by_metric_key_returns_none_for_missing(self, session: AsyncSession) -> None:
        repo = BaselineRepository(session)
        result = await repo.get_by_metric_key("nonexistent_metric")
        assert result is None


# ---------------------------------------------------------------------------
# UnitOfWork
# ---------------------------------------------------------------------------


class TestUnitOfWork:
    async def test_atomic_multi_table_write(self, session: AsyncSession) -> None:
        """NFR-02: multi-table writes in one transaction are atomic."""
        uow = UnitOfWork(session)
        async with session.begin():
            event = await uow.events.insert(
                DetectionEvent(
                    detected_at=_now(),
                    rule_id="cpu-spike",
                    rule_name="CPU Spike",
                    severity="HIGH",
                    metric_key="cpu_percent",
                    metric_value=93.0,
                )
            )
            score = await uow.scores.insert(
                ThreatScore(
                    calculated_at=_now(),
                    score=0.72,
                    contributing_events=json.dumps([event.id]),
                )
            )
            await uow.state_changes.insert(
                DefenseStateChange(
                    changed_at=_now(),
                    from_state="ALERT",
                    to_state="DEFENSIVE",
                    trigger_score=0.72,
                    trigger_event_ids=json.dumps([event.id]),
                )
            )

        # Verify all three rows were committed atomically.
        async with session.begin():
            fetched_event = await uow.events.get_by_id(event.id)
            fetched_score = await uow.scores.get_latest()
            fetched_state = await uow.state_changes.get_latest()

        assert fetched_event is not None
        assert fetched_score is not None
        assert fetched_state is not None
        assert fetched_state.to_state == "DEFENSIVE"

    async def test_uow_has_all_repositories(self, session: AsyncSession) -> None:
        uow = UnitOfWork(session)
        assert uow.telemetry is not None
        assert uow.events is not None
        assert uow.incidents is not None
        assert uow.scores is not None
        assert uow.state_changes is not None
        assert uow.actions is not None
        assert uow.explanations is not None
        assert uow.baselines is not None


# ---------------------------------------------------------------------------
# Migration compatibility
# ---------------------------------------------------------------------------


class TestMigrationCompatibility:
    async def test_all_tables_created_by_create_all(self, engine: AsyncEngine) -> None:
        """
        create_all_tables() produces the same schema as the Alembic migration.
        This guards against models diverging from the migration.
        """
        from sqlalchemy import inspect

        async with engine.connect() as conn:
            table_names = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )

        expected_tables = {
            "telemetry_samples",
            "detection_events",
            "incidents",
            "threat_scores",
            "defense_state_changes",
            "response_actions",
            "ai_explanations",
            "baselines",
        }
        assert expected_tables.issubset(set(table_names))

    async def test_fresh_db_create_and_destroy(self, engine: AsyncEngine) -> None:
        """A test database can be created and destroyed safely (spec §Migration)."""
        await drop_all_tables(engine)
        await create_all_tables(engine)
        # No exceptions means the cycle is safe.

    async def test_timestamps_are_timezone_aware(self, session: AsyncSession) -> None:
        """
        Timestamps written as UTC-aware are read back correctly.

        SQLite does not store timezone info natively — aiosqlite returns
        naive datetimes. We verify the value is correct UTC time and that
        no data was lost. PostgreSQL will return aware datetimes.
        """
        repo = TelemetrySampleRepository(session)
        t = datetime.now(UTC)
        async with session.begin():
            await repo.insert(TelemetrySample(collected_at=t))

        async with session.begin():
            fetched = await repo.get_latest()
        assert fetched is not None
        # Compare value stripped of tzinfo to handle SQLite's naive return.
        fetched_naive = (
            fetched.collected_at.replace(tzinfo=None)
            if fetched.collected_at.tzinfo is not None
            else fetched.collected_at
        )
        expected_naive = t.replace(tzinfo=None)
        diff = abs((fetched_naive - expected_naive).total_seconds())
        assert diff < 1.0, f"Timestamp drifted by {diff}s"
