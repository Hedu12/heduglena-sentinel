"""
Restart stability of explanation triggering.

The security pipeline runs once (two attacks separated by recovery and the
reopen window). Explanations are then produced by one uninterrupted service,
and again by a service that is "restarted" (replaced by a fresh instance with
no memory) at many points, with and without redelivered decisions. The
persisted explanation records must be identical every time: the database, not
process memory, decides what is explained.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.adapters.fake import FakeLLMProvider
from core.config import Settings
from database.models import AIExplanationRecord
from explanation.service import ExplanationService
from models.enums import DefenseState
from response.service import ResponseService
from tests.response_helpers import database
from tests.threat_scenario import Scenario, play_attack
from threat.decision import Decision

SECOND_ATTACK = 800.0
SETTINGS = Settings()


@dataclass
class World:
    factory: async_sessionmaker[AsyncSession]
    decisions: list[Decision]


@pytest_asyncio.fixture()
async def world() -> AsyncIterator[World]:
    async with database() as factory:
        s = Scenario(factory)
        await play_attack(s)
        await play_attack(s, start=SECOND_ATTACK)
        response = ResponseService(SETTINGS, factory)
        await response.handle_all(s.result.decisions)
        yield World(factory, s.result.decisions)


def fresh_service(factory: async_sessionmaker[AsyncSession]) -> ExplanationService:
    """A new process: no memory of anything explained before."""
    return ExplanationService(
        SETTINGS,
        factory,
        provider=FakeLLMProvider(),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


async def feed(svc: ExplanationService, decisions: list[Decision]) -> None:
    for d in decisions:
        svc.observe(d)
        await svc.run_pending()


async def records(factory: async_sessionmaker[AsyncSession]) -> list[tuple[Any, ...]]:
    async with factory() as session:
        rows = (
            await session.execute(select(AIExplanationRecord).order_by(AIExplanationRecord.id))
        ).scalars()
        return [
            (
                r.incident_id,
                r.trigger,
                r.trigger_key,
                r.decision_at.replace(tzinfo=None) if r.decision_at else None,
                r.status,
                r.context_fingerprint,
            )
            for r in rows
        ]


async def clear(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session, session.begin():
        await session.execute(delete(AIExplanationRecord))


async def uninterrupted(w: World) -> list[tuple[Any, ...]]:
    await clear(w.factory)
    await feed(fresh_service(w.factory), w.decisions)
    return await records(w.factory)


def index_of(w: World, predicate: Any) -> int:
    return next(i for i, d in enumerate(w.decisions) if predicate(d))


def interesting_splits(w: World) -> list[int]:
    """Just before and just after every transition, plus points inside AGGRESSIVE."""
    splits: set[int] = set()
    for i, d in enumerate(w.decisions):
        if d.state_changed:
            splits.update({i, i + 1})
        if d.defense_state is DefenseState.AGGRESSIVE:
            splits.add(i)
    return sorted(s for s in splits if 0 < s < len(w.decisions))


class TestBeforeRestart:
    async def test_the_same_situation_always_yields_the_same_explanations(
        self, world: World
    ) -> None:
        first = await uninterrupted(world)
        second = await uninterrupted(world)
        assert first == second
        triggers = [r[1] for r in first]
        assert triggers.count("INCIDENT_CREATED") == 2  # one per incident
        assert "AGGRESSIVE_REFRESH" in triggers


class TestAfterRestart:
    async def test_a_restart_anywhere_changes_nothing(self, world: World) -> None:
        baseline = await uninterrupted(world)
        for split in interesting_splits(world):
            await clear(world.factory)
            await feed(fresh_service(world.factory), world.decisions[:split])
            await feed(fresh_service(world.factory), world.decisions[split:])
            assert await records(world.factory) == baseline, f"restart before decision {split}"

    async def test_redelivered_decisions_after_a_restart_explain_nothing_again(
        self, world: World
    ) -> None:
        baseline = await uninterrupted(world)
        for split in interesting_splits(world)[::3]:
            await clear(world.factory)
            await feed(fresh_service(world.factory), world.decisions[:split])
            overlap = max(0, split - 5)
            await feed(fresh_service(world.factory), world.decisions[overlap:])
            assert await records(world.factory) == baseline, f"overlap restart at {split}"

    async def test_replaying_everything_after_a_restart_adds_no_explanation(
        self, world: World
    ) -> None:
        baseline = await uninterrupted(world)
        replay = fresh_service(world.factory)
        await feed(replay, world.decisions)
        assert await records(world.factory) == baseline
        assert replay.stats.recorded == 0


class TestRecoveryAfterRestart:
    async def test_a_recovery_right_after_a_restart_is_still_explained(self, world: World) -> None:
        baseline = await uninterrupted(world)
        recovery = index_of(
            world,
            lambda d: d.state_changed and d.defense_state is DefenseState.RELAXED,
        )
        recovered = world.decisions[recovery]
        assert recovered.situation_id is None  # the decision itself no longer names it

        await clear(world.factory)
        await feed(fresh_service(world.factory), world.decisions[:recovery])
        restarted = fresh_service(world.factory)  # knows nothing about the situation
        await feed(restarted, [recovered])

        rows = await records(world.factory)
        key = f"STATE_TRANSITION:{recovered.transition_id}"
        assert ("SIT-1", "STATE_TRANSITION", key) in {r[:3] for r in rows}
        assert rows == baseline[: len(rows)]


class TestNewIncidentAfterRestart:
    async def test_a_new_incident_after_a_restart_gets_its_initial_explanation(
        self, world: World
    ) -> None:
        openings = [i for i, d in enumerate(world.decisions) if d.new_situation]
        assert len(openings) == 2
        second = openings[1]
        opening = world.decisions[second]
        await clear(world.factory)
        await feed(fresh_service(world.factory), world.decisions[:second])
        await feed(fresh_service(world.factory), world.decisions[second:])
        rows = await records(world.factory)
        created = [r for r in rows if r[1] == "INCIDENT_CREATED"]
        assert [r[0] for r in created] == ["SIT-1", f"SIT-{opening.situation_id}"]
        assert created[1][3] == opening.calculated_at.replace(tzinfo=None)


@pytest.mark.parametrize("restarts", [1, 5])
async def test_the_database_rejects_a_second_record_for_the_same_trigger(
    world: World, restarts: int
) -> None:
    await uninterrupted(world)
    before = await records(world.factory)
    for _ in range(restarts):
        svc = fresh_service(world.factory)
        await feed(svc, world.decisions[:10])
    assert await records(world.factory) == before
