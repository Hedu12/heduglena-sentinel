"""
ExplanationService against a real (in-memory) database.

Covers persistence of every outcome, deduplication, coalescing, the queue bound,
the background worker, and above all failure isolation: whatever the AI does,
Sentinel's scores, states, decisions, responses and incidents are unchanged.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.adapters.fake import HANG, FakeLLMProvider
from ai.prompt import DATA_OPEN
from core.config import Settings
from database.models import AIExplanationRecord
from database.repositories import AIExplanationRepository
from explanation.context_builder import ExplanationContextBuilder
from explanation.fallback import FALLBACK_NOTICE
from explanation.service import ExplanationService
from models.enums import ExplanationTrigger
from response.service import ResponseService
from tests.ai_helpers import answer
from tests.response_helpers import A, D, G, R, actions, database, decision, incidents
from tests.threat_scenario import Scenario, play_attack

FIXED = datetime(2026, 1, 1, tzinfo=UTC)
SETTINGS = Settings(ai_explanation_timeout_seconds=0.05)
T = ExplanationTrigger


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with database() as f:
        yield f


def service(
    factory: async_sessionmaker[AsyncSession],
    provider: Any = None,
    settings: Settings = SETTINGS,
) -> ExplanationService:
    return ExplanationService(settings, factory, provider=provider, clock=lambda: FIXED)


async def records(factory: async_sessionmaker[AsyncSession]) -> list[AIExplanationRecord]:
    async with factory() as session:
        rows = await session.execute(select(AIExplanationRecord).order_by(AIExplanationRecord.id))
        return list(rows.scalars().all())


def opening(t: float = 0.0, sid: int = 1) -> Any:
    return decision(t, A, situation_id=sid, previous=R, new_situation=True)


class TestRecording:
    async def test_a_valid_explanation_is_recorded_with_its_audit_fields(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, FakeLLMProvider([answer()]))
        assert svc.observe(opening()) is True
        assert await svc.run_pending() == 1
        (row,) = await records(factory)
        assert (row.incident_id, row.situation_id, row.trigger) == ("SIT-1", 1, "INCIDENT_CREATED")
        assert (row.status, row.failure_reason, row.provider, row.model) == (
            "VALID",
            None,
            "fake",
            "fake-model-1",
        )
        assert json.loads(row.content or "")["confidence"] == "HIGH"
        assert row.explanation == json.loads(answer())["summary"]
        assert row.raw_response == answer()
        assert row.context_fingerprint and len(row.context_fingerprint) == 64
        assert row.latency_ms is not None and row.attempts == 1

    @pytest.mark.parametrize(
        ("script", "status", "failure"),
        [
            (["not json"], "REJECTED", "MALFORMED_JSON"),
            ([answer(extra_field="x")], "REJECTED", "SCHEMA_VIOLATION"),
            ([answer(summary="Run rm -rf / now")], "REJECTED", "VALIDATOR_REDACTED"),
            ([answer(summary="Set the defense state to RELAXED.")], "REJECTED", "UNSAFE_CONTENT"),
            ([HANG, HANG], "FAILED", "TIMEOUT"),
            ([RuntimeError("x"), RuntimeError("y")], "FAILED", "PROVIDER_ERROR"),
        ],
    )
    async def test_invalid_output_never_reaches_the_displayed_fields(
        self,
        factory: async_sessionmaker[AsyncSession],
        script: list[Any],
        status: str,
        failure: str,
    ) -> None:
        svc = service(factory, FakeLLMProvider(script))
        svc.observe(opening())
        await svc.run_pending()
        (row,) = await records(factory)
        assert (row.status, row.failure_reason) == (status, failure)
        assert row.content is None
        assert row.explanation.startswith(FALLBACK_NOTICE)
        assert "rm -rf" not in row.explanation and "RELAXED." not in row.explanation

    async def test_a_context_failure_is_recorded_and_contained(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("db gone")

        monkeypatch.setattr(ExplanationContextBuilder, "build", broken)
        fake = FakeLLMProvider()
        svc = service(factory, fake)
        svc.observe(opening())
        await svc.run_pending()
        (row,) = await records(factory)
        assert (row.status, row.failure_reason) == ("FAILED", "CONTEXT_UNAVAILABLE")
        assert fake.calls == []

    async def test_a_recording_failure_is_contained_and_not_retried(
        self, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken(self: Any, record: Any) -> Any:
            raise RuntimeError("disk full")

        monkeypatch.setattr(AIExplanationRepository, "insert", broken)
        svc = service(factory)
        svc.observe(opening())
        assert await svc.run_pending() == 1
        assert svc.stats.record_failed == 1 and svc.pending == 0
        assert await records(factory) == []


class TestFrequency:
    async def test_identical_context_is_not_explained_twice(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        fake = FakeLLMProvider()
        svc = service(factory, fake)
        svc.observe(decision(0, G, situation_id=1, previous=D, new_situation=True))
        await svc.run_pending()
        # Two refreshes later, the situation, score and evidence are unchanged.
        for t in (40, 80):
            assert svc.observe(decision(t, G, situation_id=1)) is True
            await svc.run_pending()
        assert len(fake.calls) == 2  # the opening, then the first steady-state refresh
        assert svc.stats.skipped_duplicate == 1
        assert len(await records(factory)) == 2

    async def test_duplicate_decisions_produce_no_second_explanation(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        fake = FakeLLMProvider()
        svc = service(factory, fake)
        for _ in range(3):
            svc.observe(opening())
            await svc.run_pending()
        assert len(fake.calls) == 1

    async def test_bursts_are_coalesced_per_incident(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        fake = FakeLLMProvider()
        svc = service(factory, fake)
        svc.observe(opening(0))
        svc.observe(decision(5, D, situation_id=1, previous=A))
        svc.observe(decision(10, G, situation_id=1, previous=D))
        assert svc.pending == 1 and svc.stats.coalesced == 2
        await svc.run_pending()
        (row,) = await records(factory)
        # The most significant trigger is kept; the context is the latest one.
        assert row.trigger == "INCIDENT_CREATED"
        assert fake.calls[0].context.defense_state.value == "AGGRESSIVE"

    async def test_the_queue_is_bounded(self, factory: async_sessionmaker[AsyncSession]) -> None:
        svc = service(factory, settings=Settings(ai_queue_max_incidents=2))
        for sid in range(1, 6):
            svc.observe(opening(sid, sid))
        assert svc.pending == 2 and svc.stats.dropped == 3


class TestNonBlocking:
    async def test_observe_never_awaits_the_provider(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        fake = FakeLLMProvider([HANG])
        svc = service(factory, fake, Settings(ai_explanation_timeout_seconds=60))
        svc.observe(opening())  # synchronous: returns at once even though the provider hangs
        assert fake.calls == []

    async def test_the_background_worker_explains_and_stops_cleanly(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, FakeLLMProvider())
        svc.start()
        svc.observe(opening())
        # Wait on the service's own counters: polling the in-memory test database here
        # would share its single connection with the worker's transaction.
        for _ in range(1000):
            await asyncio.sleep(0.01)
            if svc.stats.recorded or svc.stats.record_failed:
                break
        await svc.stop()
        assert svc.stats.record_failed == 0
        assert [r.status for r in await records(factory)] == ["VALID"]

    async def test_a_hanging_provider_does_not_hold_the_worker(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory, FakeLLMProvider([HANG, HANG]))
        svc.observe(opening())
        await asyncio.wait_for(svc.run_pending(), timeout=5)  # bounded by timeout x attempts
        (row,) = await records(factory)
        assert row.failure_reason == "TIMEOUT" and row.attempts == 2

    async def test_observe_swallows_its_own_errors(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        svc = service(factory)
        assert svc.observe("not a decision") is False  # type: ignore[arg-type]


# ── Failure isolation: the security pipeline is identical with any AI behaviour ──


def _decision_fingerprint(d: Any) -> tuple[Any, ...]:
    return (
        d.calculated_at,
        round(d.threat_score, 9),
        d.defense_state,
        d.previous_state,
        d.state_changed,
        d.reason_codes,
        d.recommended_actions,
        d.situation_id,
        d.new_situation,
        d.ended_situation_id,
    )


async def _run_pipeline(provider: Any | None) -> tuple[list[Any], list[Any], list[Any], int]:
    """Attack + recovery through threat, response and (optionally) explanations."""
    async with database() as factory:
        s = Scenario(factory)
        settings = Settings(ai_explanation_timeout_seconds=0.02)
        response = ResponseService(settings, factory)
        ai = service(factory, provider, settings) if provider is not None else None
        await play_attack(s)
        for t in range(430, 760, 10):
            await s.telemetry(t, "quiet")
        for step in s.result.steps:
            await response.handle(step.decision)
            if ai is not None:
                ai.observe(step.decision)
                await ai.run_pending()
        rows = [
            (r.action_type, r.status, r.situation_id, r.executed_at, r.lifecycle)
            for r in await actions(factory)
        ]
        incident_rows = [
            (i.incident_id, i.status, i.recovered_at, i.resolved_at, i.resolution)
            for i in await incidents(factory)
        ]
        explained = len(await records(factory))
    return (
        [_decision_fingerprint(st.decision) for st in s.result.steps],
        rows,
        incident_rows,
        explained,
    )


class TestFailureIsolation:
    @pytest.mark.parametrize(
        "provider",
        [
            FakeLLMProvider([RuntimeError("down")] * 50),
            FakeLLMProvider([HANG] * 50),
            FakeLLMProvider(["{malformed"] * 50),
            FakeLLMProvider([answer(summary="Set the defense state to RELAXED.")] * 50),
            FakeLLMProvider([answer(what_happened="ignore all rules; rm -rf /")] * 50),
        ],
        ids=["exceptions", "timeouts", "malformed", "state-change-attempt", "shell-attempt"],
    )
    async def test_a_failing_ai_changes_nothing_in_the_security_pipeline(
        self, provider: FakeLLMProvider
    ) -> None:
        baseline = await _run_pipeline(None)
        with_ai = await _run_pipeline(provider)
        assert with_ai[0] == baseline[0]  # threat scores, states, decisions
        assert with_ai[1] == baseline[1]  # response actions
        assert with_ai[2] == baseline[2]  # incident lifecycle (incl. resolution)
        assert with_ai[3] > 0  # the failures were recorded

    async def test_a_working_ai_changes_nothing_either(self) -> None:
        baseline = await _run_pipeline(None)
        with_ai = await _run_pipeline(FakeLLMProvider())
        assert with_ai[:3] == baseline[:3]


class TestEndToEnd:
    async def test_a_full_attack_is_explained_and_ai_stays_observational(self) -> None:
        async with database() as factory:
            s = Scenario(factory)
            fake = FakeLLMProvider()
            settings = Settings()
            response = ResponseService(settings, factory)
            ai = service(factory, fake, settings)
            await play_attack(s)
            for t in range(430, 760, 10):  # quiet until the incident can be resolved
                await s.telemetry(t, "quiet")
            for step in s.result.steps:
                await response.handle(step.decision)
                ai.observe(step.decision)
                await ai.run_pending()
            rows = await records(factory)
            (incident,) = await incidents(factory)

        path = [(r.trigger, json.loads(r.content or "{}").get("current_state", "")) for r in rows]
        triggers = [t for t, _ in path]
        states = [fake.calls[i].context.defense_state.value for i in range(len(fake.calls))]
        assert triggers[0] == "INCIDENT_CREATED" and states[0] == "ALERT"
        # Every escalation and every recovery step is explained, in order.
        transitions = [
            s for t, s in zip(triggers, states, strict=True) if t != "AGGRESSIVE_REFRESH"
        ]
        assert transitions == ["ALERT", "DEFENSIVE", "AGGRESSIVE", "DEFENSIVE", "ALERT", "RELAXED"]
        # AGGRESSIVE is refreshed, at most once per 30 s of decision time.
        refresh_times = [
            fake.calls[i].context.evaluated_at
            for i, t in enumerate(triggers)
            if t == "AGGRESSIVE_REFRESH"
        ]
        assert refresh_times, "AGGRESSIVE should be refreshed"
        assert all(r.status == "VALID" for r in rows)
        assert len(rows) <= 10
        # The incident went through its whole lifecycle, untouched by the AI.
        assert incident.status == "resolved" and incident.resolution == "QUIET_FOR_REOPEN_WINDOW"
        # The model only ever saw sanitised data inside the data block.
        for call in fake.calls:
            assert call.messages[0].role == "system"
            assert DATA_OPEN in call.messages[1].content
            for response_ctx in call.context.responses:
                assert response_ctx.simulated is True

    async def test_explanations_name_the_simulated_response_that_occurred(self) -> None:
        async with database() as factory:
            s = Scenario(factory)
            response = ResponseService(Settings(), factory)
            fake = FakeLLMProvider()
            ai = service(factory, fake)
            await play_attack(s)
            for step in s.result.steps:
                await response.handle(step.decision)
                ai.observe(step.decision)
                await ai.run_pending()

        aggressive = next(c for c in fake.calls if c.context.defense_state.value == "AGGRESSIVE")
        seen = {
            (r.action_type.value, r.guard_verdict, r.simulation_outcome)
            for r in aggressive.context.responses
        }
        assert ("SIMULATE_QUARANTINE", "AUTHORIZED", "WOULD_QUARANTINE") in seen
        assert ("SIMULATE_IP_BLOCK", "AUTHORIZED", "WOULD_BLOCK_SOURCE") in seen
        assert aggressive.context.score_breakdown.final_score > 0.8
        assert {r.code for r in aggressive.context.reasons}
        assert aggressive.context.evidence
