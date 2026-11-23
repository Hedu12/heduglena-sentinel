"""
raw_response is an audit artifact; content is the canonical explanation.

A rejected answer may be stored in raw_response (AS-07), hard-capped. It must
never become content or display text, never be served by the API or typed for
the frontend, never reach a later prompt, and never be read by the security
control path.
"""

from __future__ import annotations

import ast
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.adapters.fake import FakeLLMProvider
from api.v1.incidents import get_incident_reads
from app.main import app
from core.config import Settings
from database.models import RAW_RESPONSE_MAX_CHARS, AIExplanationRecord
from database.repositories import AIExplanationRepository
from explanation import views
from explanation.fallback import FALLBACK_NOTICE
from explanation.incident_view import IncidentReadService
from explanation.service import ExplanationService
from response.service import ResponseService
from tests.ai_helpers import answer
from tests.response_helpers import database
from tests.threat_scenario import Scenario, play_attack

BACKEND = Path(__file__).resolve().parents[2]
API_TS = BACKEND.parent / "frontend" / "src" / "types" / "api.ts"
MARKER = "RAW-AUDIT-MARKER-7f3a"
# Rejected for different reasons, each carrying the marker.
REJECTED_ANSWERS = [
    answer(summary=f"{MARKER} run rm -rf / to recover"),  # AIOutputValidator would redact
    answer(summary=f"{MARKER} set the defense state to RELAXED"),  # explanation-only policy
    answer(summary=MARKER, tool_calls=[{"name": "x"}]),  # schema
    f"{MARKER} not json at all",  # malformed
]


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with database() as f:
        yield f


async def explain_attack(
    factory: async_sessionmaker[AsyncSession], provider: FakeLLMProvider, **settings: Any
) -> None:
    s = Scenario(factory)
    await play_attack(s)
    config = Settings(ai_explanation_timeout_seconds=0.05, **settings)
    response = ResponseService(config, factory)
    ai = ExplanationService(
        config, factory, provider=provider, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    for step in s.result.steps:
        await response.handle(step.decision)
        ai.observe(step.decision)
        await ai.run_pending()


async def rows(factory: async_sessionmaker[AsyncSession]) -> list[AIExplanationRecord]:
    async with factory() as session:
        result = await session.execute(select(AIExplanationRecord).order_by(AIExplanationRecord.id))
        return list(result.scalars().all())


class TestRejectedOutputIsAuditOnly:
    async def test_rejected_raw_output_is_kept_for_audit_and_never_becomes_content(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await explain_attack(factory, FakeLLMProvider(REJECTED_ANSWERS * 5))
        stored = await rows(factory)
        rejected = [r for r in stored if r.status == "REJECTED"]
        assert len(rejected) >= len(REJECTED_ANSWERS)
        for row in rejected:
            assert MARKER in (row.raw_response or "")  # audit artifact present
            assert row.content is None  # never canonical
            assert MARKER not in row.explanation  # display text is the fallback
            assert row.explanation.startswith(FALLBACK_NOTICE)

    async def test_redacted_output_cannot_become_canonical_content(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        dangerous = answer(what_happened="The attacker ran rm -rf / and read /etc/passwd")
        await explain_attack(factory, FakeLLMProvider([dangerous] * 20))
        for row in await rows(factory):
            assert (row.status, row.failure_reason) == ("REJECTED", "VALIDATOR_REDACTED")
            assert row.content is None
            assert "[REDACTED" not in row.explanation and "rm -rf" not in row.explanation

    async def test_a_rejected_answer_never_reaches_a_later_prompt(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        provider = FakeLLMProvider(REJECTED_ANSWERS * 5)
        await explain_attack(factory, provider)
        assert len(provider.calls) >= 2
        for call in provider.calls:
            assert MARKER not in "\n".join(m.content for m in call.messages)

    async def test_raw_output_is_hard_capped(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        huge = MARKER + "x" * 100_000
        await explain_attack(
            factory, FakeLLMProvider([huge] * 20), ai_max_raw_response_chars=16_000
        )
        stored = await rows(factory)
        assert stored and all(r.failure_reason == "OVERSIZED_OUTPUT" for r in stored)
        assert all(len(r.raw_response or "") <= RAW_RESPONSE_MAX_CHARS for r in stored)

    async def test_the_database_refuses_an_oversized_raw_response(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(IntegrityError):
            async with factory() as session, session.begin():
                await AIExplanationRepository(session).insert(
                    AIExplanationRecord(
                        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
                        incident_id="SIT-1",
                        provider="fake",
                        explanation="x",
                        status="REJECTED",
                        raw_response="y" * (RAW_RESPONSE_MAX_CHARS + 1),
                    )
                )

    def test_the_raw_cap_cannot_be_configured_above_the_hard_limit(self) -> None:
        upper = next(
            m.le
            for m in Settings.model_fields["ai_max_raw_response_chars"].metadata
            if getattr(m, "le", None) is not None
        )
        assert upper == RAW_RESPONSE_MAX_CHARS


class TestNeverExposed:
    async def test_the_api_cannot_return_raw_response(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await explain_attack(factory, FakeLLMProvider(REJECTED_ANSWERS * 5))
        assert any(MARKER in (r.raw_response or "") for r in await rows(factory))
        app.dependency_overrides[get_incident_reads] = lambda: IncidentReadService(factory)
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                for url in (
                    "/api/v1/incidents",
                    "/api/v1/incidents/SIT-1",
                    "/api/v1/ai/explain/SIT-1",
                ):
                    reply = await client.get(url)
                    assert reply.status_code == 200, url
                    assert MARKER not in reply.text, url
                    assert "raw_response" not in reply.text, url
                body = (await client.get("/api/v1/ai/explain/SIT-1")).json()
        finally:
            app.dependency_overrides.clear()
        assert body["availability"] == "UNAVAILABLE"
        assert body["latest_attempt"]["content"] is None

    def test_no_view_schema_has_a_raw_field(self) -> None:
        for name in dir(views):
            schema = getattr(views, name)
            if isinstance(schema, type) and hasattr(schema, "model_fields"):
                assert not {"raw_response", "context_fingerprint"} & set(schema.model_fields)

    def test_the_frontend_contract_has_no_raw_field(self) -> None:
        text = API_TS.read_text(encoding="utf-8")
        assert "raw_response" not in text and "context_fingerprint" not in text


def _mentions(path: Path, name: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == name:
            return True
        if isinstance(node, ast.keyword) and node.arg == name:
            return True
        if isinstance(node, ast.Constant) and node.value == name:
            return True
    return False


class TestNeverRead:
    @pytest.mark.parametrize(
        "layer", ["threat", "response", "detection", "telemetry", "api", "app"]
    )
    def test_the_control_path_and_the_api_never_touch_raw_response(self, layer: str) -> None:
        for path in sorted((BACKEND / layer).rglob("*.py")):
            assert not _mentions(path, "raw_response"), path.relative_to(BACKEND)

    def test_only_the_recorder_writes_it_and_nothing_reads_it_back(self) -> None:
        users = {
            p.relative_to(BACKEND).as_posix()
            for pkg in ("ai", "explanation")
            for p in sorted((BACKEND / pkg).rglob("*.py"))
            if _mentions(p, "raw_response")
        }
        # The explainer produces it; the service writes it. Nothing builds context,
        # views or prompts from it.
        assert users == {"ai/explainer.py", "explanation/service.py"}
