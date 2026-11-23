"""
Read-only incident and explanation API (httpx.AsyncClient, in-memory SQLite).

The API exposes what the dashboard needs and nothing internal: no scope,
once or idempotency keys, lifecycle or parameter JSON, raw model output,
fingerprints, untrusted labels or configuration.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.adapters.fake import FakeLLMProvider
from api.v1.incidents import get_incident_reads, router
from app.main import app
from core.config import Settings
from explanation.incident_view import IncidentReadService
from explanation.service import ExplanationService
from response.service import ResponseService
from tests.ai_helpers import answer
from tests.response_helpers import database
from tests.threat_scenario import Scenario, play_attack

INTERNAL_KEYS = {
    "scope_key",
    "once_key",
    "idempotency_key",
    "lifecycle",
    "parameters",
    "raw_response",
    "context_fingerprint",
    "situation_id",
    "triggering_event_id",
    "event_data",
    "untrusted_subject",
    "openai_api_key",
    "database_url",
}


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_keys(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(_keys(v) for v in value)) if value else set()
    return set()


@pytest_asyncio.fixture()
async def factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with database() as f:
        yield f


@pytest_asyncio.fixture()
async def client(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[httpx.AsyncClient]:
    app.dependency_overrides[get_incident_reads] = lambda: IncidentReadService(factory)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()


async def attack(
    factory: async_sessionmaker[AsyncSession], provider: Any = None, *, quiet_until: int = 0
) -> None:
    s = Scenario(factory)
    settings = Settings(ai_explanation_timeout_seconds=0.02)
    response = ResponseService(settings, factory)
    ai = ExplanationService(
        settings,
        factory,
        provider=provider or FakeLLMProvider(),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    await play_attack(s)
    for t in range(430, quiet_until, 10):
        await s.telemetry(t, "quiet")
    for step in s.result.steps:
        await response.handle(step.decision)
        ai.observe(step.decision)
        await ai.run_pending()


class TestIncidents:
    async def test_an_empty_database_lists_no_incidents(self, client: httpx.AsyncClient) -> None:
        reply = await client.get("/api/v1/incidents")
        assert reply.status_code == 200 and reply.json() == []

    async def test_the_incident_list(
        self, client: httpx.AsyncClient, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await attack(factory, quiet_until=760)
        (item,) = (await client.get("/api/v1/incidents")).json()
        assert item["incident_id"] == "SIT-1"
        assert item["status"] == "resolved"
        assert item["resolution"] == "QUIET_FOR_REOPEN_WINDOW"
        assert item["recovered_at"] and item["resolved_at"]

    async def test_the_incident_detail_has_everything_the_dashboard_needs(
        self, client: httpx.AsyncClient, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await attack(factory)
        reply = await client.get("/api/v1/incidents/SIT-1")
        assert reply.status_code == 200
        body = reply.json()
        assert body["incident"]["status"] == "open"
        assert body["current_score"]["score"] >= 0
        assert {"severity", "correlation", "decay", "reasons"} <= set(body["current_score"])
        assert body["evidence"] and body["evidence"][0]["rule_name"]
        path = [(t["from_state"], t["to_state"]) for t in body["transitions"]]
        assert path[:3] == [
            ("RELAXED", "ALERT"),
            ("ALERT", "DEFENSIVE"),
            ("DEFENSIVE", "AGGRESSIVE"),
        ]
        simulated = {s["action_type"]: s for s in body["simulations"]}
        quarantine = simulated["SIMULATE_QUARANTINE"]
        assert quarantine["guard_verdict"] == "AUTHORIZED"
        assert quarantine["simulation_outcome"] == "WOULD_QUARANTINE"
        assert all(s["is_simulated"] for s in body["simulations"])
        ai = body["ai"]
        assert ai["availability"] == "AVAILABLE"
        assert ai["explanation"]["content"]["summary"]
        assert ai["explanation"]["generated_at"] and ai["explanation"]["trigger"]
        assert ai["fallback_text"].startswith("AI explanation unavailable")

    async def test_no_internal_field_is_exposed(
        self, client: httpx.AsyncClient, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await attack(factory)
        for url in ("/api/v1/incidents", "/api/v1/incidents/SIT-1", "/api/v1/ai/explain/SIT-1"):
            body = (await client.get(url)).json()
            assert not _keys(body) & INTERNAL_KEYS, url

    @pytest.mark.parametrize("incident_id", ["SIT-999", "SIT-2"])
    async def test_an_unknown_incident_is_404(
        self, client: httpx.AsyncClient, incident_id: str
    ) -> None:
        assert (await client.get(f"/api/v1/incidents/{incident_id}")).status_code == 404
        assert (await client.get(f"/api/v1/ai/explain/{incident_id}")).status_code == 404

    @pytest.mark.parametrize(
        "incident_id", ["1", "SIT-", "SIT-1'%20OR%201=1", "s1:SIMULATE_IP_BLOCK", "SIT-" + "9" * 20]
    )
    async def test_a_malformed_incident_id_is_422(
        self, client: httpx.AsyncClient, incident_id: str
    ) -> None:
        assert (await client.get(f"/api/v1/incidents/{incident_id}")).status_code == 422

    async def test_the_list_limit_is_validated(self, client: httpx.AsyncClient) -> None:
        assert (await client.get("/api/v1/incidents?limit=0")).status_code == 422
        assert (await client.get("/api/v1/incidents?limit=1000")).status_code == 422


class TestExplanationAvailability:
    async def test_pending_before_any_attempt(
        self, client: httpx.AsyncClient, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        s = Scenario(factory)
        await play_attack(s)
        response = ResponseService(Settings(), factory)
        for step in s.result.steps:
            await response.handle(step.decision)
        body = (await client.get("/api/v1/ai/explain/SIT-1")).json()
        assert body["availability"] == "PENDING"
        assert body["explanation"] is None and body["latest_attempt"] is None
        assert "Incident ID: SIT-1" in body["fallback_text"]

    async def test_unavailable_when_every_attempt_failed(
        self, client: httpx.AsyncClient, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        dangerous = answer(summary="Run rm -rf / now")
        await attack(factory, FakeLLMProvider([dangerous] * 20))
        body = (await client.get("/api/v1/ai/explain/SIT-1")).json()
        assert body["availability"] == "UNAVAILABLE"
        assert body["explanation"] is None
        attempt = body["latest_attempt"]
        assert attempt["status"] == "REJECTED"
        assert attempt["failure_reason"] == "VALIDATOR_REDACTED"
        assert attempt["content"] is None
        assert "rm -rf" not in json.dumps(body)

    async def test_ai_status_reports_the_provider_without_configuration(
        self, client: httpx.AsyncClient
    ) -> None:
        body = (await client.get("/api/v1/ai/status")).json()
        assert body == {
            "provider": "null",
            "language_model_configured": False,
            "explanation_only": True,
        }


def test_every_incident_and_ai_route_is_read_only() -> None:
    routes = [r for r in router.routes if isinstance(r, APIRoute)]
    assert routes
    for route in routes:
        assert route.methods == {"GET"}, route.path
