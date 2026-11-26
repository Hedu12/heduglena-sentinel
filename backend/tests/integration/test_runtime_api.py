"""
Runtime API: health, status, runtime, state, score, telemetry, events, actions,
incidents, demo endpoints, the live WebSocket, and the real application lifespan.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.websockets import WebSocketDisconnect

import app.main as main
from api.v1.incidents import get_incident_reads
from api.v1.runtime import get_runtime_reads
from app.main import app
from app.runtime import SentinelRuntime
from core.config import settings
from core.live import LiveHub, LiveMessageType
from core.runtime_views import RuntimeReadService
from explanation.incident_view import IncidentReadService
from tests.runtime_helpers import FakeClock, build, cycles, fresh_database, play, quiet_settings

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
    "telemetry_sample_id",
    "event_data",
    "raw_json",
    "openai_api_key",
    "database_url",
    "content",
    "prompt",
}


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_keys(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(_keys(v) for v in value)) if value else set()
    return set()


@pytest_asyncio.fixture()
async def factory(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async with fresh_database(tmp_path) as f:
        yield f


@pytest_asyncio.fixture()
async def runtime(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[SentinelRuntime, FakeClock]]:
    clock = FakeClock()
    rt = build(factory, clock)
    await rt.start(monitor=False)
    app.state.runtime = rt
    try:
        yield rt, clock
    finally:
        app.state.runtime = None
        await rt.stop()


@pytest_asyncio.fixture()
async def client(factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[httpx.AsyncClient]:
    app.dependency_overrides[get_runtime_reads] = lambda: RuntimeReadService(factory)
    app.dependency_overrides[get_incident_reads] = lambda: IncidentReadService(factory)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()


# ── Read endpoints ─────────────────────────────────────────────────────────────


class TestReadEndpoints:
    async def test_health_is_degraded_without_a_running_runtime(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "degraded", "service": "sentinel", "version": "0.1.0"}

    async def test_runtime_routes_answer_503_before_startup(
        self, client: httpx.AsyncClient
    ) -> None:
        assert (await client.get("/api/v1/runtime")).status_code == 503
        assert (await client.get("/api/v1/status")).status_code == 503

    async def test_a_fresh_database_answers_empty_or_404(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        assert (await client.get("/api/v1/status")).status_code == 503  # no decision yet
        assert (await client.get("/api/v1/score/current")).status_code == 404
        assert (await client.get("/api/v1/telemetry/latest")).status_code == 404
        assert (await client.get("/api/v1/events")).json() == []
        assert (await client.get("/api/v1/actions")).json() == []
        state = (await client.get("/api/v1/state/current")).json()
        assert state == {
            "current_state": "RELAXED",
            "since": None,
            "threat_score_at_transition": None,
        }

    async def test_the_running_pipeline_is_observable(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        rt, clock = runtime
        await cycles(rt, clock, 2)
        await play(rt, "critical")

        status = (await client.get("/api/v1/status")).json()
        assert status["defense_state"] == "AGGRESSIVE" and 0.0 <= status["threat_score"] <= 1.0
        assert (await client.get("/api/v1/state/current")).json()["current_state"] == "AGGRESSIVE"
        assert 0.0 <= (await client.get("/api/v1/score/current")).json()["score"] <= 1.0
        assert (await client.get("/api/v1/telemetry/latest")).json()["cpu_percent"] == 20.0

        events = (await client.get("/api/v1/events?limit=5")).json()
        assert 0 < len(events) <= 5 and all(e["is_synthetic"] for e in events)

        acts = (await client.get("/api/v1/actions")).json()
        assert acts and all(a["is_simulated"] for a in acts)
        assert {a["incident_id"] for a in acts} - {None} == {"SIT-1"}
        assert "SIMULATE_QUARANTINE" in {a["action_type"] for a in acts}

        incidents = (await client.get("/api/v1/incidents")).json()
        assert [i["incident_id"] for i in incidents] == ["SIT-1"]

        view = (await client.get("/api/v1/runtime")).json()
        assert view["decisions"] >= 13 and view["synthetic_events"] == 11
        assert view["last_demo_run"]["status"] == "completed"
        assert view["demo_running"] is None

    async def test_no_endpoint_exposes_internal_fields(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        rt, clock = runtime
        await cycles(rt, clock, 1)
        await play(rt, "critical")
        for path in (
            "/api/v1/status",
            "/api/v1/runtime",
            "/api/v1/state/current",
            "/api/v1/score/current",
            "/api/v1/telemetry/latest",
            "/api/v1/events",
            "/api/v1/actions",
        ):
            body = (await client.get(path)).json()
            assert not _keys(body) & INTERNAL_KEYS, path

    async def test_limits_are_validated(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        for bad in ("0", "201", "abc", "-1"):
            assert (await client.get(f"/api/v1/events?limit={bad}")).status_code == 422
            assert (await client.get(f"/api/v1/actions?limit={bad}")).status_code == 422


# ── Demo endpoints ─────────────────────────────────────────────────────────────


class TestDemoEndpoints:
    async def test_injection_goes_through_detection(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        response = await client.post(
            "/api/v1/demo/inject", json={"event_type": "auth_failure", "count": 5}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["injected"] == 5 and len(body["event_ids"]) == 1
        events = (await client.get("/api/v1/events")).json()
        assert [e["id"] for e in events] == body["event_ids"] and events[0]["is_synthetic"]

    @pytest.mark.parametrize(
        "payload",
        [
            {"event_type": "rm_rf"},
            {"event_type": "cpu_spike"},
            {"event_type": "auth_failure", "count": 0},
            {"event_type": "auth_failure", "count": 21},
            {"event_type": "auth_failure", "command": "whoami"},
            {},
        ],
    )
    async def test_invalid_injections_are_refused(
        self,
        client: httpx.AsyncClient,
        runtime: tuple[SentinelRuntime, FakeClock],
        payload: dict[str, Any],
    ) -> None:
        assert (await client.post("/api/v1/demo/inject", json=payload)).status_code == 422

    async def test_scenarios_start_once_at_a_time(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        rt, _ = runtime
        listed = (await client.get("/api/v1/demo/scenarios")).json()
        assert [s["name"] for s in listed] == ["normal", "suspicious", "critical"]
        assert (await client.post("/api/v1/demo/scenario/unknown")).status_code == 404
        assert (await client.post("/api/v1/demo/scenario/BAD!")).status_code == 422
        started = await client.post("/api/v1/demo/scenario/suspicious")
        assert started.status_code == 202
        assert started.json()["status"] == "started"
        assert (await client.post("/api/v1/demo/scenario/critical")).status_code == 409
        await rt.demo.wait()
        assert (await client.post("/api/v1/demo/scenario/critical")).status_code == 202
        await rt.demo.wait()

    async def test_demo_requests_are_rate_limited(
        self, client: httpx.AsyncClient, runtime: tuple[SentinelRuntime, FakeClock]
    ) -> None:
        rt, _ = runtime
        limit = settings.demo_max_requests_per_minute
        codes = [
            (
                await client.post(
                    "/api/v1/demo/inject", json={"event_type": "access_denied", "count": 1}
                )
            ).status_code
            for _ in range(limit + 1)
        ]
        assert codes[:limit] == [201] * limit and codes[-1] == 429
        assert rt.stats.synthetic_events == limit

    async def test_demo_mode_off_answers_403_before_reading_input(
        self,
        client: httpx.AsyncClient,
        runtime: tuple[SentinelRuntime, FakeClock],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        rt, _ = runtime
        monkeypatch.setattr(settings, "demo_mode", False)
        for method, path, body in (
            ("GET", "/api/v1/demo/scenarios", None),
            ("POST", "/api/v1/demo/inject", {"event_type": "auth_failure"}),
            ("POST", "/api/v1/demo/inject", {"event_type": "not-a-type"}),
            ("POST", "/api/v1/demo/scenario/critical", None),
        ):
            response = await client.request(method, path, json=body)
            assert response.status_code == 403, (path, response.text)
        assert rt.stats.synthetic_events == 0 and rt.demo.last_run is None


# ── Live WebSocket ─────────────────────────────────────────────────────────────


class PrimedHub(LiveHub):
    """Publishes one message as soon as a client subscribes (inside the server loop)."""

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        async with super().subscribe() as queue:
            self.publish(LiveMessageType.THREAT_SCORE, {"score": 0.42, "defense_state": "ALERT"})
            yield queue


@pytest.fixture()
def live_app() -> Iterator[tuple[TestClient, PrimedHub]]:
    hub = PrimedHub(max_subscribers=1, queue_size=10)
    app.state.runtime = SimpleNamespace(live=hub)
    try:
        yield TestClient(app), hub
    finally:
        app.state.runtime = None


class TestLiveStream:
    def test_clients_receive_sanitized_messages_and_can_reconnect(
        self, live_app: tuple[TestClient, PrimedHub]
    ) -> None:
        client, hub = live_app
        for _ in range(2):  # connect, disconnect, reconnect
            with client.websocket_connect("/ws/live") as ws:
                ws.send_text('{"command": "set_state", "state": "RELAXED"}')  # ignored
                message = ws.receive_json()
                assert message["type"] == "threat_score"
                assert message["payload"] == {"score": 0.42, "defense_state": "ALERT"}
        assert hub.subscriber_count == 0

    def test_a_foreign_browser_origin_is_refused(
        self, live_app: tuple[TestClient, PrimedHub]
    ) -> None:
        client, hub = live_app
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect("/ws/live", headers={"origin": "http://evil.example"}):
                pass
        assert refused.value.code == 1008
        with client.websocket_connect(
            "/ws/live", headers={"origin": settings.frontend_origin}
        ) as ws:
            assert ws.receive_json()["type"] == "threat_score"

    def test_the_subscriber_limit_is_enforced(self, live_app: tuple[TestClient, PrimedHub]) -> None:
        client, _ = live_app
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()
            with pytest.raises(WebSocketDisconnect) as full:
                with client.websocket_connect("/ws/live"):
                    pass
            assert full.value.code == 1013

    def test_no_runtime_closes_the_socket(self) -> None:
        app.state.runtime = None
        with pytest.raises(WebSocketDisconnect) as closed:
            with TestClient(app).websocket_connect("/ws/live"):
                pass
        assert closed.value.code == 1013


# ── Application lifespan ───────────────────────────────────────────────────────


class TestLifespan:
    async def test_startup_creates_the_schema_starts_monitoring_and_shutdown_cleans_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "app.db"
        monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db.as_posix()}")
        built: list[SentinelRuntime] = []

        def fake_build(config: Any, session_factory: Any) -> SentinelRuntime:
            runtime = build(
                session_factory, FakeClock(), settings=quiet_settings(poll_interval_seconds=0.25)
            )
            runtime._sleep = asyncio.sleep  # the real loop must really wait between cycles
            built.append(runtime)
            return runtime

        monkeypatch.setattr(main, "build_runtime", fake_build)
        async with main.lifespan(app):
            runtime = app.state.runtime
            assert runtime is built[0] and runtime.running
            assert db.exists()
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                assert (await c.get("/api/v1/runtime")).json()["monitoring"] is True
                assert (await c.get("/health")).json()["status"] == "ok"
        assert app.state.runtime is None
        assert not built[0].running
        leftover = {
            t.get_name() for t in asyncio.all_tasks() if t.get_name().startswith("sentinel-")
        }
        assert leftover == set()
