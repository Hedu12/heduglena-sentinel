"""
The demo reset (Phase 3.1): archive the session, start a clean one, decide nothing.

Runs the real application lifespan on a temporary SQLite file. The only test seam
is the runtime builder (fake host telemetry, deterministic clock), installed the
same way the application installs the production builder.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.lifecycle as lifecycle
import app.main as main
from app.demo_reset import demo_database_file
from app.main import app
from app.runtime import SentinelRuntime
from core.config import settings
from core.live import LiveHub, LiveMessageType, SubscriberLimitError
from tests.runtime_helpers import FakeClock, build, quiet_settings
from threat.service import ThreatAssessmentService

BACKEND = Path(__file__).resolve().parents[2]
PROTECTIVE = {"SIMULATE_IP_BLOCK", "SIMULATE_PROCESS_ISOLATE", "SIMULATE_QUARANTINE"}


def _fake_builder(config: Any, session_factory: Any) -> SentinelRuntime:
    runtime = build(session_factory, FakeClock(), settings=quiet_settings(poll_interval_seconds=60))
    runtime._sleep = asyncio.sleep  # one monitoring cycle, then a long real wait
    return runtime


@pytest_asyncio.fixture()
async def client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path]]:
    db = tmp_path / "demo.db"
    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db.as_posix()}")
    monkeypatch.setattr(main, "build_runtime", _fake_builder)
    async with main.lifespan(app):
        await _first_cycle()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c, db


async def _first_cycle() -> None:
    for _ in range(200):
        runtime: SentinelRuntime | None = app.state.runtime
        if runtime is not None and runtime.stats.cycles >= 1:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("the runtime never completed a monitoring cycle")


async def _scenario(c: httpx.AsyncClient, name: str) -> None:
    assert (await c.post(f"/api/v1/demo/scenario/{name}")).status_code == 202
    run = await app.state.runtime.demo.wait()
    assert run is not None and run.status == "completed"


async def _reset(c: httpx.AsyncClient) -> dict[str, Any]:
    response = await c.post("/api/v1/demo/reset")
    assert response.status_code == 200, response.text
    await _first_cycle()
    body: dict[str, Any] = response.json()
    return body


def _archived(db: Path, session: str) -> Path:
    return db.parent / f"{db.stem}-demo-sessions" / session / db.name


def _count(path: Path, sql: str) -> int:
    with closing(sqlite3.connect(path)) as conn:  # `with conn` alone does not close it
        return int(conn.execute(sql).fetchone()[0])


class TestDemoLifecycle:
    async def test_a_new_demo_starts_clean_and_relaxed(
        self, client: tuple[httpx.AsyncClient, Path]
    ) -> None:
        c, _ = client
        assert (await c.get("/api/v1/status")).json()["defense_state"] == "RELAXED"
        assert (await c.get("/api/v1/incidents")).json() == []
        assert (await c.get("/api/v1/actions")).json() == []
        assert (await c.get("/api/v1/events")).json() == []

    async def test_suspicious_then_reset(self, client: tuple[httpx.AsyncClient, Path]) -> None:
        c, db = client
        await _scenario(c, "suspicious")
        assert (await c.get("/api/v1/status")).json()["defense_state"] in {"ALERT", "DEFENSIVE"}
        acted = (await c.get("/api/v1/actions")).json()
        assert acted and all(a["is_simulated"] for a in acted)

        body = await _reset(c)
        assert body["status"] == "reset" and body["defense_state"] == "RELAXED"
        assert "/" not in body["archived_session"] and "\\" not in body["archived_session"]
        # The new session is empty: nothing carried over, nothing written by the reset.
        assert (await c.get("/api/v1/incidents")).json() == []
        assert (await c.get("/api/v1/actions")).json() == []
        assert (await c.get("/api/v1/events")).json() == []
        state = (await c.get("/api/v1/state/current")).json()
        assert state == {
            "current_state": "RELAXED",
            "since": None,
            "threat_score_at_transition": None,
        }
        # The previous session is archived intact, never deleted.
        archived = _archived(db, body["archived_session"])
        assert _count(archived, "SELECT COUNT(*) FROM response_actions") == len(acted)
        assert _count(archived, "SELECT COUNT(*) FROM incidents") == 1

    async def test_critical_then_reset_then_critical_again(
        self, client: tuple[httpx.AsyncClient, Path]
    ) -> None:
        c, db = client
        first = app.state.runtime
        await _scenario(c, "critical")
        assert (await c.get("/api/v1/status")).json()["defense_state"] == "AGGRESSIVE"
        body = await _reset(c)
        assert body["defense_state"] == "RELAXED"
        assert app.state.runtime is not first and not first.running
        assert first.live.closed  # live clients of the old session were told to reconnect
        archived = _archived(db, body["archived_session"])
        quarantine = "SELECT COUNT(*) FROM response_actions WHERE action_type='SIMULATE_QUARANTINE'"
        assert _count(archived, quarantine) == 1
        # The same scenario replays to the same outcome in the clean session.
        await _scenario(c, "critical")
        assert (await c.get("/api/v1/status")).json()["defense_state"] == "AGGRESSIVE"
        assert [i["incident_id"] for i in (await c.get("/api/v1/incidents")).json()] == ["SIT-1"]


class TestResetDecidesNothing:
    async def test_the_state_comes_from_history_not_from_the_reset(
        self, client: tuple[httpx.AsyncClient, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        c, db = client
        await _scenario(c, "critical")
        calls: list[str] = []
        for name in ("assess", "reset", "restore_state"):
            real = getattr(ThreatAssessmentService, name)

            def spy(self: Any, *a: Any, _real: Any = real, _name: str = name, **k: Any) -> Any:
                calls.append(_name)
                return _real(self, *a, **k)

            monkeypatch.setattr(ThreatAssessmentService, name, spy)
        body = await c.post("/api/v1/demo/reset")
        # Only the new runtime's own startup restore ran (it rebuilds state from the
        # empty database); the reset itself never scores, assesses or sets a state.
        assert calls[:2] == ["restore_state", "reset"]
        assert "assess" not in calls[: calls.index("reset") + 1]
        assert body.json()["defense_state"] == "RELAXED"

        # Proof that the state is derived from history: restoring the archived session
        # yields the escalated posture again, by the same authoritative restore.
        archived = _archived(db, body.json()["archived_session"])
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        engine = create_async_engine(f"sqlite+aiosqlite:///{archived.as_posix()}")
        try:
            replay = build(async_sessionmaker(engine, expire_on_commit=False), FakeClock())
            await replay.start(monitor=False)
            assert replay.defense_state.value == "AGGRESSIVE"
            await replay.stop()
        finally:
            await engine.dispose()

    def test_the_reset_code_never_touches_security_decisions(self) -> None:
        forbidden = (
            "assess(",
            "restore(",
            "_machine",
            "threat_score",
            "ThreatAssessmentService",
            "ResponseGuard",
            "ResponsePlanner",
            "SimulatedActionExecutor",
            "DELETE ",
            ".delete(",
            "unlink",
            "rmtree",
            "os.remove",
            "subprocess",
        )
        for name in ("demo_reset.py", "lifecycle.py"):
            source = (BACKEND / "app" / name).read_text(encoding="utf-8")
            code = "\n".join(
                line for line in source.splitlines() if not line.strip().startswith("#")
            )
            body = code.split('"""', 2)[-1]  # ignore the module docstring
            assert not [f for f in forbidden if f in body], name

    @pytest.mark.parametrize(
        ("kwargs", "label"),
        [
            ({"json": {"defense_state": "RELAXED"}}, "state body"),
            ({"json": {"threat_score": 0.0}}, "score body"),
            ({"json": {"incident_id": "SIT-1"}}, "incident body"),
            ({"params": {"state": "RELAXED"}}, "state query"),
            ({"params": {"score": "0"}}, "score query"),
            ({"content": b"x"}, "raw body"),
        ],
    )
    async def test_the_reset_accepts_no_input(
        self, client: tuple[httpx.AsyncClient, Path], kwargs: dict[str, Any], label: str
    ) -> None:
        c, db = client
        await _scenario(c, "critical")
        before = app.state.runtime
        response = await c.post("/api/v1/demo/reset", **kwargs)
        assert response.status_code == 422, label
        assert app.state.runtime is before and before.running
        assert (await c.get("/api/v1/status")).json()["defense_state"] == "AGGRESSIVE"
        assert not (db.parent / f"{db.stem}-demo-sessions").exists()


class TestNoHalfBuiltSession:
    async def test_reads_answer_503_until_the_new_session_is_complete(
        self, client: tuple[httpx.AsyncClient, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression (found in browser QA): reads arriving while the new session's
        # schema was being migrated hit a half-built database and returned 500.
        c, _ = client
        await _scenario(c, "critical")
        entered, release = asyncio.Event(), asyncio.Event()
        real = lifecycle.ensure_schema

        async def slow_schema(engine: Any) -> Any:
            entered.set()
            await release.wait()
            return await real(engine)

        monkeypatch.setattr(lifecycle, "ensure_schema", slow_schema)
        reset = asyncio.create_task(c.post("/api/v1/demo/reset"))
        await asyncio.wait_for(entered.wait(), 10)
        for path in (
            "/api/v1/events",
            "/api/v1/actions",
            "/api/v1/incidents",
            "/api/v1/incidents/SIT-1",
            "/api/v1/ai/explain/SIT-1",
            "/api/v1/state/current",
            "/api/v1/score/current",
            "/api/v1/telemetry/latest",
            "/api/v1/status",
            "/api/v1/runtime",
        ):
            assert (await c.get(path)).status_code == 503, path
        release.set()
        assert (await reset).status_code == 200
        await _first_cycle()
        assert (await c.get("/api/v1/events")).status_code == 200


class TestResetGuards:
    async def test_demo_mode_off_refuses_the_reset(
        self, client: tuple[httpx.AsyncClient, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        c, db = client
        before = app.state.runtime
        monkeypatch.setattr(settings, "demo_mode", False)
        assert (await c.post("/api/v1/demo/reset")).status_code == 403
        assert app.state.runtime is before
        assert not (db.parent / f"{db.stem}-demo-sessions").exists()

    async def test_a_reset_in_progress_refuses_a_second_one(
        self, client: tuple[httpx.AsyncClient, Path]
    ) -> None:
        c, _ = client
        lock = asyncio.Lock()
        app.state.demo_reset_lock = lock
        try:
            async with lock:
                response = await c.post("/api/v1/demo/reset")
            assert response.status_code == 409
        finally:
            del app.state.demo_reset_lock

    async def test_the_rate_limit_survives_a_reset(
        self, client: tuple[httpx.AsyncClient, Path]
    ) -> None:
        c, _ = client
        limiter = app.state.runtime.demo.limiter
        await _reset(c)
        assert app.state.runtime.demo.limiter is limiter

    @pytest.mark.parametrize(
        "url",
        ["sqlite+aiosqlite:///:memory:", "sqlite+aiosqlite://", "postgresql+asyncpg://u@h/db"],
    )
    def test_only_a_local_sqlite_file_can_be_reset(self, url: str) -> None:
        assert demo_database_file(url) is None

    def test_a_local_sqlite_file_is_recognized(self, tmp_path: Path) -> None:
        db = tmp_path / "x.db"
        assert demo_database_file(f"sqlite+aiosqlite:///{db.as_posix()}") == db.resolve()


class TestDemoIsolation:
    async def test_synthetic_events_stay_marked_and_telemetry_stays_real(
        self, client: tuple[httpx.AsyncClient, Path]
    ) -> None:
        c, db = client
        await _scenario(c, "critical")
        events = (await c.get("/api/v1/events")).json()
        assert events and all(e["is_synthetic"] for e in events)
        body = await _reset(c)
        archived = _archived(db, body["archived_session"])
        with closing(sqlite3.connect(archived)) as conn:
            rows = conn.execute(
                "SELECT is_synthetic, telemetry_sample_id, event_data FROM detection_events"
            ).fetchall()
        assert rows
        for is_synthetic, sample_id, event_data in rows:
            assert is_synthetic == 1 and sample_id is None
            evidence = json.loads(event_data)["evidence"]
            assert evidence["source"] == "demo" and evidence["synthetic"] is True
        # The new session collects its own real samples from the telemetry provider.
        telemetry = (await c.get("/api/v1/telemetry/latest")).json()
        assert telemetry["cpu_percent"] == 20.0
        assert _count(db, "SELECT COUNT(*) FROM telemetry_samples") >= 1


class ClosingHub(LiveHub):
    """Closes as soon as a client subscribes, inside the server's event loop."""

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[Any]:
        async with super().subscribe() as queue:
            self.close()
            yield queue


class TestLiveClientsReconnect:
    def test_closing_the_hub_ends_the_stream_with_service_restart(self) -> None:
        app.state.runtime = SimpleNamespace(live=ClosingHub(max_subscribers=2, queue_size=10))
        try:
            with TestClient(app).websocket_connect("/ws/live") as ws:
                with pytest.raises(WebSocketDisconnect) as closed:
                    ws.receive_json()
                assert closed.value.code == 1012
        finally:
            app.state.runtime = None

    async def test_a_closed_hub_refuses_publishes_and_new_subscribers(self) -> None:
        hub = LiveHub(max_subscribers=2, queue_size=10)
        hub.close()
        hub.publish(LiveMessageType.TELEMETRY, {"id": 1})
        assert hub.published == 0
        with pytest.raises(SubscriberLimitError):
            async with hub.subscribe():
                pass
