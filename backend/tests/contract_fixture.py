"""
Record the real API responses the dashboard consumes.

The runtime is built exactly as the application builds it (test seams: fake
host telemetry and a deterministic clock), driven to a RELAXED snapshot and then
through the "critical" demo scenario. Every endpoint the dashboard reads is
called through the real FastAPI app, and the JSON bodies are returned.

Used by scripts/export_contract_fixture.py (writes
frontend/tests/fixtures/contract.json) and by
tests/integration/test_dashboard_contract.py (fails when the recorded fixture
no longer matches the live schema).
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import httpx

from api.v1.incidents import get_incident_reads
from api.v1.runtime import get_runtime_reads
from app.main import app
from core.runtime_views import RuntimeReadService
from explanation.incident_view import IncidentReadService
from tests.runtime_helpers import FakeClock, build, cycles, fresh_database, play, quiet_settings

ENDPOINTS = {
    "health": "/health",
    "status": "/api/v1/status",
    "runtime": "/api/v1/runtime",
    "state": "/api/v1/state/current",
    "score": "/api/v1/score/current",
    "telemetry": "/api/v1/telemetry/latest",
    "events": "/api/v1/events?limit=25",
    "actions": "/api/v1/actions?limit=25",
    "incidents": "/api/v1/incidents?limit=20",
    "ai_status": "/api/v1/ai/status",
    "scenarios": "/api/v1/demo/scenarios",
}


async def _snapshot(client: httpx.AsyncClient, incident: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, path in ENDPOINTS.items():
        response = await client.get(path)
        out[name] = {"status": response.status_code, "body": response.json()}
    if incident is not None:
        for name, path in (
            ("incident", f"/api/v1/incidents/{incident}"),
            ("explanation", f"/api/v1/ai/explain/{incident}"),
        ):
            response = await client.get(path)
            out[name] = {"status": response.status_code, "body": response.json()}
    return out


async def build_contract() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        async with fresh_database(Path(tmp)) as factory:
            clock = FakeClock()
            runtime = build(factory, clock, settings=quiet_settings(poll_interval_seconds=60))
            runtime._sleep = asyncio.sleep  # the monitor runs one cycle, then waits
            await runtime.start()
            app.state.runtime = runtime
            app.dependency_overrides[get_runtime_reads] = lambda: RuntimeReadService(factory)
            app.dependency_overrides[get_incident_reads] = lambda: IncidentReadService(factory)
            try:
                await cycles(runtime, clock, 3)
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                    relaxed = await _snapshot(c, None)
                    await play(runtime, "critical")
                    await runtime.explanation.run_pending()
                    await cycles(runtime, clock, 2)
                    critical = await _snapshot(c, "SIT-1")
            finally:
                app.state.runtime = None
                app.dependency_overrides.clear()
                await runtime.stop()
    return {
        "_note": (
            "Recorded from the real backend by scripts/export_contract_fixture.py. "
            "Do not edit by hand; regenerate instead."
        ),
        "relaxed": relaxed,
        "critical": critical,
    }


def shape(value: object) -> object:
    """The structure of a JSON value: keys and types, not the values themselves."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    if value is None:
        return "null"
    return type(value).__name__
