"""
The dashboard's recorded API fixture still matches the live backend schema.

frontend/tests/fixtures/contract.json is recorded from the real backend and
consumed by the frontend contract test. If a response shape changes on either
side, this test fails until the fixture is regenerated with
`python scripts/export_contract_fixture.py` (and the frontend types follow, P-08).
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.contract_fixture import build_contract, shape

FIXTURE = Path(__file__).resolve().parents[3] / "frontend" / "tests" / "fixtures" / "contract.json"


async def test_the_recorded_dashboard_fixture_matches_the_live_schema() -> None:
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    live = await build_contract()
    for snapshot in ("relaxed", "critical"):
        assert set(recorded[snapshot]) == set(live[snapshot]), snapshot
        for endpoint, response in live[snapshot].items():
            assert recorded[snapshot][endpoint]["status"] == response["status"], endpoint
            assert shape(recorded[snapshot][endpoint]["body"]) == shape(response["body"]), endpoint


async def test_the_fixture_tells_the_demo_story() -> None:
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    relaxed, critical = recorded["relaxed"], recorded["critical"]
    assert relaxed["status"]["body"]["defense_state"] == "RELAXED"
    assert relaxed["incidents"]["body"] == []
    assert critical["status"]["body"]["defense_state"] == "AGGRESSIVE"
    actions = {a["action_type"] for a in critical["actions"]["body"]}
    assert "SIMULATE_QUARANTINE" in actions
    assert all(a["is_simulated"] for a in critical["actions"]["body"])
    assert critical["explanation"]["body"]["availability"] == "AVAILABLE"
