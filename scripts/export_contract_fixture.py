"""
Write frontend/tests/fixtures/contract.json from the real backend.

Run from the repository root:  python scripts/export_contract_fixture.py

It starts no server and touches no real database: the backend runtime runs
in-process on a temporary SQLite file with fake telemetry, and the dashboard's
endpoints are called through the FastAPI app (see backend/tests/contract_fixture.py).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
OUT = REPO / "frontend" / "tests" / "fixtures" / "contract.json"


def main() -> int:
    sys.path.insert(0, str(BACKEND))
    from tests.contract_fixture import build_contract  # noqa: PLC0415 - needs the path above

    contract = asyncio.run(build_contract())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
