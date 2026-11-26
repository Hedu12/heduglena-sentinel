"""
Every protected security file is byte-identical to the hash recorded in the spec.

The table in .kiro/specs/heduglena-sentinel/design.md section 4 lists the
protected modules (guard, validator, scorer, state machine, planner, executor,
evaluation scoring and gates) with their SHA-256. Changing one of them requires
a reviewed spec change that updates the table, with Henok's explicit approval.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
DESIGN = REPO / ".kiro" / "specs" / "heduglena-sentinel" / "design.md"
ROW = re.compile(r"^\|[^|]+\|\s*`(backend/[\w/.]+\.py)`\s*\|\s*`([0-9A-F]{64})`\s*\|", re.M)
EXPECTED = {
    "backend/response/guard.py",
    "backend/ai/validator.py",
    "backend/threat/scorer.py",
    "backend/threat/state_machine.py",
    "backend/response/planner.py",
    "backend/response/executor.py",
    "backend/evaluation/metrics.py",
    "backend/evaluation/selection.py",
}


def _pins() -> dict[str, str]:
    return dict(ROW.findall(DESIGN.read_text(encoding="utf-8")))


def test_the_spec_pins_every_protected_file() -> None:
    assert set(_pins()) == EXPECTED


@pytest.mark.parametrize("path", sorted(EXPECTED))
def test_a_protected_file_matches_its_recorded_hash(path: str) -> None:
    actual = hashlib.sha256((REPO / path).read_bytes()).hexdigest().upper()
    assert actual == _pins()[path], (
        f"{path} changed. Protected files need Henok's explicit approval and a reviewed "
        "update of design.md section 4."
    )
