"""
P-08: frontend/src/types/api.ts mirrors the Phase 6 view schemas field for field.

A lightweight structural check (no TypeScript toolchain needed): every view's
fields must equal the fields of its TypeScript interface.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from explanation import views
from models.enums import ExplanationFailure, ExplanationTrigger

API_TS = Path(__file__).resolve().parents[3] / "frontend" / "src" / "types" / "api.ts"
PAIRS: dict[type[BaseModel], str] = {
    views.ReasonSchema: "Reason",
    views.IncidentSummarySchema: "IncidentSummary",
    views.ScoreBreakdownSchema: "ScoreBreakdown",
    views.EvidenceSchema: "IncidentEvidence",
    views.TransitionSchema: "IncidentTransition",
    views.SimulationSchema: "ResponseSimulation",
    views.ExplanationContentSchema: "ExplanationContent",
    views.ExplanationSchema: "Explanation",
    views.ExplanationStateSchema: "ExplanationState",
    views.IncidentDetailSchema: "IncidentDetail",
    views.AIStatusSchema: "AIStatus",
}
SOURCE = API_TS.read_text(encoding="utf-8")


def _interface_fields(name: str) -> set[str]:
    match = re.search(rf"export interface {name} \{{(.*?)\n\}}", SOURCE, re.DOTALL)
    assert match, f"api.ts has no interface {name}"
    return set(re.findall(r"^\s+(\w+)\??:", match.group(1), re.MULTILINE))


@pytest.mark.parametrize("schema", list(PAIRS), ids=lambda s: s.__name__)
def test_each_view_matches_its_typescript_interface(schema: type[BaseModel]) -> None:
    assert _interface_fields(PAIRS[schema]) == set(schema.model_fields)


@pytest.mark.parametrize("enum", [ExplanationTrigger, ExplanationFailure], ids=lambda e: e.__name__)
def test_enumerations_match(enum: type) -> None:
    match = re.search(rf"export type {enum.__name__} =(.*?);", SOURCE, re.DOTALL)
    assert match, enum.__name__
    assert set(re.findall(r'"(\w+)"', match.group(1))) == {m.value for m in enum}  # type: ignore[attr-defined]
