"""
One action vocabulary, and the guard sees exactly what is recorded.

The six action types of spec section 9.2 are the only action types. There is no
second vocabulary (aliases, labels used as types, caller-side translation), so
the action type ResponseGuard.evaluate() authorises is, byte for byte, the
action type persisted in response_actions. ResponseGuard is only called here.
"""

from __future__ import annotations

import ast
import dataclasses
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from core.config import Settings
from models.enums import ActionType, DefenseState
from response.actions import PlannedAction
from response.guard import GuardVerdict, ResponseGuard
from response.service import ResponseService
from tests.response_helpers import actions, database
from tests.threat_scenario import Scenario, play_attack

BACKEND = Path(__file__).resolve().parents[2]
FRONTEND_SRC = BACKEND.parent / "frontend" / "src"
SPEC_ACTIONS = {
    "GENERATE_ALERT",
    "INCREASE_MONITORING",
    "RECORD_INCIDENT",
    "SIMULATE_IP_BLOCK",
    "SIMULATE_PROCESS_ISOLATE",
    "SIMULATE_QUARANTINE",
}
# Rejected alternative names (decision: Option A). They must not exist anywhere.
REJECTED_NAMES = (
    "SIMULATE_ALERT_OPERATOR",
    "SIMULATE_BLOCK_SOURCE",
    "SIMULATE_ISOLATE_HOST",
    "SIMULATE_PROCESS_CONTAINMENT",
)
SOURCE_PACKAGES = ("ai", "api", "core", "database", "detection", "models", "response", "threat")


def _sources() -> list[Path]:
    files = [p for pkg in SOURCE_PACKAGES for p in sorted((BACKEND / pkg).rglob("*.py"))]
    files += sorted((BACKEND / "alembic").rglob("*.py"))
    if FRONTEND_SRC.exists():
        files += sorted(p for p in FRONTEND_SRC.rglob("*") if p.suffix in {".ts", ".tsx"})
    return files


def test_the_action_types_are_exactly_the_spec_vocabulary() -> None:
    assert {a.value for a in ActionType} == SPEC_ACTIONS
    assert all(a.name == a.value for a in ActionType)


def test_rejected_alternative_names_exist_nowhere_in_the_product() -> None:
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for name in REJECTED_NAMES:
            assert name not in text, f"{path.relative_to(BACKEND.parent)} mentions {name}"


def test_every_action_type_is_registered_with_the_guard() -> None:
    guard = ResponseGuard(settings=Settings())
    for action in ActionType:
        verdict = guard.evaluate(action, DefenseState.AGGRESSIVE, cooldown_seconds=0)
        assert verdict.allowed, f"{action}: {verdict.reason}"


def test_a_planned_action_cannot_be_changed_after_planning() -> None:
    assert PlannedAction.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert "action_type" in {f.name for f in dataclasses.fields(PlannedAction)}


class TestNoCallerSideTranslation:
    """Static: the guard and the record both read planned.action_type, untranslated."""

    tree = ast.parse((BACKEND / "response" / "service.py").read_text(encoding="utf-8"))

    def _calls(self, attr: str) -> list[ast.Call]:
        return [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == attr
        ]

    def test_the_guard_is_asked_about_planned_action_type(self) -> None:
        (call,) = self._calls("evaluate")
        assert ast.unparse(call.args[0]) == "planned.action_type"

    def test_the_record_stores_planned_action_type(self) -> None:
        records = [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "ResponseAction"
        ]
        (record,) = records
        value = next(k.value for k in record.keywords if k.arg == "action_type")
        assert ast.unparse(value) == "planned.action_type.value"

    def test_nothing_maps_or_renames_action_types(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Dict):
                keys = {ast.unparse(k) for k in node.keys if k is not None}
                assert not any(k.startswith("ActionType.") for k in keys), "action type mapping"


@dataclass
class RecordingGuard:
    """Wraps the real, unmodified guard and records what it was asked."""

    real: ResponseGuard = field(default_factory=lambda: ResponseGuard(settings=Settings()))
    asked: list[tuple[str, str]] = field(default_factory=list)  # (action, defense state)

    def evaluate(
        self, action: ActionType, current_state: DefenseState, cooldown_seconds: float = 60.0
    ) -> GuardVerdict:
        assert isinstance(action, ActionType)  # never a label or a translated string
        self.asked.append((action.value, current_state.value))
        return self.real.evaluate(action, current_state, cooldown_seconds)

    def record_fired(self, action: ActionType) -> None:
        self.real.record_fired(action)


async def test_every_guarded_record_carries_the_action_type_the_guard_authorised() -> None:
    async with database() as factory:
        s = Scenario(factory)
        await play_attack(s)
        await play_attack(s, start=800)
        guard = RecordingGuard()
        await ResponseService(Settings(), factory, guard=guard).handle_all(  # type: ignore[arg-type]
            s.result.decisions
        )
        rows = await actions(factory)

    assert guard.asked
    guarded = [r for r in rows if r.action_class is not None]  # rows that reached the guard
    # One guard question per guarded record, about the same action in the same state.
    assert Counter((r.action_type, r.defense_state) for r in guarded) == Counter(guard.asked)
    assert {r.action_type for r in rows} <= SPEC_ACTIONS
