"""
No real destructive response exists yet, and the decision layer cannot ask for one.

Sentinel may only recommend actions; every protective recommendation is a
SIMULATED action. These tests fail if a live/destructive action type, handler, or
code path is added before it has been deliberately designed and reviewed.
ResponseGuard is only *called* here, never modified.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.config import Settings
from models.enums import ActionClass, ActionType, DefenseState
from response.guard import ResponseGuard
from threat.decision import recommended_actions_for

BACKEND = Path(__file__).resolve().parents[2]
DECISION_AND_RESPONSE = [
    *sorted((BACKEND / "threat").rglob("*.py")),
    *sorted((BACKEND / "response").rglob("*.py")),
]

# Calls that would act on the host. None may appear in the decision or response layer.
DESTRUCTIVE_CALLS = {
    "system",
    "popen",
    "kill",
    "killpg",
    "terminate",
    "remove",
    "unlink",
    "rmtree",
    "rmdir",
    "chmod",
    "chown",
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "execv",
    "execve",
    "spawnv",
    "startfile",
}
DESTRUCTIVE_WORDS = (
    "iptables",
    "netsh",
    "taskkill",
    "nftables",
    "firewall-cmd",
    "pfctl",
    "powershell",
    "pwsh",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "os.kill",
    "os.system",
    "shutil.rmtree",
    "subprocess",
    "socket",
)


def _name(path: Path) -> str:
    return path.relative_to(BACKEND).as_posix()


def test_every_action_type_is_simulated_or_non_destructive() -> None:
    guard = ResponseGuard(settings=Settings(live_actions=False))
    for action in ActionType:
        verdict = guard.evaluate(action, DefenseState.AGGRESSIVE)
        assert verdict.action_class is not ActionClass.LIVE_PROTECTIVE, (
            f"{action} is a live protective action; live response is not implemented yet"
        )


def test_protective_action_names_are_all_simulations() -> None:
    destructive = {"BLOCK", "ISOLATE", "QUARANTINE", "KILL", "DELETE", "FIREWALL"}
    for action in ActionType:
        if any(word in action.value for word in destructive):
            assert action.value.startswith("SIMULATE_"), (
                f"{action} sounds destructive but is not simulated"
            )


@pytest.mark.parametrize("state", list(DefenseState))
def test_no_recommendation_is_ever_live_even_if_live_actions_were_enabled(
    state: DefenseState,
) -> None:
    # Even with the operator flag turned on, today's recommendations stay simulated:
    # the flag would only matter for a LIVE_PROTECTIVE action, and none exists.
    guard = ResponseGuard(settings=Settings(live_actions=True))
    for action in recommended_actions_for(state, new_evidence=True, record_incident=True):
        verdict = guard.evaluate(action, state)
        assert verdict.action_class is not ActionClass.LIVE_PROTECTIVE
        if verdict.action_class is ActionClass.SIMULATED_PROTECTIVE:
            assert verdict.is_simulated is True


def test_live_actions_defaults_to_off() -> None:
    assert Settings.model_fields["live_actions"].default is False


@pytest.mark.parametrize("path", DECISION_AND_RESPONSE, ids=_name)
def test_decision_and_response_code_contains_no_host_actions(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", "")
            )
            assert name not in DESTRUCTIVE_CALLS, f"{path.name} calls {name}()"
            for keyword in node.keywords:
                assert keyword.arg != "shell", f"{path.name} passes shell= to {name}()"
    lowered = source.lower()
    for word in DESTRUCTIVE_WORDS:
        assert word not in lowered, f"{path.name} mentions {word}"


def test_the_response_package_contains_only_reviewed_modules() -> None:
    # Adding a module to the response package (for example a live executor) must be a
    # deliberate, reviewed change to this allowlist.
    modules = {p.name for p in (BACKEND / "response").rglob("*.py")}
    assert modules == {
        "__init__.py",
        "guard.py",
        "actions.py",
        "planner.py",
        "executor.py",
        "service.py",
    }, f"unexpected response modules: {modules}"
