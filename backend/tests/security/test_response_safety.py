"""
Static security tests for the Phase 5 response engine.

The response layer is the closest Sentinel comes to acting, so it is held to the
strictest rules: no process, network, filesystem or environment access, no wall
clock, no randomness, no LLM, and no code path that can record or perform a
non-simulated action. guard.py is excluded only from the clock rule: it is the
unmodified security boundary and reads the clock for its own (unused) cooldown.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

RESPONSE = Path(__file__).resolve().parents[2] / "response"
NEW_MODULES = sorted(p for p in RESPONSE.glob("*.py") if p.name not in {"guard.py", "__init__.py"})

FORBIDDEN_MODULES = {
    "subprocess",
    "shlex",
    "socket",
    "ssl",
    "http",
    "urllib",
    "requests",
    "httpx",
    "aiohttp",
    "ctypes",
    "pickle",
    "marshal",
    "os",
    "shutil",
    "signal",
    "multiprocessing",
    "random",
    "secrets",
    "uuid",
    "time",
    "psutil",
    "ai",
    "telemetry",
    "detection",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input"}
FORBIDDEN_ATTRIBUTES = {
    "now",
    "utcnow",
    "today",
    "time",
    "time_ns",
    "monotonic",
    "perf_counter",
    "sleep",
    "getenv",
    "environ",
    "system",
    "popen",
}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_the_new_response_modules_were_found() -> None:
    assert [p.name for p in NEW_MODULES] == [
        "actions.py",
        "executor.py",
        "planner.py",
        "service.py",
    ]


@pytest.mark.parametrize("path", NEW_MODULES, ids=lambda p: p.name)
class TestStaticSafety:
    def test_no_forbidden_imports(self, path: Path) -> None:
        for node in ast.walk(_tree(path)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in FORBIDDEN_MODULES, f"{path.name} imports {name}"

    def test_no_dynamic_code_or_file_access(self, path: Path) -> None:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}()"

    def test_no_clock_environment_or_process_access(self, path: Path) -> None:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Attribute):
                assert node.attr not in FORBIDDEN_ATTRIBUTES, f"{path.name} uses .{node.attr}"

    def test_nothing_is_ever_recorded_as_not_simulated(self, path: Path) -> None:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.keyword) and node.arg == "is_simulated":
                assert isinstance(node.value, ast.Constant) and node.value.value is True, (
                    f"{path.name} sets is_simulated to something other than the literal True"
                )


def test_the_guard_is_imported_never_reimplemented() -> None:
    # The service must use the real ResponseGuard, and nothing may define a rival guard.
    for path in NEW_MODULES:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.ClassDef):
                assert "Guard" not in node.name, f"{path.name} defines {node.name}"
    service = (RESPONSE / "service.py").read_text(encoding="utf-8")
    assert "from response.guard import GuardVerdict, ResponseGuard" in service
    assert ".evaluate(" in service


def test_live_execution_is_switched_off_in_code_not_configuration() -> None:
    from response import executor

    assert executor.LIVE_EXECUTION_SUPPORTED is False
    # The executor reads no configuration, so no setting (LIVE_ACTIONS included) can
    # turn live execution on.
    for node in ast.walk(_tree(RESPONSE / "executor.py")):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "core.config", "executor must not read configuration"


def test_importing_the_response_layer_loads_no_llm_or_upstream_collectors() -> None:
    code = (
        "import sys, response.service, response.planner, response.executor;"
        "banned=('ai','telemetry','detection','psutil');"
        "bad=[m for m in sys.modules if m.split('.')[0] in banned];"
        "print('LOADED:', bad)"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=RESPONSE.parent,
        timeout=60,
        check=True,
    )
    assert "LOADED: []" in result.stdout
