"""
The evaluation framework is offline tooling with no path into Sentinel's decisions.

  * it imports only the AI layer, enums, the fixed reason texts and configuration;
  * it never imports the response engine, the threat service, scoring, the state
    machine, detection, telemetry, the database or the explanation service;
  * nothing in Sentinel imports it;
  * it has no execution capability.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
EVAL_FILES = sorted((BACKEND / "evaluation").rglob("*.py"))
PRODUCTION = ("ai", "api", "app", "core", "database", "detection", "explanation", "models",
              "response", "telemetry", "threat")  # fmt: skip

ALLOWED = {
    "__future__", "argparse", "asyncio", "collections", "dataclasses", "datetime", "enum",
    "hashlib", "json", "math", "pathlib", "re", "statistics", "sys", "time", "typing",
    "urllib.parse", "ipaddress", "pydantic", "evaluation", "models.enums", "threat.reasons",
    "core.config",
    "ai.context", "ai.output", "ai.explainer", "ai.protocols", "ai.factory", "ai.prompt",
    "ai.adapters.null_adapter", "ai.adapters.openai_compatible",
}  # fmt: skip
DANGEROUS = {"subprocess", "os", "socket", "shutil", "ctypes", "pickle", "signal"}
# Network and host measurement are confined to these modules: read-only Ollama
# inventory, system-wide CPU/memory, and the production adapter's HTTP types.
CONFINED = {
    "httpx": {"resources.py", "providers.py", "suite.py"},
    "psutil": {"resources.py", "hardware.py"},
    # Read-only host metadata (Phase 8.5.1), only in the hardware probe.
    "platform": {"hardware.py"},
    "winreg": {"hardware.py"},
}


def _imports(path: Path) -> list[str]:
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _allowed(name: str) -> bool:
    return any(name == a or name.startswith(a + ".") for a in ALLOWED)


@pytest.mark.parametrize("path", EVAL_FILES, ids=lambda p: p.name)
def test_evaluation_imports_only_the_allowed_modules(path: Path) -> None:
    for name in _imports(path):
        root = name.split(".")[0]
        assert root not in DANGEROUS, f"evaluation/{path.name} imports {name}"
        if root in CONFINED:
            assert path.name in CONFINED[root], f"evaluation/{path.name} imports {name}"
            continue
        assert _allowed(name), f"evaluation/{path.name} imports {name}"


@pytest.mark.parametrize("path", EVAL_FILES, ids=lambda p: p.name)
def test_evaluation_has_no_execution_capability(path: Path) -> None:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}


@pytest.mark.parametrize(
    "path", [p for layer in PRODUCTION for p in sorted((BACKEND / layer).rglob("*.py"))],
    ids=lambda p: p.relative_to(BACKEND).as_posix(),
)  # fmt: skip
def test_nothing_in_sentinel_imports_evaluation(path: Path) -> None:
    assert not any(n.split(".")[0] == "evaluation" for n in _imports(path))


def test_importing_evaluation_loads_no_security_component() -> None:
    code = (
        "import sys, evaluation.runner, evaluation.dataset, evaluation.metrics,"
        " evaluation.report, evaluation.__main__;"
        "banned=('response','detection','telemetry','database','explanation','sqlalchemy');"
        "bad=sorted({m.split('.')[0] for m in sys.modules if m.split('.')[0] in banned});"
        "threat=sorted(m for m in sys.modules if m.startswith('threat.')"
        " and m not in ('threat.reasons',));"
        "print('LOADED:', bad, threat)"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=BACKEND, timeout=60,
        check=True,
    )  # fmt: skip
    assert "LOADED: [] []" in result.stdout, result.stdout
