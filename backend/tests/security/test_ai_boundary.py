"""
The one-way boundary: security domain -> AI explanation, never the reverse.

    AI -> ThreatScorer / DefenseStateMachine / ResponsePlanner / ResponseGuard
       -> executor / live action                                   all impossible

Enforced statically (imports and calls in source) and at runtime (what importing
a module actually loads).
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
AI_FILES = sorted((BACKEND / "ai").rglob("*.py"))
EXPLANATION_FILES = sorted((BACKEND / "explanation").rglob("*.py"))
SECURITY_LAYERS = ("threat", "response", "detection", "telemetry", "database", "core", "models")

AI_ALLOWED_ROOTS = {
    "__future__",
    "ai",
    "core",
    "models",
    "pydantic",
    "httpx",
    "asyncio",
    "collections",
    "dataclasses",
    "hashlib",
    "json",
    "logging",
    "math",
    "re",
    "time",
    "typing",
    "unicodedata",
}
EXPLANATION_FORBIDDEN = {
    "response",
    "threat.service",
    "threat.scorer",
    "threat.state_machine",
    "detection",
    "telemetry",
    "api",
    "app",
}
DANGEROUS_ROOTS = {"subprocess", "os", "socket", "shutil", "ctypes", "pickle", "signal", "shlex"}
# Bare-name calls (eval(...)) and attribute calls (os.system(...)) that execute code.
DANGEROUS_NAME_CALLS = {"eval", "exec", "compile", "__import__", "open"}
DANGEROUS_ATTR_CALLS = {"system", "popen", "Popen", "spawnv", "startfile", "check_output"}
SESSION_WRITES = {"add", "add_all", "merge", "delete", "commit", "flush", "begin", "insert"}


def _name(path: Path) -> str:
    return path.relative_to(BACKEND).as_posix()


def _imports(path: Path) -> list[str]:
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _calls(path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """(bare-name calls, (receiver, attribute) calls)."""
    names: set[str] = set()
    attrs: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                attrs.add((ast.unparse(func.value), func.attr))
    return names, attrs


class TestTheAIPackage:
    @pytest.mark.parametrize("path", AI_FILES, ids=_name)
    def test_imports_only_the_allowed_layers(self, path: Path) -> None:
        for name in _imports(path):
            root = name.split(".")[0]
            assert root in AI_ALLOWED_ROOTS, f"{_name(path)} imports {name}"
            if root == "httpx":
                assert path.name == "openai_compatible.py", "only the HTTP adapter may use httpx"
            if root == "core":
                assert name in {"core.config", "core.exceptions"}, name

    @pytest.mark.parametrize("path", [*AI_FILES, *EXPLANATION_FILES], ids=_name)
    def test_has_no_execution_capability(self, path: Path) -> None:
        assert not {n.split(".")[0] for n in _imports(path)} & DANGEROUS_ROOTS
        names, attrs = _calls(path)
        assert not names & DANGEROUS_NAME_CALLS, f"{_name(path)} calls {names}"
        assert not {a for _, a in attrs} & DANGEROUS_ATTR_CALLS, f"{_name(path)} calls {attrs}"

    def test_the_prompt_and_context_cannot_read_configuration(self) -> None:
        for module in ("prompt.py", "context.py", "output.py", "policy.py"):
            assert "core.config" not in _imports(BACKEND / "ai" / module), module

    def test_importing_the_ai_layer_loads_no_security_component(self) -> None:
        code = (
            "import sys, ai.explainer, ai.factory, ai.adapters.fake, ai.adapters.null_adapter,"
            " ai.adapters.openai_compatible;"
            "banned=('response','threat','detection','telemetry','database','explanation',"
            "'sqlalchemy','psutil');"
            "print('LOADED:', sorted({m.split('.')[0] for m in sys.modules"
            " if m.split('.')[0] in banned}))"
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=BACKEND,
            timeout=60,
            check=True,
        )
        assert "LOADED: []" in result.stdout, result.stdout


class TestTheExplanationPackage:
    @pytest.mark.parametrize("path", EXPLANATION_FILES, ids=_name)
    def test_never_imports_the_control_path(self, path: Path) -> None:
        for name in _imports(path):
            for banned in EXPLANATION_FORBIDDEN:
                assert not (name == banned or name.startswith(banned + ".")), (
                    f"{_name(path)} imports {name}"
                )
            assert name.split(".")[0] not in DANGEROUS_ROOTS

    @pytest.mark.parametrize(
        "module", ["queries.py", "context_builder.py", "incident_view.py", "triggers.py"]
    )
    def test_read_side_modules_cannot_write(self, module: str) -> None:
        path = BACKEND / "explanation" / module
        _, attrs = _calls(path)
        session_writes = {(r, a) for r, a in attrs if "session" in r and a in SESSION_WRITES}
        assert not session_writes, f"{module} writes: {session_writes}"
        # SQL statements available to it: SELECT only.
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module == "sqlalchemy":
                assert {a.name for a in node.names} <= {"select"}, module
        assert "Repository" not in path.read_text(encoding="utf-8")

    def test_the_service_writes_only_explanation_records(self) -> None:
        source = (BACKEND / "explanation" / "service.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        repos = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "database.repositories"
            for alias in node.names
        }
        assert repos == {"AIExplanationRepository"}
        assert "ResponseAction(" not in source and "Incident(" not in source


class TestTheSecurityDomain:
    @pytest.mark.parametrize(
        "path",
        [p for layer in SECURITY_LAYERS for p in sorted((BACKEND / layer).rglob("*.py"))],
        ids=_name,
    )
    def test_never_imports_the_ai_or_explanation_layers(self, path: Path) -> None:
        for name in _imports(path):
            assert name.split(".")[0] not in {"ai", "explanation"}, f"{_name(path)} imports {name}"

    def test_ai_output_types_never_appear_in_the_control_path(self) -> None:
        markers = ("ExplanationOutput", "ExplanationOutcome", "AIExplanationRecord", "explanation")
        for layer in ("threat", "response", "detection", "telemetry"):
            for path in sorted((BACKEND / layer).rglob("*.py")):
                source = path.read_text(encoding="utf-8")
                for marker in markers:
                    assert marker not in source, f"{_name(path)} mentions {marker}"

    def test_importing_the_control_path_loads_no_ai(self) -> None:
        code = (
            "import sys, threat.service, response.service, response.guard, response.executor,"
            " response.planner, detection.engine;"
            "print('LOADED:', sorted({m.split('.')[0] for m in sys.modules"
            " if m.split('.')[0] in ('ai','explanation','httpx')}))"
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=BACKEND,
            timeout=60,
            check=True,
        )
        assert "LOADED: []" in result.stdout, result.stdout


def test_the_request_shape_offers_the_model_nothing_to_call() -> None:
    from dataclasses import fields

    from ai.protocols import ExplanationRequest

    assert {f.name for f in fields(ExplanationRequest)} == {
        "incident_id",
        "messages",
        "max_output_tokens",
        "context",
    }
