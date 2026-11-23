"""
Read-only checks run by the Kiro hooks in .kiro/hooks/.

Nothing here formats, fixes, installs, downloads, commits or edits project
files. Tools may write their own git-ignored caches (.mypy_cache, .pytest_cache,
.coverage). A check whose tool is not installed is skipped, never installed.

Usage (from the repository root):
    python scripts/hooks/check.py python-file   <path>   ruff check + mypy --strict
    python scripts/hooks/check.py security-file <path>   bandit -ll
    python scripts/hooks/check.py ts-file       <path>   ESLint (local install only)
    python scripts/hooks/check.py quality-gate           full pre-commit gate

Exit codes:
    0  passed or skipped
    1  a file check found problems (reported to the agent by Kiro)
    3  the quality gate failed. Not 1: for the Stop trigger, exit code 1 makes
       Kiro start another agent turn automatically, and this gate must only
       report, never start unattended work.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess  # nosec B404 - fixed argument lists, no shell, no user-built commands
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
FRONTEND = REPO / "frontend"
SOURCE_PACKAGES = (
    "app",
    "api",
    "core",
    "detection",
    "telemetry",
    "threat",
    "response",
    "ai",
    "explanation",
    "evaluation",
    "database",
    "models",
)
SECURITY_DIRS = (
    "backend/response/",
    "backend/ai/",
    "backend/explanation/",
    "backend/threat/",
    "backend/core/",
)
PATH_KEYS = ("file_path", "filePath", "path", "file")


def _from_stdin() -> str | None:
    """Kiro sends hook event JSON on STDIN; use it if no path argument was given."""
    if sys.stdin is None or sys.stdin.isatty():
        return None
    try:
        event = json.loads(sys.stdin.read() or "null")
    except ValueError:
        return None
    stack: list[object] = [event]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key in PATH_KEYS and isinstance(value, str) and value:
                    return value
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return None


def _target(argv: list[str]) -> str | None:
    """Repository-relative POSIX path of the saved file, or None if outside the repo."""
    raw = argv[0] if argv and argv[0] and "{{" not in argv[0] else _from_stdin()
    if not raw:
        return None
    path = Path(raw)
    path = (path if path.is_absolute() else REPO / path).resolve()
    try:
        return path.relative_to(REPO).as_posix()
    except ValueError:
        return None


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _report(failures: list[str], rel: str) -> int:
    if failures:
        print("\n\n".join(failures), file=sys.stderr)
        return 1
    print(f"ok: {rel}")
    return 0


def python_file(rel: str) -> int:
    if not (rel.startswith("backend/") and rel.endswith(".py")):
        print(f"skipped: {rel} is not a backend Python file")
        return 0
    inner = rel.removeprefix("backend/")
    failures: list[str] = []
    if _has_module("ruff"):
        ruff = [sys.executable, "-m", "ruff", "check", "--output-format=concise", inner]
        code, out = _run(ruff, BACKEND)
        if code:
            failures.append(f"ruff check {rel}:\n{out}")
    else:
        print("skipped: ruff is not installed")
    # Test files and Alembic migrations are outside the strict-typing scope
    # (see testing-requirements.md: mypy --strict covers the source packages).
    if inner.split("/", 1)[0] in SOURCE_PACKAGES:
        if _has_module("mypy"):
            code, out = _run([sys.executable, "-m", "mypy", "--strict", inner], BACKEND)
            if code:
                failures.append(f"mypy --strict {rel}:\n{out}")
        else:
            print("skipped: mypy is not installed")
    return _report(failures, rel)


def security_file(rel: str) -> int:
    if not (rel.endswith(".py") and rel.startswith(SECURITY_DIRS)):
        print(f"skipped: {rel} is not in a security-sensitive backend package")
        return 0
    if not _has_module("bandit"):
        print("skipped: bandit is not installed")
        return 0
    bandit = [sys.executable, "-m", "bandit", "-ll", "-q", rel.removeprefix("backend/")]
    code, out = _run(bandit, BACKEND)
    return _report([f"bandit -ll {rel}:\n{out}"] if code else [], rel)


def ts_file(rel: str) -> int:
    if not (rel.startswith("frontend/src/") and rel.endswith((".ts", ".tsx"))):
        print(f"skipped: {rel} is not a frontend source file")
        return 0
    eslint = FRONTEND / "node_modules" / "eslint" / "bin" / "eslint.js"
    node = shutil.which("node")
    if node is None or not eslint.is_file():
        print("skipped: frontend dependencies are not installed (hooks never install packages)")
        return 0
    lint = [node, str(eslint), rel.removeprefix("frontend/"), "--format=compact"]
    code, out = _run(lint, FRONTEND)
    return _report([f"eslint {rel}:\n{out}"] if code else [], rel)


def _gate_steps() -> list[tuple[str, list[str] | None, Path]]:
    py = sys.executable
    tsc = FRONTEND / "node_modules" / "typescript" / "bin" / "tsc"
    node = shutil.which("node")
    cov = [f"--cov={p}" for p in SOURCE_PACKAGES]
    quiet = ["-q", "--tb=short", "-o", "addopts=", "-p", "no:cacheprovider"]
    return [
        ("ruff check", [py, "-m", "ruff", "check", ".", "--output-format=concise"], BACKEND),
        ("ruff format --check", [py, "-m", "ruff", "format", "--check", "."], BACKEND),
        ("mypy --strict (source)", [py, "-m", "mypy", "--strict", *SOURCE_PACKAGES], BACKEND),
        (
            "unit tests + coverage >= 80%",
            [py, "-m", "pytest", "tests/unit", *quiet, *cov, "--cov-fail-under=80"],
            BACKEND,
        ),
        ("security tests", [py, "-m", "pytest", "tests/security", *quiet], BACKEND),
        (
            "bandit -ll (source)",
            [
                py,
                "-m",
                "bandit",
                "-r",
                ".",
                "-x",
                "./tests,./.hypothesis,./.mypy_cache",
                "-ll",
                "-q",
            ],
            BACKEND,
        ),
        (
            "frontend tsc --noEmit",
            [node, str(tsc), "--noEmit"] if node and tsc.is_file() else None,
            FRONTEND,
        ),
    ]


def quality_gate() -> int:
    failed = 0
    for name, cmd, cwd in _gate_steps():
        if cmd is None:
            print(f"SKIPPED  {name} (dependencies not installed)")
            continue
        started = time.monotonic()
        code, out = _run(cmd, cwd)
        elapsed = time.monotonic() - started
        print(f"{'PASS' if code == 0 else 'FAIL'}     {name} ({elapsed:.0f} s)")
        if code:
            failed += 1
            print("\n".join(out.splitlines()[-25:]))
    print(f"quality gate: {'FAILED' if failed else 'PASSED'} ({failed} failing step(s))")
    return 3 if failed else 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 0
    command, rest = argv[0], argv[1:]
    if command == "quality-gate":
        return quality_gate()
    checks = {"python-file": python_file, "security-file": security_file, "ts-file": ts_file}
    if command not in checks:
        print(f"unknown check: {command}", file=sys.stderr)
        return 0
    rel = _target(rest)
    if rel is None:
        print("skipped: no file path inside the repository was provided")
        return 0
    return checks[command](rel)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
