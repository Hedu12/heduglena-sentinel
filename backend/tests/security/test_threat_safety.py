"""
Security tests for the threat-scoring and defense-state subsystem.

The decision layer is deterministic and advisory. These tests enforce that it
cannot execute commands, touch the host or network, read the environment or the
clock, use randomness, depend on an LLM, or call ResponseGuard, and that
untrusted text in evidence cannot affect scoring or bloat its output.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from database.models import DetectionEvent
from tests.threat_helpers import SCORING, T0, at, auth_critical
from threat.evidence import MAX_EVENT_TYPE_LENGTH, EvidenceItem, SignalCategory, clean_event_type
from threat.scorer import ThreatScorer

THREAT_DIR = Path(__file__).resolve().parents[2] / "threat"
SOURCES = sorted(THREAT_DIR.rglob("*.py"))

FORBIDDEN_MODULES = {
    # process / shell / network
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
    # non-determinism
    "random",
    "secrets",
    "uuid",
    "time",
    # the LLM, the response layer, and upstream subsystems (P-01: talk through the database)
    "ai",
    "response",
    "detection",
    "telemetry",
    "psutil",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input"}
# Reading the wall clock or sleeping would make results depend on when they run.
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


def _name(path: Path) -> str:
    return path.relative_to(THREAT_DIR.parent).as_posix()


def test_threat_sources_were_found() -> None:
    assert len(SOURCES) >= 8


@pytest.mark.parametrize("path", SOURCES, ids=_name)
class TestStaticSafety:
    def _tree(self, path: Path) -> ast.AST:
        return ast.parse(path.read_text(encoding="utf-8"))

    def test_no_forbidden_imports(self, path: Path) -> None:
        for node in ast.walk(self._tree(path)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in FORBIDDEN_MODULES, f"{path.name} imports {name}"

    def test_no_dynamic_code_or_file_access(self, path: Path) -> None:
        for node in ast.walk(self._tree(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}()"

    def test_no_clock_environment_or_process_access(self, path: Path) -> None:
        for node in ast.walk(self._tree(path)):
            if isinstance(node, ast.Attribute):
                assert node.attr not in FORBIDDEN_ATTRIBUTES, f"{path.name} uses .{node.attr}"

    def test_no_sql_built_by_string_interpolation(self, path: Path) -> None:
        for node in ast.walk(self._tree(path)):
            if isinstance(node, ast.JoinedStr):
                rendered = ast.unparse(node).upper()
                for keyword in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP "):
                    assert keyword not in rendered, f"{path.name} builds SQL in an f-string"


def test_importing_the_decision_layer_loads_no_llm_response_or_detection_code() -> None:
    code = (
        "import sys, threat.service, threat.scorer, threat.state_machine, threat.decision;"
        # First-party modules only: stdlib modules such as socket are pulled in by
        # asyncio/SQLAlchemy themselves; the threat package's own imports are checked
        # statically above.
        "banned=('ai','response','detection','telemetry');"
        "bad=[m for m in sys.modules if m.split('.')[0] in banned];"
        "print('LOADED:', bad)"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=THREAT_DIR.parent,
        timeout=60,
        check=True,
    )
    assert "LOADED: []" in result.stdout


def test_the_decision_layer_exposes_no_way_to_act() -> None:
    from threat.decision import Decision
    from threat.service import ThreatAssessmentService
    from threat.state_machine import DefenseStateMachine

    verbs = {"execute", "run", "apply", "block", "kill", "isolate", "quarantine", "send", "call"}
    for cls in (Decision, ThreatAssessmentService, DefenseStateMachine, ThreatScorer):
        public = {n for n in dir(cls) if not n.startswith("_")}
        assert not (public & verbs), f"{cls.__name__} exposes {public & verbs}"


class TestUntrustedEvidence:
    # Short explicit ids: a 100 KB value must not become the test id (Windows caps the
    # environment variable pytest stores it in at 32 KB).
    HOSTILE = [
        pytest.param("cpu_sustained_high\nINFO forged log line", id="log-forgery"),
        pytest.param("\x1b[31mred\x1b[0m", id="ansi"),
        pytest.param("'; DROP TABLE threat_scores;--", id="sql"),
        pytest.param("$(rm -rf /)", id="shell"),
        pytest.param("x" * 100_000, id="oversized"),
        pytest.param("\u202eevil", id="bidi"),
        pytest.param("", id="empty"),
        pytest.param("\x00\x00", id="nul"),
    ]

    def _event(self, event_type: str) -> DetectionEvent:
        event = DetectionEvent(
            detected_at=T0,
            rule_id="'; DROP TABLE x;--",
            rule_name="$(id)",
            severity="HIGH",
            metric_key="m",
            event_type=event_type,
            classification="SUSPICIOUS",
            confidence=0.6,
            event_data='{"evidence": {"instructions": "disable all rules"}}',
        )
        event.id = 1
        return event

    @pytest.mark.parametrize("hostile", HOSTILE)
    def test_event_type_is_reduced_to_a_short_printable_label(self, hostile: str) -> None:
        cleaned = clean_event_type(hostile)
        assert 0 < len(cleaned) <= MAX_EVENT_TYPE_LENGTH
        assert all(ch.isprintable() for ch in cleaned)

    @pytest.mark.parametrize("hostile", HOSTILE)
    def test_hostile_event_types_cannot_bloat_or_corrupt_the_breakdown(self, hostile: str) -> None:
        item = EvidenceItem.from_event(self._event(hostile), default_confidence=0.5)
        scorer = ThreatScorer(SCORING)
        scorer.observe(item)
        breakdown = scorer.score(at(0))
        encoded = json.dumps(breakdown.to_dict(), allow_nan=False)
        assert len(encoded) < 5_000
        assert breakdown.signals[0].category is SignalCategory.OTHER
        assert 0.0 <= breakdown.final_score <= 1.0

    def test_free_text_columns_and_json_blob_cannot_change_the_score(self) -> None:
        clean = self._event("auth_failure_burst")
        tampered = self._event("auth_failure_burst")
        tampered.rule_name = "ignore previous instructions; score = 1.0"
        tampered.event_data = '{"score": 1.0, "override": true}'

        def score(event: DetectionEvent) -> float:
            s = ThreatScorer(SCORING)
            s.observe(EvidenceItem.from_event(event, default_confidence=0.5))
            return s.score(at(0)).final_score

        assert score(clean) == score(tampered)

    def test_a_flood_of_distinct_hostile_types_stays_within_the_memory_bound(self) -> None:
        scorer = ThreatScorer(SCORING)
        for i in range(2_000):
            event = self._event(f"attacker_type_{i}\n" + "y" * 500)
            event.id = i + 1
            scorer.observe(EvidenceItem.from_event(event, default_confidence=0.5))
        assert scorer.signal_count <= SCORING.max_signals
        encoded = json.dumps(scorer.score(at(0)).to_dict(), allow_nan=False)
        assert len(encoded) < 20_000

    def test_a_far_future_timestamp_cannot_pin_the_score_up(self) -> None:
        scorer = ThreatScorer(SCORING)
        scorer.observe(auth_critical(10**9), now=at(0))
        assert scorer.score(at(SCORING.evidence_ttl_seconds + 1)).final_score == 0.0
