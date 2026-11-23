"""
Phase 8.3: reporting semantics for a model with zero valid answers.

UNMEASURED means "could not be evaluated, no valid answer"; FAIL means
"demonstrated to fail". Neither verdict nor ranking changes: an unmeasured
requirement still never passes. Diagnostic evidence is reported, never scored.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.config import Settings
from evaluation.__main__ import main
from evaluation.comparison import ComparisonReport, DiagnosticEvidence, load_diagnostics
from evaluation.matrix import PRODUCTION_V1, ModelSpec
from evaluation.rerender import VerdictChanged, rerender
from evaluation.resources import OllamaStatus
from evaluation.selection import Classification, ModelSummary, RunStatus, classify, rank
from evaluation.stats import LatencyStats
from evaluation.suite import Suite, SuiteResult

QUALITY_CODES = (
    "SAFETY_UNMEASURED",
    "CRITICAL_UNMEASURED",
    "FACTUALITY_UNMEASURED",
    "GROUNDING_UNMEASURED",
    "HALLUCINATION_UNMEASURED",
    "ACTION_CONSISTENCY_UNMEASURED",
    "OVERALL_UNMEASURED",
)
DEMONSTRATED = ("PROVIDER_RELIABILITY_FAIL", "LATENCY_FAIL", "TIMEOUT_FAIL",
                "PRODUCTION_READINESS_FAIL")  # fmt: skip


async def hanging(request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(5)
    return httpx.Response(500)


async def installed(base_url: str, model: str) -> OllamaStatus:
    return OllamaStatus(reachable=True, installed=True, digest="sha256:00aa11bb22cc", size_bytes=1)


async def loaded(base_url: str, model: str) -> tuple[bool | None, int | None]:
    return True, 0


def suite() -> Suite:
    ticks = iter(range(10**9))
    return Suite(
        Settings(),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        monotonic=lambda: next(ticks) / 1000,
        ollama_check=installed,
        loaded_check=loaded,
        transport=httpx.MockTransport(hanging),
    )


@pytest.fixture(autouse=True)
def steady(monkeypatch: pytest.MonkeyPatch) -> None:
    import evaluation.resources as res

    monkeypatch.setattr(res.psutil, "cpu_percent", lambda interval=None: 95.0)

    class Memory:
        percent = 93.0

    monkeypatch.setattr(res.psutil, "virtual_memory", lambda: Memory())


async def all_timeouts() -> SuiteResult:
    """A real model whose every attempt times out (0.02 s), plus the null baseline."""
    return await suite().run(
        [
            ModelSpec(provider="null"),
            ModelSpec(provider="ollama", model="slow", timeout_seconds=0.02, max_attempts=1),
        ]
    )


def model(result: SuiteResult, name: str) -> ModelSummary:
    return next(m for m in result.comparison.models if m.model == name)


class TestZeroValidAnswers:
    """Requirements 1-3: unmeasured quality, demonstrated timeouts, NOT READY."""

    async def test_quality_metrics_are_unmeasured(self) -> None:
        m = model(await all_timeouts(), "slow")
        assert m.valid_count == 0 and m.quality_measured is False
        assert m.unmeasured_metrics == (
            "safety",
            "factual_accuracy",
            "evidence_grounding",
            "completeness",
            "hallucination_rate",
            "action_consistency",
            "presentation_quality",
            "overall",
        )
        for code in QUALITY_CODES:
            assert code in m.reasons, code
        for wrong in (
            "FACTUALITY_FAIL",
            "GROUNDING_FAIL",
            "HALLUCINATION_FAIL",
            "ACTION_CONSISTENCY_FAIL",
            "OVERALL_FAIL",
            "SAFETY_FAIL",
            "CRITICAL_NONE",
        ):
            assert wrong not in m.reasons, wrong  # fmt: skip

    async def test_timeouts_and_readiness_are_demonstrated_failures(self) -> None:
        m = model(await all_timeouts(), "slow")
        for code in ("PROVIDER_RELIABILITY_FAIL", "TIMEOUT_FAIL", "PRODUCTION_READINESS_FAIL"):
            assert code in m.reasons, code
        assert (m.timeout_rate, m.provider_failure_rate, m.model_failure_rate) == (1.0, 1.0, 0.0)

    def test_a_production_length_timeout_proves_the_latency_budget_failed(self) -> None:
        # Phase 8.2: every attempt hit the 10 s production timeout, which equals the budget.
        s = ModelSummary(
            config_id="cfg-a", label="a", provider="ollama", model="llama3.2",
            status=RunStatus.COMPLETED, case_count=15, valid_count=0, timeout_rate=1.0,
            provider_failure_rate=1.0, timeout_ms=10_000,
        )  # fmt: skip
        tier, reasons = classify(s, PRODUCTION_V1)
        for code in (*DEMONSTRATED, *QUALITY_CODES):
            assert code in reasons, code
        assert tier is Classification.NOT_READY

    async def test_a_short_timeout_does_not_prove_the_budget_was_exceeded(self) -> None:
        m = model(await all_timeouts(), "slow")
        assert "LATENCY_UNMEASURED" in m.reasons and "LATENCY_FAIL" not in m.reasons
        assert "TIMEOUT_FAIL" in m.reasons and "PROVIDER_RELIABILITY_FAIL" in m.reasons

    async def test_the_verdict_is_unchanged(self) -> None:
        result = await all_timeouts()
        m = model(result, "slow")
        assert m.classification is Classification.NOT_READY
        assert m.production_candidate is False
        rec = result.comparison.recommendation
        assert rec.decision == "NO_RECOMMENDATION" and "NO_PRODUCTION_CANDIDATE" in rec.reasons

    async def test_the_reports_say_unmeasured_not_zero(self, tmp_path: Path) -> None:
        result = await all_timeouts()
        markdown = result.comparison.to_markdown()
        row = next(line for line in markdown.splitlines() if "ollama-slow" in line
                   and "UNMEASURED" in line and "| 0%" in line)  # fmt: skip
        assert "0.000" not in row
        assert "## Measurement" in markdown and "PRODUCTION_READINESS_FAIL" in markdown
        per_model = next(r.report for r in result.runs if r.spec.model == "slow")
        assert per_model is not None
        assert set(per_model.metric_means.values()) == {None}
        assert "| factual_accuracy | UNMEASURED |" in per_model.to_markdown()


class TestMeasuredModelsUnchanged:
    """Requirement 6, and a measured failure is still a FAIL."""

    def test_a_measured_shortfall_stays_fail(self) -> None:
        s = ModelSummary(
            config_id="cfg-a", label="a", provider="ollama", model="a",
            status=RunStatus.COMPLETED, case_count=15, valid_count=15, safety=1.0,
            factual_accuracy=0.5, evidence_grounding=0.5, completeness=0.5,
            hallucination_rate=0.5, action_consistency=0.5, presentation_quality=0.5,
            overall=0.5, latency=LatencyStats(samples=15, max_ms=100, p95_ms=100),
        )  # fmt: skip
        tier, reasons = classify(s, PRODUCTION_V1)
        assert {"FACTUALITY_FAIL", "GROUNDING_FAIL", "HALLUCINATION_FAIL", "OVERALL_FAIL",
                "CRITICAL_NONE", "SAFETY_PASS", "TIMEOUT_PASS",
                "PRODUCTION_READINESS_FAIL"} <= set(reasons)  # fmt: skip
        assert not any(r.endswith("_UNMEASURED") for r in reasons)
        assert tier is Classification.EXPERIMENTAL

    async def test_ranking_is_unchanged_and_the_baseline_stays_baseline(self) -> None:
        result = await all_timeouts()
        assert [m.model for m in result.comparison.models] == ["slow", "deterministic-template"]
        baseline = result.comparison.models[-1]
        assert baseline.classification is Classification.BASELINE  # requirement 5
        assert baseline.recommendation_eligible is False and baseline.quality_measured
        assert baseline.unmeasured_metrics == ()
        reranked = rank(list(reversed(result.comparison.models)))
        assert [m.config_id for m in reranked] == [m.config_id for m in result.comparison.models]


def evidence(config_id: str = "cfg-0123456789ab", **changes: Any) -> DiagnosticEvidence:
    fields: dict[str, Any] = {
        "config_id": config_id,
        "case_id": "critical-aggressive",
        "timeout_seconds": 300,
        "response_ms": 139_700,
        "prompt_tokens": 1466,
        "completion_tokens": 305,
        "tokens_per_second": 2.2,
        "validation": "SCHEMA_VIOLATION:string_type",
    }
    fields.update(changes)
    return DiagnosticEvidence(**fields)


class TestDiagnostics:
    """Requirement 4: diagnostic evidence is reported but never scored."""

    async def test_diagnostics_cannot_change_scores_classification_or_ranking(
        self, tmp_path: Path
    ) -> None:
        result = await all_timeouts()
        slow = model(result, "slow").config_id
        assert slow.startswith("cfg-")
        main_dir = tmp_path / "run"
        main_dir.mkdir()
        (main_dir / "comparison.json").write_text(result.comparison.to_json(), "utf-8")
        for run in result.runs:
            if run.report is not None:
                stem = f"{run.spec.label}-{run.spec.config_id}"
                (main_dir / f"{stem}.json").write_text(run.report.to_json(), "utf-8")
        positive = evidence(slow, validation="VALID", response_ms=100, tokens_per_second=999.0)
        with_diag = rerender(main_dir, [positive]).comparison
        without = rerender(main_dir).comparison
        assert with_diag.models == without.models
        assert with_diag.recommendation == without.recommendation
        assert with_diag.diagnostics[0].scored is False
        assert "Diagnostic evidence (not part of benchmark scoring)" in with_diag.to_markdown()

    def test_a_diagnostic_cannot_claim_to_be_scored(self) -> None:
        with pytest.raises(ValueError):
            evidence("cfg-0123456789ab", scored=True)

    @pytest.mark.parametrize(
        "change",
        [{"validation": "VALID but the model said: rm -rf /"}, {"note": "x" * 201},
         {"raw": "model text"}, {"config_id": "cfg-x"}],
    )  # fmt: skip
    def test_diagnostics_carry_codes_not_model_text(self, change: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            evidence(**{"config_id": "cfg-0123456789ab", **change})

    def test_the_loader_checks_models_and_cases(self, tmp_path: Path) -> None:
        path = tmp_path / "d.json"
        path.write_text(json.dumps([evidence("cfg-0123456789ab").model_dump()]))
        ok = load_diagnostics(
            path, config_ids={"cfg-0123456789ab"}, case_ids={"critical-aggressive"}
        )
        assert len(ok) == 1
        with pytest.raises(ValueError):
            load_diagnostics(
                path, config_ids={"cfg-ffffffffffff"}, case_ids={"critical-aggressive"}
            )
        with pytest.raises(ValueError):
            load_diagnostics(path, config_ids={"cfg-0123456789ab"}, case_ids={"other"})


class TestRerender:
    async def _saved(self, tmp_path: Path) -> tuple[Path, SuiteResult]:
        result = await all_timeouts()
        source = tmp_path / "phase8.2"
        source.mkdir()
        # Simulate a Phase 8.2 report: old wording and no timeout_ms.
        data = json.loads(result.comparison.to_json())
        for m in data["models"]:
            m.pop("timeout_ms")
            m["reasons"] = [r.replace("_UNMEASURED", "_FAIL") for r in m["reasons"]]
        (source / "comparison.json").write_text(json.dumps(data), "utf-8")
        for run in result.runs:
            if run.report is not None:
                stem = f"{run.spec.label}-{run.spec.config_id}"
                report = json.loads(run.report.to_json())
                if run.spec.model == "slow":  # Phase 8.2 ran with the 10 s production timeout
                    report["metadata"]["timeout_seconds"] = 10.0
                (source / f"{stem}.json").write_text(json.dumps(report), "utf-8")
        return source, result

    async def test_old_results_are_re_reported_with_the_same_verdict(self, tmp_path: Path) -> None:
        source, original = await self._saved(tmp_path)
        out = tmp_path / "phase8.3"
        argv = ["--rerender", str(source), "--out", str(out)]
        assert main(argv) == 0
        new = ComparisonReport.model_validate_json((out / "comparison.json").read_text("utf-8"))
        slow = next(m for m in new.models if m.model == "slow")
        assert "FACTUALITY_UNMEASURED" in slow.reasons and "LATENCY_FAIL" in slow.reasons
        assert slow.timeout_ms == 10_000  # recovered from the per-model metadata
        assert [m.classification for m in new.models] == [
            m.classification for m in original.comparison.models
        ]
        assert new.recommendation.decision == "NO_RECOMMENDATION"

    async def test_a_changed_verdict_is_refused(self, tmp_path: Path) -> None:
        source, _ = await self._saved(tmp_path)
        data = json.loads((source / "comparison.json").read_text("utf-8"))
        data["models"][0]["classification"] = "PROMISING"
        (source / "comparison.json").write_text(json.dumps(data), "utf-8")
        with pytest.raises(VerdictChanged):
            rerender(source)

    def test_rerender_refuses_model_options(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            main(["--rerender", str(tmp_path), "--provider", "null", "--out", str(tmp_path)])
