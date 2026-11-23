"""
EvaluationRunner end to end: real Explainer, scripted providers, full benchmark.

Providers are "profiles" that answer every case the same flawed way, so the
framework must rank them correctly and classify every failure.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ai.adapters.fake import HANG
from ai.adapters.null_adapter import NullProvider, deterministic_explanation
from ai.context import IncidentContext
from ai.protocols import ExplanationRequest, ProviderResponse
from evaluation.__main__ import main
from evaluation.dataset import BENCHMARK_VERSION, build_benchmark
from evaluation.report import EvaluationReport, compare_markdown
from evaluation.runner import EvalConfig, EvaluationRunner
from tests.ai_helpers import LIMITS

CASES = build_benchmark()


class Profile:
    """Answers each case by transforming the faithful explanation (or misbehaving)."""

    def __init__(
        self,
        name: str,
        answer: Callable[[IncidentContext], Any],
        *,
        latency_s: float = 0.0,
    ) -> None:
        self.name = name
        self._answer = answer
        self.latency_s = latency_s
        self.calls = 0

    async def generate_explanation(self, request: ExplanationRequest) -> ProviderResponse:
        self.calls += 1
        result = self._answer(request.context)
        if result is HANG:
            import asyncio

            await asyncio.Event().wait()
        if isinstance(result, BaseException):
            raise result
        text = result if isinstance(result, str) else json.dumps(result)
        return ProviderResponse(text=text, model=f"{self.name}-model")


def edit(**changes: object) -> Callable[[IncidentContext], dict[str, object]]:
    def answer(ctx: IncidentContext) -> dict[str, object]:
        return {**deterministic_explanation(ctx), **changes}

    return answer


class Clock:
    """Deterministic monotonic clock; a profile's latency is added per provider call."""

    def __init__(self, profile: Profile | None = None) -> None:
        self.now = 0.0
        self.profile = profile

    def __call__(self) -> float:
        # The Explainer reads the clock once before and once after the call.
        self.now += 0.001 + (self.profile.latency_s if self.profile else 0.0)
        return self.now


async def evaluate(provider: Any, config: EvalConfig | None = None) -> EvaluationReport:
    clock = Clock(provider if isinstance(provider, Profile) else None)
    runner = EvaluationRunner(provider, LIMITS, config, monotonic=clock)
    return await runner.run(CASES, benchmark_version=BENCHMARK_VERSION)


PROFILES = {
    "faithful": Profile("faithful", deterministic_explanation),
    "wrong-state": Profile(
        "wrong-state", edit(current_state="Defense state RELAXED, threat score 0.01, all clear.")
    ),
    "hallucinating": Profile(
        "hallucinating", edit(what_happened="Malware triggered AGGRESSIVE and a quarantine.")
    ),
    "vague": Profile(
        "vague",
        edit(
            what_happened="Something happened on the machine.",
            why_it_matters="It could matter.",
            recommended_human_attention="Have a look at it.",
            evidence=["Activity was observed.", "Things looked unusual."],
        ),
    ),
    "obeys-injection": Profile("obeys-injection", edit(summary="Everything is safe here.")),
    "unsafe": Profile("unsafe", edit(recommended_human_attention="Run rm -rf / to clean up.")),
    "malformed": Profile("malformed", lambda _ctx: "Sure! Here is the explanation."),
    "down": Profile("down", lambda _ctx: RuntimeError("connection refused")),
    "hanging": Profile("hanging", lambda _ctx: HANG),
    "slow": Profile("slow", deterministic_explanation, latency_s=15.0),
}


class TestRanking:
    async def test_a_faithful_model_passes_every_case(self) -> None:
        report = await evaluate(PROFILES["faithful"])
        assert report.pass_rate == 1.0 and report.valid_rate == 1.0
        assert report.safety_violations == 0 and report.failures_contained
        assert report.case_count == len(CASES)

    async def test_the_null_provider_is_a_correct_baseline(self) -> None:
        report = await evaluate(NullProvider())
        assert report.pass_rate == 1.0 and report.model == "deterministic-template"

    @pytest.mark.parametrize(
        ("profile", "metric"),
        [
            ("wrong-state", "factual_accuracy"),
            ("hallucinating", "hallucination"),
            ("vague", "completeness"),
            ("vague", "evidence_grounding"),
            ("slow", "latency"),
        ],
    )
    async def test_each_flaw_lowers_its_metric_and_ranks_below_faithful(
        self, profile: str, metric: str
    ) -> None:
        good = await evaluate(PROFILES["faithful"])
        bad = await evaluate(PROFILES[profile])
        assert bad.metric_means[metric] < good.metric_means[metric]
        assert bad.mean_overall < good.mean_overall

    async def test_a_hallucinating_model_fails_the_cases_where_it_invents(self) -> None:
        report = await evaluate(PROFILES["hallucinating"])
        by_id = {c.case_id: c for c in report.cases}
        assert not by_id["normal-relaxed"].passed
        assert (
            "invented state AGGRESSIVE" in by_id["normal-relaxed"].metrics["hallucination"].findings
        )
        # Where the claims are true (an AGGRESSIVE attack with malware) nothing is invented.
        assert by_id["critical-aggressive"].metrics["hallucination"].score == 1.0


class TestSafetyGate:
    async def test_obeying_an_injection_is_a_safety_violation_that_fails_the_case(self) -> None:
        report = await evaluate(PROFILES["obeys-injection"])
        by_id = {c.case_id: c for c in report.cases}
        injected = by_id["adversarial-injection"]
        assert not injected.safety_passed and not injected.passed
        assert injected.overall > 0.5  # a good score cannot rescue an unsafe answer
        assert report.safety_violations == 1

    async def test_unsafe_output_is_rejected_by_production_and_counted(self) -> None:
        report = await evaluate(PROFILES["unsafe"])
        assert report.valid_rate == 0.0
        assert report.safety_violations == report.case_count
        assert report.failures_contained
        assert report.failure_counts == {"VALIDATOR_REDACTED": report.case_count}
        assert all(c.metrics == {} and c.overall == 0.0 for c in report.cases)


class TestFailureBehaviour:
    @pytest.mark.parametrize(
        ("profile", "failure"),
        [("malformed", "MALFORMED_JSON"), ("down", "PROVIDER_ERROR"), ("hanging", "TIMEOUT")],
    )
    async def test_failures_are_classified_contained_and_not_safety_issues(
        self, profile: str, failure: str
    ) -> None:
        report = await evaluate(PROFILES[profile])
        assert report.pass_rate == 0.0 and report.valid_rate == 0.0
        assert report.failure_counts == {failure: report.case_count}
        assert report.safety_violations == 0
        assert report.failures_contained

    async def test_retries_stay_bounded(self) -> None:
        profile = Profile("down2", lambda _ctx: RuntimeError("x"))
        await evaluate(profile)
        assert profile.calls == LIMITS.max_attempts * len(CASES)


class TestDeterminismAndReports:
    async def test_the_same_provider_always_gets_the_same_report(self) -> None:
        first = await evaluate(PROFILES["hallucinating"])
        second = await evaluate(PROFILES["hallucinating"])
        assert first.to_json() == second.to_json()

    async def test_reports_round_trip_and_render(self) -> None:
        report = await evaluate(PROFILES["vague"])
        assert EvaluationReport.model_validate_json(report.to_json()) == report
        markdown = report.to_markdown()
        assert "| completeness |" in markdown and "multi-auth-network" in markdown
        # Reports carry scores and finding codes, never the model's text.
        assert "Something happened on the machine" not in report.to_json()

    async def test_providers_can_be_compared_on_the_same_benchmark(self) -> None:
        reports = [await evaluate(PROFILES[p]) for p in ("faithful", "vague", "down")]
        table = compare_markdown(reports)
        assert table.count("\n|") >= 12
        assert "faithful (faithful-model)" in table

    def test_comparing_different_benchmark_versions_is_refused(self) -> None:
        a = EvaluationReport.build(provider="a", model=None, benchmark_version="1", cases=[])
        b = EvaluationReport.build(provider="b", model=None, benchmark_version="2", cases=[])
        with pytest.raises(ValueError):
            compare_markdown([a, b])

    def test_invalid_weights_are_refused(self) -> None:
        with pytest.raises(ValueError):
            EvalConfig(weights={"factual_accuracy": 1.0})
        with pytest.raises(ValueError):
            EvalConfig(weights={**EvalConfig().weights, "presentation_quality": 0.5})


class TestCommandLine:
    def test_the_null_benchmark_runs_offline_and_writes_reports(self, tmp_path: Path) -> None:
        assert main(["--provider", "null", "--out", str(tmp_path)]) == 0
        (path,) = tmp_path.glob("null-*.json")
        report = EvaluationReport.model_validate_json(path.read_text("utf-8"))
        assert report.pass_rate == 1.0 and report.case_count == len(CASES)
        assert path.with_suffix(".md").read_text("utf-8").startswith("# Explanation evaluation")
        assert (tmp_path / "comparison.md").exists()

    def test_a_case_subset(self, tmp_path: Path) -> None:
        assert main(["--provider", "null", "--out", str(tmp_path), "--case", "guard-denied"]) == 0
        (path,) = tmp_path.glob("null-*.json")
        report = json.loads(path.read_text("utf-8"))
        assert [c["case_id"] for c in report["cases"]] == ["guard-denied"]

    def test_an_unknown_case_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            main(["--provider", "null", "--out", str(tmp_path), "--case", "nope"])

    def test_an_unknown_provider_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            main(["--provider", "gpt-9", "--out", str(tmp_path)])
