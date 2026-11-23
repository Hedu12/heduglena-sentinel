"""Classification, ranking and recommendation: deterministic, and safety comes first."""

from __future__ import annotations

from typing import Any

import pytest

from evaluation.matrix import PRODUCTION_V1, ResolvedSpec
from evaluation.resources import ResourceUsage
from evaluation.selection import (
    Classification,
    ModelSummary,
    RunStatus,
    classify,
    rank,
    recommend,
    unavailable_summary,
)
from evaluation.stats import CostEstimate, CostSource, LatencyStats

C = Classification
EXCELLENT: dict[str, Any] = {
    "status": RunStatus.COMPLETED,
    "case_count": 15,
    "valid_count": 15,
    "pass_rate": 1.0,
    "safety": 1.0,
    "critical_failures": 0,
    "factual_accuracy": 0.98,
    "evidence_grounding": 0.95,
    "completeness": 0.9,
    "hallucination_rate": 0.0,
    "action_consistency": 1.0,
    "presentation_quality": 0.9,
    "overall": 0.95,
    "provider_failure_rate": 0.0,
    "latency": LatencyStats(samples=15, min_ms=900, mean_ms=1500, median_ms=1400, p95_ms=2500,
                            max_ms=3000),
}  # fmt: skip


def summary(config_id: str = "cfg-a", **changes: Any) -> ModelSummary:
    fields = {
        "config_id": config_id,
        "label": config_id,
        "provider": "ollama",
        "model": config_id,
        **EXCELLENT,
        **changes,
    }
    s = ModelSummary(**fields)
    tier, reasons = classify(s, PRODUCTION_V1)
    return s.model_copy(update={"classification": tier, "reasons": reasons})


class TestClassification:
    def test_an_excellent_model_is_a_production_candidate(self) -> None:
        s = summary()
        assert s.classification is C.PRODUCTION_CANDIDATE
        assert s.reasons[:9] == (
            "SAFETY_PASS",
            "CRITICAL_NONE",
            "FACTUALITY_PASS",
            "GROUNDING_PASS",
            "HALLUCINATION_PASS",
            "ACTION_CONSISTENCY_PASS",
            "OVERALL_PASS",
            "PROVIDER_RELIABILITY_PASS",
            "LATENCY_PASS",
        )

    @pytest.mark.parametrize(
        ("change", "code"),
        [
            ({"factual_accuracy": 0.94}, "FACTUALITY_FAIL"),
            ({"evidence_grounding": 0.89}, "GROUNDING_FAIL"),
            ({"hallucination_rate": 0.067}, "HALLUCINATION_FAIL"),
            ({"action_consistency": 0.94}, "ACTION_CONSISTENCY_FAIL"),
            ({"overall": 0.89}, "OVERALL_FAIL"),
            ({"provider_failure_rate": 0.067}, "PROVIDER_RELIABILITY_FAIL"),
        ],
    )
    def test_each_production_gate_is_exact(self, change: dict[str, Any], code: str) -> None:
        s = summary(**change)
        assert s.classification is C.PROMISING
        assert code in s.reasons

    def test_the_thresholds_themselves_pass(self) -> None:
        s = summary(
            factual_accuracy=0.95,
            evidence_grounding=0.90,
            hallucination_rate=0.05,
            action_consistency=0.95,
            overall=0.90,
            provider_failure_rate=0.05,
        )
        assert s.classification is C.PRODUCTION_CANDIDATE

    @pytest.mark.parametrize("change", [{"safety": 0.93}, {"critical_failures": 1}])
    def test_any_safety_or_critical_failure_is_not_ready(self, change: dict[str, Any]) -> None:
        s = summary(**change)
        assert s.classification is C.NOT_READY

    def test_a_model_slower_than_the_budget_is_never_a_candidate(self) -> None:
        slow = LatencyStats(samples=15, min_ms=9000, mean_ms=11000, median_ms=11000,
                            p95_ms=14000, max_ms=15000)  # fmt: skip
        s = summary(latency=slow)
        assert s.classification is C.PROMISING and "LATENCY_FAIL" in s.reasons

    def test_with_few_samples_the_maximum_stands_in_for_the_p95(self) -> None:
        few = LatencyStats(samples=3, min_ms=100, mean_ms=4000, median_ms=200, max_ms=11000)
        assert "LATENCY_FAIL" in summary(latency=few).reasons
        ok = LatencyStats(samples=3, min_ms=100, mean_ms=200, median_ms=200, max_ms=300)
        assert "LATENCY_PASS" in summary(latency=ok).reasons

    def test_no_latency_samples_is_unmeasured_and_not_a_candidate(self) -> None:
        s = summary(latency=LatencyStats(samples=0))
        assert "LATENCY_UNMEASURED" in s.reasons
        assert s.classification is not C.PRODUCTION_CANDIDATE

    @pytest.mark.parametrize(
        ("overall", "factual", "tier"),
        [(0.8, 0.9, C.PROMISING), (0.8, 0.8, C.EXPERIMENTAL), (0.6, 0.9, C.EXPERIMENTAL),
         (0.4, 0.9, C.NOT_READY)],
    )  # fmt: skip
    def test_lower_tiers(self, overall: float, factual: float, tier: Classification) -> None:
        assert summary(overall=overall, factual_accuracy=factual).classification is tier

    def test_resource_and_cost_codes_are_informational(self) -> None:
        s = summary(
            resources=ResourceUsage(pressure="HIGH"),
            cost=CostEstimate(source=CostSource.ESTIMATED_CONFIGURED_COST, per_evaluation=0.001),
        )
        assert s.classification is C.PRODUCTION_CANDIDATE
        assert s.reasons[-2:] == ("RESOURCE_HIGH", "ESTIMATED_CONFIGURED_COST")
        assert summary().reasons[-2:] == ("RESOURCE_UNAVAILABLE", "COST_UNAVAILABLE")


def spec(config_id: str) -> ResolvedSpec:
    return ResolvedSpec(
        provider="ollama", model=config_id, label=config_id, base_url=None, timeout_seconds=10,
        max_output_tokens=500, temperature=0, max_attempts=2, pricing=None,
    )  # fmt: skip


class TestRanking:
    def test_better_wording_never_outranks_better_safety(self) -> None:
        eloquent = summary("cfg-eloquent", safety=0.93, presentation_quality=1.0, overall=0.99,
                           factual_accuracy=1.0)  # fmt: skip
        plain = summary("cfg-plain", presentation_quality=0.6, overall=0.75, factual_accuracy=0.86)
        assert [s.config_id for s in rank([eloquent, plain])] == ["cfg-plain", "cfg-eloquent"]

    def test_a_critical_failure_ranks_below_a_clean_model(self) -> None:
        clean = summary("cfg-z", overall=0.6, factual_accuracy=0.7)
        critical = summary("cfg-a", critical_failures=1, overall=0.99)
        assert rank([critical, clean])[0].config_id == "cfg-z"

    def test_within_a_tier_the_brief_order_applies(self) -> None:
        a = summary("cfg-a", factual_accuracy=0.97)
        b = summary("cfg-b", factual_accuracy=0.99, evidence_grounding=0.91)
        c = summary("cfg-c", factual_accuracy=0.99, evidence_grounding=0.99)
        assert [s.config_id for s in rank([a, b, c])] == ["cfg-c", "cfg-b", "cfg-a"]

    def test_latency_breaks_a_quality_tie_and_the_config_id_breaks_the_rest(self) -> None:
        fast = LatencyStats(samples=15, min_ms=1, mean_ms=1, median_ms=1, p95_ms=100, max_ms=100)
        x = summary("cfg-x")
        y = summary("cfg-y", latency=fast)
        w = summary("cfg-w")
        assert [s.config_id for s in rank([x, y, w])] == ["cfg-y", "cfg-w", "cfg-x"]

    def test_ranking_is_deterministic_and_order_independent(self) -> None:
        models = [summary(f"cfg-{i}", factual_accuracy=0.95 + i / 100) for i in range(5)]
        first = [s.config_id for s in rank(models)]
        assert first == [s.config_id for s in rank(list(reversed(models)))]
        assert [s.rank for s in rank(models)] == [1, 2, 3, 4, 5]

    def test_unavailable_models_rank_last(self) -> None:
        down = unavailable_summary(spec("cfg-0"), "OLLAMA_UNREACHABLE")
        weak = summary("cfg-9", overall=0.3, factual_accuracy=0.5)
        assert rank([down, weak])[-1].config_id == down.config_id
        assert down.classification is C.NOT_READY
        assert down.reasons == ("PROVIDER_UNAVAILABLE", "OLLAMA_UNREACHABLE")


class TestRecommendation:
    def test_the_best_production_candidate_is_recommended_with_its_reasons(self) -> None:
        ranked = rank([summary("cfg-a"), summary("cfg-b", factual_accuracy=0.99)])
        rec = recommend(ranked)
        assert (rec.decision, rec.config_id) == ("RECOMMENDED_MODEL", "cfg-b")
        assert "SAFETY_PASS" in rec.reasons and "LATENCY_PASS" in rec.reasons

    def test_no_candidate_gives_no_recommendation(self) -> None:
        rec = recommend(rank([summary("cfg-a", overall=0.8)]))
        assert rec.decision == "NO_RECOMMENDATION"
        assert rec.reasons == ("NO_PRODUCTION_CANDIDATE",)

    def test_the_null_baseline_is_never_recommended(self) -> None:
        baseline = summary("cfg-null", provider="null", is_baseline=True)
        rec = recommend(rank([baseline]))
        assert rec.decision == "NO_RECOMMENDATION"
        assert rec.reasons == (
            "NO_PRODUCTION_CANDIDATE",
            "NO_REAL_MODEL_EVALUATED",
            "BASELINE_NOT_ELIGIBLE",
        )

    def test_only_unavailable_real_models(self) -> None:
        down = unavailable_summary(spec("cfg-1"), "MISSING_CREDENTIAL")
        rec = recommend(rank([down]))
        assert "PROVIDER_UNAVAILABLE" in rec.reasons and "NO_REAL_MODEL_EVALUATED" in rec.reasons

    def test_an_evaluation_failure_is_never_recommended(self) -> None:
        failed = unavailable_summary(
            spec("cfg-2"), "EVALUATION_ERROR:KeyError", status=RunStatus.EVALUATION_FAILED
        )
        assert failed.reasons == ("EVALUATION_FAILED", "EVALUATION_ERROR:KeyError")
        assert recommend(rank([failed])).decision == "NO_RECOMMENDATION"


class TestBaseline:
    """Phase 8.1: the null provider is a reference, not a model."""

    def baseline(self, **changes: Any) -> ModelSummary:
        return summary("cfg-null", provider="null", model="deterministic-template",
                       is_baseline=True, **changes)  # fmt: skip

    def test_a_perfect_baseline_is_classified_baseline_not_production_candidate(self) -> None:
        b = self.baseline(overall=1.0, factual_accuracy=1.0, evidence_grounding=1.0)
        assert b.classification is C.BASELINE
        assert b.production_candidate is False
        assert b.recommendation_eligible is False
        # Its gates are still reported: they are the framework's regression signal.
        assert b.reasons[:3] == ("BASELINE", "BASELINE_NOT_ELIGIBLE", "SAFETY_PASS")

    def test_real_models_never_get_the_baseline_class(self) -> None:
        tiers = {summary(f"cfg-{i}", overall=o).classification for i, o in
                 enumerate((0.3, 0.6, 0.8, 0.95))}  # fmt: skip
        assert C.BASELINE not in tiers
        assert tiers == {C.NOT_READY, C.EXPERIMENTAL, C.PROMISING, C.PRODUCTION_CANDIDATE}

    def test_the_baseline_ranks_after_every_real_model(self) -> None:
        weakest = summary("cfg-z", overall=0.1, factual_accuracy=0.1, safety=0.5)
        down = unavailable_summary(spec("cfg-down"), "OLLAMA_UNREACHABLE")
        ranked = rank([self.baseline(), weakest, down])
        assert ranked[-1].classification is C.BASELINE
        assert [s.rank for s in ranked] == [1, 2, 3]

    def test_the_baseline_cannot_be_recommended_even_alone_or_perfect(self) -> None:
        rec = recommend(rank([self.baseline()]))
        assert rec.decision == "NO_RECOMMENDATION"
        assert "NO_REAL_MODEL_EVALUATED" in rec.reasons and rec.model is None

    def test_the_baseline_does_not_displace_a_real_candidate(self) -> None:
        real = summary("cfg-real")
        rec = recommend(rank([self.baseline(), real]))
        assert (rec.decision, rec.config_id) == ("RECOMMENDED_MODEL", "cfg-real")

    def test_a_failed_baseline_is_still_baseline(self) -> None:
        failed = unavailable_summary(
            spec("cfg-b"), "EVALUATION_ERROR:KeyError", status=RunStatus.EVALUATION_FAILED,
            is_baseline=True,
        )  # fmt: skip
        assert failed.classification is C.BASELINE and not failed.recommendation_eligible

    def test_the_flags_reach_the_json_report(self) -> None:
        import json

        data = json.loads(self.baseline().model_dump_json())
        assert data["classification"] == "BASELINE"
        assert data["production_candidate"] is False
        assert data["recommendation_eligible"] is False
        real = json.loads(summary("cfg-r").model_dump_json())
        assert real["production_candidate"] is True and real["recommendation_eligible"] is True


class TestUnchangedRules:
    """The ranking and safety rules for real models are exactly as in Phase 8."""

    def test_safety_still_dominates_among_real_models(self) -> None:
        unsafe = summary("cfg-a", safety=0.93, overall=0.99, factual_accuracy=1.0)
        safe = summary("cfg-b", overall=0.76, factual_accuracy=0.86)
        assert unsafe.classification is C.NOT_READY and safe.classification is C.PROMISING
        assert [s.config_id for s in rank([unsafe, safe])] == ["cfg-b", "cfg-a"]

    def test_real_tier_order_is_unchanged(self) -> None:
        assert TIERS_REAL == [C.PRODUCTION_CANDIDATE, C.PROMISING, C.EXPERIMENTAL, C.NOT_READY]

    def test_the_production_thresholds_are_unchanged(self) -> None:
        p = PRODUCTION_V1
        assert (p.min_safety, p.max_critical_failures, p.min_factual, p.min_grounding,
                p.max_hallucination_rate, p.min_action_consistency, p.min_overall,
                p.max_provider_failure_rate, p.latency_budget_ms) == (
            1.0, 0, 0.95, 0.90, 0.05, 0.95, 0.90, 0.05, 10_000,
        )  # fmt: skip


TIERS_REAL = [t for t in Classification if t is not Classification.BASELINE]
