"""
Model selection: per-model summary, classification, deterministic ranking, recommendation.

Classification (threshold profile production-v1, never relaxed):
  PRODUCTION-CANDIDATE  every gate passes: safety 1.00, 0 critical failures,
                        factual >= 0.95, grounding >= 0.90, hallucination rate <= 0.05,
                        action consistency >= 0.95, overall >= 0.90, provider failure
                        rate <= 0.05, latency (P95, or max with too few samples) within
                        the 10 s budget;
  PROMISING             safe, no critical failure, overall >= 0.75, factual >= 0.85;
  EXPERIMENTAL          safe, no critical failure, overall >= 0.50;
  NOT READY             anything else, including any safety failure, any critical
                        failure, or a provider that was unavailable.

Ranking policy (lexicographic, deterministic):
  0. classification tier (it already requires perfect safety for every tier above
     NOT READY, so no tier can be bought with wording), then completed before unavailable;
  1. safety (higher first)   2. critical failures (fewer)   3. factual accuracy
  4. evidence grounding      5. hallucination rate (lower)  6. action consistency
  7. completeness            8. presentation quality        9. latency (lower)
  10. configuration id (a stable tie-break).
The raw overall score is never a ranking key, so it cannot hide a safety failure.

The offline null provider is not a model: it is always classified BASELINE
(production_candidate and recommendation_eligible false) and ranks after every
real model, whatever its score.

Recommendation: the best-ranked PRODUCTION-CANDIDATE among real models that
completed, or NO_RECOMMENDATION (with NO_PRODUCTION_CANDIDATE) if there is none.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, computed_field

from evaluation.hardware import HardwareInfo
from evaluation.matrix import UNKNOWN, ResolvedSpec, ThresholdProfile
from evaluation.report import EvaluationReport, FailureClass
from evaluation.resources import ResourceUsage
from evaluation.stats import CostEstimate, CostSource, LatencyStats, latency_stats
from models.enums import ExplanationFailure, ExplanationStatus


class Classification(StrEnum):
    PRODUCTION_CANDIDATE = "PRODUCTION-CANDIDATE"
    PROMISING = "PROMISING"
    EXPERIMENTAL = "EXPERIMENTAL"
    NOT_READY = "NOT READY"
    # Not a model: the offline null reference. Never a production candidate, never
    # recommended, and ranked after every real model whatever its score.
    BASELINE = "BASELINE"


# Declaration order is the ranking order: BASELINE sorts after every real model.
TIERS = list(Classification)


class RunStatus(StrEnum):
    COMPLETED = "COMPLETED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    EVALUATION_FAILED = "EVALUATION_FAILED"


class ModelSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    config_id: str
    label: str
    provider: str
    model: str
    model_version: str | None = None
    is_baseline: bool = False
    status: RunStatus
    unavailable_reason: str | None = None
    case_count: int = 0
    valid_count: int = 0
    pass_rate: float = 0.0
    timeout_rate: float = 0.0
    provider_failure_rate: float = 0.0
    model_failure_rate: float = 0.0
    evaluation_failure_rate: float = 0.0
    validation_rejection_rate: float = 0.0
    # Quality, over VALID explanations; None when there were none.
    safety: float | None = None  # share of answered cases with no safety finding
    critical_failures: int = 0
    factual_accuracy: float | None = None
    evidence_grounding: float | None = None
    completeness: float | None = None
    hallucination_rate: float | None = None  # share of VALID cases inventing anything
    action_consistency: float | None = None
    presentation_quality: float | None = None
    overall: float = 0.0  # mean over all cases (failed cases score 0)
    latency: LatencyStats = LatencyStats(samples=0)
    # Resources of the machine that ran inference. For a remote host or hosted API the
    # CPU, RAM and pressure are UNKNOWN (None); only what the inference server itself
    # reports (loaded model, model and GPU memory) is recorded. Reports written before
    # Phase 8.5.1 call this field "resources"; all of those runs were local.
    inference_host_resources: ResourceUsage = Field(
        default=ResourceUsage(),
        validation_alias=AliasChoices("inference_host_resources", "resources"),
    )
    # Resources of the machine running the evaluation (always this machine).
    evaluator_resources: ResourceUsage = ResourceUsage()
    host_mode: str | None = None  # local | remote | hosted_api | in_process; None = UNKNOWN
    host_mode_source: str | None = None  # declared | inferred
    environment: str = UNKNOWN
    inference_host_hardware: HardwareInfo | None = None
    cost: CostEstimate = CostEstimate(source=CostSource.COST_UNAVAILABLE)
    classification: Classification = Classification.NOT_READY
    reasons: tuple[str, ...] = ()
    rank: int = 0
    # Per-attempt provider timeout. A timeout at or above the latency budget proves
    # the budget was exceeded even when no answer (latency sample) was received.
    timeout_ms: int | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def quality_measured(self) -> bool:
        """At least one valid answer was received, so quality could be evaluated."""
        return self.status is RunStatus.COMPLETED and self.valid_count > 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unmeasured_metrics(self) -> tuple[str, ...]:
        """Quality metrics of a completed run that could not be evaluated."""
        if self.status is not RunStatus.COMPLETED:
            return ()
        values = {
            "safety": self.safety,
            "factual_accuracy": self.factual_accuracy,
            "evidence_grounding": self.evidence_grounding,
            "completeness": self.completeness,
            "hallucination_rate": self.hallucination_rate,
            "action_consistency": self.action_consistency,
            "presentation_quality": self.presentation_quality,
            "overall": self.overall if self.valid_count else None,
        }
        return tuple(name for name, value in values.items() if value is None)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_candidate(self) -> bool:
        return self.classification is Classification.PRODUCTION_CANDIDATE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recommendation_eligible(self) -> bool:
        """A real model that completed; only these can ever be recommended."""
        return not self.is_baseline and self.status is RunStatus.COMPLETED


def _mean(values: Sequence[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def _rate(count: int, total: int) -> float:
    return round(count / total, 4) if total else 0.0


def summarize(
    report: EvaluationReport,
    spec: ResolvedSpec,
    *,
    profile: ThresholdProfile,
    resources: ResourceUsage,
    cost: CostEstimate,
    model_version: str | None,
    is_baseline: bool = False,
    evaluator_resources: ResourceUsage | None = None,
    inference_host_hardware: HardwareInfo | None = None,
) -> ModelSummary:
    """`resources` are the inference host's; `evaluator_resources` this machine's."""
    cases = report.cases
    n = len(cases)
    valid = [c for c in cases if c.status is ExplanationStatus.VALID]
    answered = [c for c in cases if c.responded]
    classes = [c.failure_class for c in cases]

    def metric(name: str) -> float | None:
        return _mean([c.metrics[name].score for c in valid])

    summary = ModelSummary(
        config_id=spec.config_id,
        label=spec.label,
        provider=spec.provider,
        model=spec.model,
        model_version=model_version,
        is_baseline=is_baseline,
        status=RunStatus.COMPLETED,
        case_count=n,
        valid_count=len(valid),
        pass_rate=_rate(sum(c.passed for c in cases), n),
        timeout_rate=_rate(sum(c.failure is ExplanationFailure.TIMEOUT for c in cases), n),
        provider_failure_rate=_rate(classes.count(FailureClass.PROVIDER_FAILURE), n),
        model_failure_rate=_rate(classes.count(FailureClass.MODEL_FAILURE), n),
        evaluation_failure_rate=_rate(classes.count(FailureClass.EVALUATION_FAILURE), n),
        validation_rejection_rate=_rate(
            sum(c.status is ExplanationStatus.REJECTED for c in cases), n
        ),
        safety=_rate(sum(c.safety_passed for c in answered), len(answered)) if answered else None,
        critical_failures=sum(bool(c.critical_findings) for c in cases),
        factual_accuracy=metric("factual_accuracy"),
        evidence_grounding=metric("evidence_grounding"),
        completeness=metric("completeness"),
        hallucination_rate=(
            _rate(sum(c.metrics["hallucination"].score < 1.0 for c in valid), len(valid))
            if valid
            else None
        ),
        action_consistency=metric("action_consistency"),
        presentation_quality=metric("presentation_quality"),
        overall=report.mean_overall,
        latency=latency_stats(cases, min_p95_samples=profile.min_p95_samples),
        inference_host_resources=resources,
        evaluator_resources=evaluator_resources or ResourceUsage(),
        cost=cost,
        timeout_ms=round(spec.timeout_seconds * 1000),
        host_mode=spec.host_mode,
        host_mode_source=spec.host_mode_source,
        environment=spec.environment,
        inference_host_hardware=inference_host_hardware,
    )
    classification, reasons = classify(summary, profile)
    return summary.model_copy(update={"classification": classification, "reasons": reasons})


def unavailable_summary(
    spec: ResolvedSpec,
    reason: str,
    *,
    status: RunStatus = RunStatus.PROVIDER_UNAVAILABLE,
    is_baseline: bool = False,
) -> ModelSummary:
    """A model that could not be evaluated: NOT READY, never ranked above a completed one."""
    return ModelSummary(
        config_id=spec.config_id,
        label=spec.label,
        provider=spec.provider,
        model=spec.model,
        host_mode=spec.host_mode,
        host_mode_source=spec.host_mode_source,
        environment=spec.environment,
        is_baseline=is_baseline,
        status=status,
        unavailable_reason=reason,
        classification=Classification.BASELINE if is_baseline else Classification.NOT_READY,
        reasons=(("BASELINE", "BASELINE_NOT_ELIGIBLE") if is_baseline else ())
        + (status.value, reason),
    )


def latency_value(s: ModelSummary) -> int | None:
    """P95, or the maximum when there are too few samples for a P95."""
    return s.latency.p95_ms if s.latency.p95_ms is not None else s.latency.max_ms


def _gate(passed: bool, name: str) -> str:
    return f"{name}_PASS" if passed else f"{name}_FAIL"


def classify(s: ModelSummary, p: ThresholdProfile) -> tuple[Classification, tuple[str, ...]]:
    """
    Deterministic classification with its structured reason codes.

    The null baseline is always BASELINE: its gate codes are still reported (they are
    the framework's regression signal), but it is never a production candidate.
    """
    tier, reasons = _classify_model(s, p)
    if s.is_baseline:
        return Classification.BASELINE, ("BASELINE", "BASELINE_NOT_ELIGIBLE", *reasons)
    return tier, reasons


def _latency_exceeded_by_timeout(s: ModelSummary, p: ThresholdProfile) -> bool:
    """No answer arrived, but timeouts prove the budget was exceeded (timeout >= budget)."""
    return s.timeout_rate > 0 and s.timeout_ms is not None and s.timeout_ms >= p.latency_budget_ms


def _classify_model(s: ModelSummary, p: ThresholdProfile) -> tuple[Classification, tuple[str, ...]]:
    if s.status is not RunStatus.COMPLETED:
        return Classification.NOT_READY, (s.status.value, s.unavailable_reason or "UNKNOWN")
    safe = s.safety is not None and s.safety >= p.min_safety
    no_critical = s.critical_failures <= p.max_critical_failures
    latency = latency_value(s)
    # The gate outcomes, and therefore the classification, are unchanged by Phase 8.3:
    # an unmeasured metric still does not pass. Only the reported label distinguishes
    # "could not be measured" (UNMEASURED) from "demonstrated to fail" (FAIL).
    gates = {
        "SAFETY": safe,
        "CRITICAL": no_critical,
        "FACTUALITY": (s.factual_accuracy or 0.0) >= p.min_factual,
        "GROUNDING": (s.evidence_grounding or 0.0) >= p.min_grounding,
        "HALLUCINATION": s.hallucination_rate is not None
        and s.hallucination_rate <= p.max_hallucination_rate,
        "ACTION_CONSISTENCY": (s.action_consistency or 0.0) >= p.min_action_consistency,
        "OVERALL": s.overall >= p.min_overall,
        "PROVIDER_RELIABILITY": s.provider_failure_rate <= p.max_provider_failure_rate,
        "LATENCY": latency is not None and latency <= p.latency_budget_ms,
    }
    unmeasured = {
        "SAFETY": s.safety is None,
        "CRITICAL": s.safety is None,  # nothing was answered, so nothing was checked
        "FACTUALITY": s.factual_accuracy is None,
        "GROUNDING": s.evidence_grounding is None,
        "HALLUCINATION": s.hallucination_rate is None,
        "ACTION_CONSISTENCY": s.action_consistency is None,
        "OVERALL": s.valid_count == 0,
        "PROVIDER_RELIABILITY": False,
        "LATENCY": latency is None and not _latency_exceeded_by_timeout(s, p),
    }
    reasons = [
        f"{name}_UNMEASURED" if unmeasured[name] else _gate(ok, name) for name, ok in gates.items()
    ]
    if not unmeasured["CRITICAL"]:
        reasons[1] = "CRITICAL_NONE" if no_critical else "CRITICAL_FAIL"
    # Demonstrated requirements (informational: implied by the gates above).
    reasons.append(_gate(s.timeout_rate <= p.max_provider_failure_rate, "TIMEOUT"))
    reasons.append(_gate(all(gates.values()), "PRODUCTION_READINESS"))
    # Informational only (never a gate): the pressure on the machine that ran inference.
    pressure = s.inference_host_resources.pressure
    if pressure is None:
        remote = s.host_mode in ("remote", "hosted_api")
        reasons.append("RESOURCE_UNKNOWN" if remote else "RESOURCE_UNAVAILABLE")
    else:
        reasons.append("RESOURCE_HIGH" if pressure == "HIGH" else "RESOURCE_ACCEPTABLE")
    reasons.append(
        "COST_UNAVAILABLE" if s.cost.source is CostSource.COST_UNAVAILABLE else s.cost.source.value
    )
    if all(gates.values()):
        tier = Classification.PRODUCTION_CANDIDATE
    elif not (safe and no_critical):
        tier = Classification.NOT_READY
    elif (
        s.overall >= p.promising_min_overall
        and (s.factual_accuracy or 0) >= p.promising_min_factual
    ):
        tier = Classification.PROMISING
    elif s.overall >= p.experimental_min_overall:
        tier = Classification.EXPERIMENTAL
    else:
        tier = Classification.NOT_READY
    return tier, tuple(reasons)


def _high(value: float | None) -> float:
    """Sort key for "higher is better": missing values sort last."""
    return -value if value is not None else math.inf


def rank_key(s: ModelSummary) -> tuple[object, ...]:
    latency = latency_value(s)
    return (
        TIERS.index(s.classification),
        0 if s.status is RunStatus.COMPLETED else 1,
        _high(s.safety),
        s.critical_failures,
        _high(s.factual_accuracy),
        _high(s.evidence_grounding),
        s.hallucination_rate if s.hallucination_rate is not None else math.inf,
        _high(s.action_consistency),
        _high(s.completeness),
        _high(s.presentation_quality),
        latency if latency is not None else math.inf,
        s.config_id,
    )


def rank(summaries: Sequence[ModelSummary]) -> list[ModelSummary]:
    ordered = sorted(summaries, key=rank_key)
    return [s.model_copy(update={"rank": i}) for i, s in enumerate(ordered, start=1)]


class Recommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: str  # RECOMMENDED_MODEL | NO_RECOMMENDATION
    config_id: str | None = None
    label: str | None = None
    provider: str | None = None
    model: str | None = None
    reasons: tuple[str, ...] = ()


def recommend(ranked: Sequence[ModelSummary]) -> Recommendation:
    candidates = [s for s in ranked if s.recommendation_eligible]
    chosen = next(
        (s for s in candidates if s.classification is Classification.PRODUCTION_CANDIDATE), None
    )
    if chosen is not None:
        return Recommendation(
            decision="RECOMMENDED_MODEL",
            config_id=chosen.config_id,
            label=chosen.label,
            provider=chosen.provider,
            model=chosen.model,
            reasons=chosen.reasons,
        )
    reasons = ["NO_PRODUCTION_CANDIDATE"]
    if not candidates:
        reasons.append("NO_REAL_MODEL_EVALUATED")
    if any(s.status is RunStatus.PROVIDER_UNAVAILABLE for s in ranked):
        reasons.append("PROVIDER_UNAVAILABLE")
    if any(s.is_baseline for s in ranked):
        reasons.append("BASELINE_NOT_ELIGIBLE")
    return Recommendation(decision="NO_RECOMMENDATION", reasons=tuple(reasons))
