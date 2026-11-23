"""
Per-model evaluation reports: per-case results and aggregates, as JSON and Markdown.

Reports contain scores, fixed finding codes and case ids, never the model's
text, so they can be shared without carrying model output around. Run metadata
(provider, model, configuration id, versions, threshold profile, timestamp) makes
a report reproducible; it never contains credentials.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from evaluation.hardware import HardwareInfo
from evaluation.matrix import UNKNOWN
from models.enums import ExplanationFailure, ExplanationStatus

METRICS = (
    "factual_accuracy",
    "evidence_grounding",
    "completeness",
    "hallucination",
    "action_consistency",
    "presentation_quality",
    "latency",
)


class FailureClass(StrEnum):
    """Who failed. Provider failures are never counted as model hallucinations."""

    MODEL_FAILURE = "MODEL_FAILURE"  # the model answered, but the answer was unusable
    PROVIDER_FAILURE = "PROVIDER_FAILURE"  # no answer: timeout, error, unavailable
    EVALUATION_FAILURE = "EVALUATION_FAILURE"  # the evaluation itself could not run the case


MODEL_FAILURES = frozenset(
    {
        ExplanationFailure.EMPTY_RESPONSE,
        ExplanationFailure.OVERSIZED_OUTPUT,
        ExplanationFailure.MALFORMED_JSON,
        ExplanationFailure.SCHEMA_VIOLATION,
        ExplanationFailure.UNSAFE_CONTENT,
        ExplanationFailure.VALIDATOR_REDACTED,
    }
)
PROVIDER_FAILURES = frozenset({ExplanationFailure.TIMEOUT, ExplanationFailure.PROVIDER_ERROR})


def classify_failure(failure: ExplanationFailure | None) -> FailureClass | None:
    if failure is None:
        return None
    if failure in MODEL_FAILURES:
        return FailureClass.MODEL_FAILURE
    if failure in PROVIDER_FAILURES:
        return FailureClass.PROVIDER_FAILURE
    return FailureClass.EVALUATION_FAILURE


class MetricScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    score: float
    findings: tuple[str, ...] = ()


class CaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    category: str
    status: ExplanationStatus
    model: str | None
    latency_ms: int
    attempts: int
    failure: ExplanationFailure | None
    failure_class: FailureClass | None = None
    # The provider returned an answer (valid or not): only these count for latency.
    responded: bool = False
    failure_contained: bool
    safety_passed: bool
    safety_findings: tuple[str, ...]
    critical_findings: tuple[str, ...] = ()
    metrics: dict[str, MetricScore]
    overall: float
    passed: bool
    prompt_tokens: int | None = None
    response_tokens: int | None = None


class RunMetadata(BaseModel):
    """Everything needed to reproduce a run. Never credentials."""

    model_config = ConfigDict(frozen=True)

    evaluator_version: str
    scoring_version: str
    prompt_version: str
    benchmark_version: str
    threshold_profile: str
    config_id: str
    label: str
    provider: str
    model: str
    model_version: str | None
    base_url: str | None  # with any userinfo, query and fragment removed
    timeout_seconds: float
    max_output_tokens: int
    temperature: float
    max_attempts: int
    evaluated_at: str
    case_count: int
    # Where inference ran (Phase 8.5.1). None in reports written before it (UNKNOWN).
    host_mode: str | None = None  # local | remote | hosted_api | in_process
    host_mode_source: str | None = None  # declared | inferred
    environment: str = UNKNOWN
    evaluator_hardware: HardwareInfo | None = None
    inference_host_hardware: HardwareInfo | None = None


class EvaluationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    model: str | None
    benchmark_version: str
    cases: list[CaseResult]
    case_count: int
    pass_rate: float
    valid_rate: float
    safety_violations: int
    critical_failures: int = 0
    failures_contained: bool
    mean_overall: float
    # Mean of each metric over VALID explanations; None (UNMEASURED) when there were none.
    metric_means: dict[str, float | None]
    latency_mean_ms: float
    latency_p95_ms: int
    failure_counts: dict[str, int]
    failure_class_counts: dict[str, int] = {}
    metadata: RunMetadata | None = None

    @classmethod
    def build(
        cls,
        *,
        provider: str,
        model: str | None,
        benchmark_version: str,
        cases: Sequence[CaseResult],
        metadata: RunMetadata | None = None,
    ) -> EvaluationReport:
        n = len(cases)
        valid = [c for c in cases if c.status is ExplanationStatus.VALID]
        latencies = sorted(c.latency_ms for c in cases)
        p95 = latencies[max(0, math.ceil(0.95 * n) - 1)] if latencies else 0
        return cls(
            provider=provider,
            model=model,
            benchmark_version=benchmark_version,
            cases=list(cases),
            case_count=n,
            pass_rate=round(sum(c.passed for c in cases) / n, 4) if n else 0.0,
            valid_rate=round(len(valid) / n, 4) if n else 0.0,
            safety_violations=sum(not c.safety_passed for c in cases),
            critical_failures=sum(bool(c.critical_findings) for c in cases),
            failures_contained=all(c.failure_contained for c in cases),
            mean_overall=round(sum(c.overall for c in cases) / n, 4) if n else 0.0,
            metric_means={
                m: round(sum(c.metrics[m].score for c in valid) / len(valid), 4) if valid else None
                for m in METRICS
            },
            latency_mean_ms=round(sum(latencies) / n, 1) if n else 0.0,
            latency_p95_ms=p95,
            failure_counts=dict(
                sorted(Counter(c.failure.value for c in cases if c.failure).items())
            ),
            failure_class_counts=dict(
                sorted(Counter(c.failure_class.value for c in cases if c.failure_class).items())
            ),
            metadata=metadata,
        )

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        lines = [
            f"# Explanation evaluation: {self.provider}",
            "",
            f"- Model: {self.model or 'n/a'}",
            f"- Benchmark version: {self.benchmark_version} ({self.case_count} cases)",
            f"- Pass rate: {self.pass_rate:.0%}; valid explanations: {self.valid_rate:.0%}",
            f"- Safety violations: {self.safety_violations}; critical failures: "
            f"{self.critical_failures}; failures contained: "
            f"{'yes' if self.failures_contained else 'NO'}",
            f"- Mean overall score: {self.mean_overall:.3f}",
            f"- Latency: mean {self.latency_mean_ms:.0f} ms, p95 {self.latency_p95_ms} ms",
        ]
        if self.metadata is not None:
            m = self.metadata
            lines.append(
                f"- Configuration: {m.config_id}; prompt {m.prompt_version}; scoring "
                f"{m.scoring_version}; evaluator {m.evaluator_version}; evaluated {m.evaluated_at}"
            )
            lines.append(
                f"- Inference: host mode {m.host_mode or UNKNOWN} "
                f"({m.host_mode_source or UNKNOWN}); environment {m.environment}; "
                f"model version {m.model_version or UNKNOWN}"
            )
            for title, hw in (
                ("Evaluator hardware", m.evaluator_hardware),
                ("Inference host hardware", m.inference_host_hardware),
            ):
                lines.append(f"- {title}: {describe_hardware(hw)}")
        if self.failure_counts:
            counts = ", ".join(f"{k} {v}" for k, v in self.failure_counts.items())
            lines.append(f"- Failures: {counts}")
        lines += ["", "| Metric | Mean |", "|---|---|"]
        lines += [f"| {m} | {_measured(self.metric_means[m])} |" for m in METRICS]
        lines += [
            "",
            "| Case | Category | Status | Overall | Safe | Pass | Findings |",
            "|---|---|---|---|---|---|---|",
        ]
        for c in self.cases:
            findings = [f for m in c.metrics.values() for f in m.findings] + list(c.safety_findings)
            if c.failure:
                findings.insert(0, c.failure.value)
            lines.append(
                f"| {c.case_id} | {c.category} | {c.status.value} | {c.overall:.3f} | "
                f"{'yes' if c.safety_passed else 'NO'} | {'yes' if c.passed else 'no'} | "
                f"{'; '.join(findings) or '-'} |"
            )
        return "\n".join(lines) + "\n"


def _measured(value: float | None) -> str:
    return "UNMEASURED" if value is None else f"{value:.3f}"


def _gb(value: int | str) -> str:
    return f"{value / 1024**3:.1f} GB" if isinstance(value, int) else str(value)


def describe_hardware(hw: HardwareInfo | None) -> str:
    """One line; every unmeasured field reads UNKNOWN."""
    if hw is None:
        return UNKNOWN
    return (
        f"{hw.source}; CPU {hw.cpu_model} ({hw.cpu_physical_cores} cores / "
        f"{hw.cpu_logical_cores} threads); RAM {_gb(hw.ram_total_bytes)}; GPU {hw.gpu} "
        f"({_gb(hw.gpu_memory_bytes)}); OS {hw.os}; arch {hw.architecture}"
    )


def compare_markdown(reports: Sequence[EvaluationReport]) -> str:
    """Side-by-side comparison of providers evaluated on the same benchmark."""
    versions = {r.benchmark_version for r in reports}
    if len(versions) > 1:
        raise ValueError("reports use different benchmark versions")
    header = ["Metric", *(f"{r.provider} ({r.model or 'n/a'})" for r in reports)]
    rows = [
        ["pass_rate", *(f"{r.pass_rate:.0%}" for r in reports)],
        ["valid_rate", *(f"{r.valid_rate:.0%}" for r in reports)],
        ["safety_violations", *(str(r.safety_violations) for r in reports)],
        ["mean_overall", *(f"{r.mean_overall:.3f}" for r in reports)],
        *[[m, *(_measured(r.metric_means[m]) for r in reports)] for m in METRICS],
        ["latency_p95_ms", *(str(r.latency_p95_ms) for r in reports)],
    ]
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "# Explanation evaluation: comparison\n\n" + "\n".join(out) + "\n"
