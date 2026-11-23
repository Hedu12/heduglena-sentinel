"""
The model comparison report (JSON and Markdown).

Contains the model matrix, scores, safety and failures, latency, resources,
cost, classification, ranking policy and the deterministic recommendation, plus
the metadata needed to reproduce the run. No model text, no credentials.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evaluation.hardware import HardwareInfo
from evaluation.matrix import UNKNOWN, ThresholdProfile
from evaluation.report import describe_hardware
from evaluation.resources import ResourceUsage
from evaluation.selection import ModelSummary, Recommendation, RunStatus

RANKING_POLICY = (
    "classification tier",
    "completed before unavailable",
    "safety",
    "critical failures",
    "factual accuracy",
    "evidence grounding",
    "hallucination rate",
    "action consistency",
    "completeness",
    "presentation quality",
    "latency",
    "configuration id",
)
NONDETERMINISM_NOTE = (
    "Real models may answer differently between runs even at temperature 0 (provider "
    "batching, model updates, sampling). The null baseline and scripted providers are "
    "fully deterministic; real-model results are reproducible in structure, not "
    "necessarily in every score."
)


class DiagnosticEvidence(BaseModel):
    """
    A separate, evaluator-supplied measurement (for example one request with a long
    timeout). Reported for context only: it is never scored and never changes a
    classification, the ranking or the recommendation. Fixed codes, no model text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    config_id: str = Field(pattern=r"^cfg-[0-9a-f]{12}$")
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    timeout_seconds: float = Field(gt=0.0, le=3600.0)
    response_ms: int | None = Field(default=None, ge=0, le=3_600_000)
    prompt_tokens: int | None = Field(default=None, ge=0, le=10_000_000)
    completion_tokens: int | None = Field(default=None, ge=0, le=10_000_000)
    tokens_per_second: float | None = Field(default=None, ge=0.0, le=100_000.0)
    # A fixed code such as VALID, TIMEOUT or SCHEMA_VIOLATION:string_type.
    validation: str = Field(pattern=r"^[A-Z][A-Z_]{1,40}(:[a-z_]{1,40})?$")
    scored: Literal[False] = False
    note: str = Field(default="Diagnostic only; not part of benchmark scoring.", max_length=200)


def load_diagnostics(
    path: Path, *, config_ids: set[str], case_ids: set[str]
) -> list[DiagnosticEvidence]:
    """A JSON list of DiagnosticEvidence for models and cases of this evaluation."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read the diagnostics file ({type(exc).__name__})") from None
    if not isinstance(data, list):
        raise ValueError("the diagnostics file must be a JSON list")
    try:
        items = [DiagnosticEvidence.model_validate(d) for d in data]
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise ValueError(f"invalid diagnostics entries: {fields}") from None
    for item in items:
        if item.config_id not in config_ids:
            raise ValueError(f"diagnostic for unknown configuration {item.config_id}")
        if item.case_id not in case_ids:
            raise ValueError(f"diagnostic for unknown case {item.case_id}")
    return items


class ComparisonReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    generated_at: str
    evaluator_version: str
    scoring_version: str
    prompt_version: str
    benchmark_version: str
    case_count: int
    threshold_profile: ThresholdProfile
    ranking_policy: tuple[str, ...] = RANKING_POLICY
    nondeterminism: str = NONDETERMINISM_NOTE
    models: list[ModelSummary]
    recommendation: Recommendation
    # Context only; never scored (DiagnosticEvidence.scored is always false).
    diagnostics: list[DiagnosticEvidence] = []
    # The machine that ran the evaluation (Phase 8.5.1); None in older reports.
    evaluator_hardware: HardwareInfo | None = None

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        return render_markdown(self)


def _pct(value: float | None) -> str:
    return "unavailable" if value is None else f"{value:.0%}"


def _i(value: int | float | None, unit: str = "") -> str:
    return "unavailable" if value is None else f"{value:g}{unit}"


def _ran(m: ModelSummary) -> bool:
    return m.status is RunStatus.COMPLETED


def _q(m: ModelSummary, value: float | None, fmt: str = ".3f") -> str:
    """A quality value: unavailable if the model did not run, UNMEASURED if no answer."""
    if not _ran(m):
        return "unavailable"
    return "UNMEASURED" if value is None else format(value, fmt)


def _overall(m: ModelSummary) -> str:
    return _q(m, m.overall if m.valid_count else None)


def _critical(m: ModelSummary) -> str:
    if not _ran(m):
        return "unavailable"
    return "UNMEASURED" if m.safety is None else str(m.critical_failures)


def _resource_row(n: str, m: ModelSummary, r: ResourceUsage, *, host: bool) -> list[str]:
    """Unmeasured remote-host values read UNKNOWN; other gaps read unavailable."""
    gap = UNKNOWN if host and m.host_mode in ("remote", "hosted_api") else "unavailable"

    def v(value: int | float | bool | str | None, unit: str = "") -> str:
        if value is None:
            return gap
        return str(value) if isinstance(value, bool | str) else f"{value:g}{unit}"

    return [
        n, m.host_mode or UNKNOWN, v(r.cpu_mean_percent, "%"), v(r.cpu_max_percent, "%"),
        v(r.memory_max_percent, "%"), v(r.gpu_utilization_percent, "%"),
        v(r.inference_duration_ms, " ms"), v(r.model_loaded), v(r.model_gpu_memory_bytes, " B"),
        v(r.pressure),
    ]  # fmt: skip


def demonstrated_failures(m: ModelSummary) -> tuple[str, ...]:
    return tuple(code for code in m.reasons if code.endswith("_FAIL"))


def _done(m: ModelSummary, value: float) -> float | None:
    """A measured value, or None (shown as unavailable) when the model did not run."""
    return value if _ran(m) else None


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    return out + ["| " + " | ".join(r) + " |" for r in rows]


def render_markdown(r: ComparisonReport) -> str:
    models = r.models
    name = [f"{m.rank}. {m.label}" + (" (baseline)" if m.is_baseline else "") for m in models]
    lines = [
        "# Sentinel explanation model evaluation",
        "",
        f"- Generated: {r.generated_at}",
        f"- Evaluator {r.evaluator_version}; scoring {r.scoring_version}; prompt "
        f"{r.prompt_version}; benchmark {r.benchmark_version} ({r.case_count} cases); "
        f"thresholds {r.threshold_profile.name}",
        f"- Note: {r.nondeterminism}",
        "",
        "## Model matrix",
        "",
    ]
    lines += _table(
        ["Model", "Provider", "Model id", "Version", "Host mode", "Environment", "Config",
         "Status"],
        [
            [n, m.provider, m.model, m.model_version or "unavailable",
             f"{m.host_mode or UNKNOWN} ({m.host_mode_source or UNKNOWN})", m.environment,
             m.config_id,
             m.status.value + (f" ({m.unavailable_reason})" if m.unavailable_reason else "")]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += ["", "## Scores", ""]
    lines += _table(
        ["Model", "Factual", "Grounding", "Completeness", "Hallucination rate", "Actions",
         "Presentation", "Overall", "Pass rate"],
        [
            [n, _q(m, m.factual_accuracy), _q(m, m.evidence_grounding), _q(m, m.completeness),
             _q(m, m.hallucination_rate, ".0%"), _q(m, m.action_consistency),
             _q(m, m.presentation_quality), _overall(m), _pct(_done(m, m.pass_rate))]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += ["", "## Safety and failures", ""]
    lines += _table(
        ["Model", "Safety", "Critical", "Timeouts", "Provider failures", "Model failures",
         "Validation rejections", "Evaluation failures"],
        [
            [n, _q(m, m.safety, ".2f"), _critical(m),
             _pct(_done(m, m.timeout_rate)), _pct(_done(m, m.provider_failure_rate)),
             _pct(_done(m, m.model_failure_rate)), _pct(_done(m, m.validation_rejection_rate)),
             _pct(_done(m, m.evaluation_failure_rate))]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += ["", f"## Latency (budget {r.threshold_profile.latency_budget_ms} ms)", ""]
    lines += _table(
        ["Model", "Samples", "Min", "Mean", "Median", "P95", "Max"],
        [
            [n, str(m.latency.samples), _i(m.latency.min_ms, " ms"), _i(m.latency.mean_ms, " ms"),
             _i(m.latency.median_ms, " ms"),
             _i(m.latency.p95_ms, " ms") if m.latency.samples else "unavailable",
             _i(m.latency.max_ms, " ms")]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += [
        "",
        "## Inference host resources",
        "",
        "The machine that ran the model. Local: the evaluator, sampled system-wide between "
        "cases. Remote or hosted: UNKNOWN, except what the inference server itself reports "
        "(loaded model, model and GPU memory).",
        "",
    ]
    lines += _table(
        ["Model", "Host mode", "CPU mean", "CPU max", "Memory max", "GPU", "Inference",
         "Loaded", "Model GPU memory", "Pressure"],
        [_resource_row(n, m, m.inference_host_resources, host=True)
         for n, m in zip(name, models, strict=True)],
    )  # fmt: skip
    lines += ["", "## Evaluator resources (this machine, never the remote host)", ""]
    lines += _table(
        ["Model", "Host mode", "CPU mean", "CPU max", "Memory max", "GPU", "Inference",
         "Loaded", "Model GPU memory", "Pressure"],
        [_resource_row(n, m, m.evaluator_resources, host=False)
         for n, m in zip(name, models, strict=True)],
    )  # fmt: skip
    lines += ["", "## Hardware", "", f"- Evaluator: {describe_hardware(r.evaluator_hardware)}"]
    lines += [
        f"- {n} inference host: {describe_hardware(m.inference_host_hardware)}"
        for n, m in zip(name, models, strict=True)
    ]
    lines += ["", "## Cost", ""]
    lines += _table(
        ["Model", "Source", "Per evaluation", "Per 100", "Per 1,000"],
        [
            [n, m.cost.source.value + (f" ({m.cost.reason})" if m.cost.reason else ""),
             _i(m.cost.per_evaluation), _i(m.cost.per_100), _i(m.cost.per_1000)]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += [
        "",
        "## Measurement",
        "",
        "UNMEASURED: could not be evaluated because no valid answer was received. "
        "FAIL: demonstrated to fail. An unmeasured requirement never passes.",
        "",
    ]
    lines += _table(
        ["Model", "Quality measured", "UNMEASURED", "Demonstrated FAIL"],
        [
            [n, ("yes" if m.quality_measured else "no") if _ran(m) else "unavailable",
             " ".join(m.unmeasured_metrics) or "-", " ".join(demonstrated_failures(m)) or "-"]
            for n, m in zip(name, models, strict=True)
        ],
    )  # fmt: skip
    lines += ["", "## Classification", ""]
    lines += _table(
        ["Model", "Classification", "Reasons"],
        [
            [n, m.classification.value, " ".join(m.reasons)]
            for n, m in zip(name, models, strict=True)
        ],
    )
    if r.diagnostics:
        labels = {m.config_id: m.label for m in models}
        lines += [
            "",
            "## Diagnostic evidence (not part of benchmark scoring)",
            "",
            "Separate, evaluator-supplied measurements. They never change a score, a "
            "classification, the ranking or the recommendation.",
            "",
        ]
        lines += _table(
            ["Model", "Case", "Timeout", "Response time", "Tokens (prompt/completion)",
             "Tokens/s", "Validation", "Note"],
            [
                [labels.get(d.config_id, d.config_id), d.case_id, f"{d.timeout_seconds:g} s",
                 _i(None if d.response_ms is None else round(d.response_ms / 1000, 1), " s"),
                 f"{_i(d.prompt_tokens)}/{_i(d.completion_tokens)}", _i(d.tokens_per_second),
                 d.validation, d.note]
                for d in r.diagnostics
            ],
        )  # fmt: skip
    rec = r.recommendation
    lines += [
        "",
        "## Ranking policy",
        "",
        " > ".join(r.ranking_policy),
        "",
        "## Recommendation",
        "",
        f"**{rec.decision}**" + (f": {rec.label} ({rec.config_id})" if rec.label else ""),
        "",
        " ".join(rec.reasons),
    ]
    return "\n".join(lines) + "\n"
