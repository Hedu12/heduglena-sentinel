"""
Re-render saved evaluation results with the current reporting rules. No model is called.

Reads comparison.json and the per-model reports from a previous run, re-derives
the reason codes and metric means with the current reporting semantics, and
optionally attaches evaluator-supplied diagnostic evidence. It is reporting
only: if re-deriving would change any classification, the ranking or the
recommendation, it refuses (raises) instead of writing a different verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from evaluation.comparison import ComparisonReport, DiagnosticEvidence
from evaluation.report import EvaluationReport
from evaluation.selection import classify, rank, recommend


@dataclass
class Rerendered:
    comparison: ComparisonReport
    reports: dict[str, EvaluationReport]  # file stem -> rebuilt per-model report


class VerdictChanged(ValueError):
    """Re-rendering would have changed a classification, the ranking or the recommendation."""


def _rebuild(report: EvaluationReport) -> EvaluationReport:
    return EvaluationReport.build(
        provider=report.provider,
        model=report.model,
        benchmark_version=report.benchmark_version,
        cases=report.cases,
        metadata=report.metadata,
    )


def rerender(source: Path, diagnostics: list[DiagnosticEvidence] | None = None) -> Rerendered:
    old = ComparisonReport.model_validate_json(
        (source / "comparison.json").read_text(encoding="utf-8")
    )
    reports: dict[str, EvaluationReport] = {}
    models = []
    for summary in old.models:
        stem = f"{summary.label}-{summary.config_id}"
        path = source / f"{stem}.json"
        timeout_ms = summary.timeout_ms
        if path.exists():
            report = _rebuild(EvaluationReport.model_validate_json(path.read_text("utf-8")))
            reports[stem] = report
            if timeout_ms is None and report.metadata is not None:
                timeout_ms = round(report.metadata.timeout_seconds * 1000)
        updated = summary.model_copy(update={"timeout_ms": timeout_ms})
        tier, reasons = classify(updated, old.threshold_profile)
        if tier is not summary.classification:
            raise VerdictChanged(
                f"{summary.config_id}: {summary.classification.value} -> {tier.value}"
            )
        models.append(updated.model_copy(update={"reasons": reasons}))

    ranked = rank(models)
    if [m.config_id for m in ranked] != [m.config_id for m in old.models]:
        raise VerdictChanged("the ranking would change")
    recommendation = recommend(ranked)
    before, after = old.recommendation, recommendation
    if (before.decision, before.config_id) != (after.decision, after.config_id):
        raise VerdictChanged("the recommendation would change")
    comparison = old.model_copy(
        update={
            "models": ranked,
            "recommendation": recommendation,
            "diagnostics": list(diagnostics or old.diagnostics),
        }
    )
    return Rerendered(comparison, reports)


def write(result: Rerendered, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "comparison.json").write_text(result.comparison.to_json(), encoding="utf-8")
    (out / "comparison.md").write_text(result.comparison.to_markdown(), encoding="utf-8")
    for stem, report in result.reports.items():
        (out / f"{stem}.json").write_text(report.to_json(), encoding="utf-8")
        (out / f"{stem}.md").write_text(report.to_markdown(), encoding="utf-8")
