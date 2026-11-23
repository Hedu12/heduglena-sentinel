"""
Command line: evaluate one or more provider/model configurations on the benchmark.

    python -m evaluation --provider null --out reports
    python -m evaluation --provider ollama --model llama3.2 --out reports
    python -m evaluation --provider openai --model gpt-4o-mini --out reports
    python -m evaluation \\
        --provider ollama --model model-a \\
        --provider ollama --model model-b --temperature 0 \\
        --provider openai --model model-c --price-input 0.15 --price-output 0.60 \\
        --out reports
    python -m evaluation --matrix models.json --out reports

Options after a --provider apply to that provider. "null" runs offline (CI);
real providers use OLLAMA_BASE_URL / OPENAI_BASE_URL and OPENAI_API_KEY from the
environment or .env; a key is never accepted on the command line or in a matrix.
An unavailable provider is reported as PROVIDER_UNAVAILABLE and the run goes on.

Writes comparison.json / comparison.md and <label>-<config>.json / .md per model.
--debug-responses DIR additionally writes raw answers (each capped at 4,000
characters) to a separate directory; normal reports never contain model text.

Exit status: 0 when the evaluation completed; 1 when the offline null baseline
(if evaluated) failed a case, which means the framework itself regressed;
2 for invalid arguments. A real model's result never changes the exit status.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.config import Settings
from evaluation.comparison import ComparisonReport, DiagnosticEvidence, load_diagnostics
from evaluation.dataset import build_benchmark
from evaluation.matrix import ModelSpec, load_matrix
from evaluation.rerender import VerdictChanged, rerender
from evaluation.rerender import write as write_rerendered
from evaluation.suite import Suite, SuiteResult

PROVIDERS = ("null", "ollama", "openai")
OPTIONS: dict[str, tuple[str, type]] = {
    "--model": ("model", str),
    "--label": ("label", str),
    "--base-url": ("base_url", str),
    "--timeout": ("timeout_seconds", float),
    "--max-tokens": ("max_output_tokens", int),
    "--temperature": ("temperature", float),
    "--attempts": ("max_attempts", int),
    "--price-input": ("price_input", float),
    "--price-output": ("price_output", float),
    "--host-mode": ("host_mode", str),  # local | remote | hosted_api (remote for a tunnel)
    "--environment": ("environment", str),  # safe name, e.g. cloud-gpu-l4
}


class _Provider(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        ns: argparse.Namespace,
        value: object,
        opt: str | None = None,
    ) -> None:
        ns.specs = [*(ns.specs or []), {"provider": value}]


class _Option(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        ns: argparse.Namespace,
        value: object,
        opt: str | None = None,
    ) -> None:
        if not ns.specs:
            parser.error(f"{opt} must follow a --provider")
        ns.specs[-1][self.dest] = value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation",
        description="Evaluate Sentinel explanation models on the benchmark.",
    )
    parser.add_argument("--provider", action=_Provider, choices=PROVIDERS, dest="specs")
    for flag, (dest, kind) in OPTIONS.items():
        parser.add_argument(flag, action=_Option, dest=dest, type=kind, help=argparse.SUPPRESS)
    parser.add_argument("--matrix", type=Path, help="JSON list of model specifications")
    parser.add_argument("--out", type=Path, required=True, help="directory for the reports")
    parser.add_argument("--case", action="append", help="only these case ids")
    parser.add_argument("--debug-responses", type=Path, help="separate directory for raw answers")
    parser.add_argument(
        "--rerender", type=Path, help="re-report a previous result directory (no model calls)"
    )
    parser.add_argument(
        "--diagnostic", type=Path, help="JSON list of diagnostic evidence (never scored)"
    )
    return parser


def _diagnostics(
    path: Path | None, parser: argparse.ArgumentParser, config_ids: set[str]
) -> list[DiagnosticEvidence]:
    if path is None:
        return []
    case_ids = {c.case_id for c in build_benchmark()}
    try:
        return load_diagnostics(path, config_ids=config_ids, case_ids=case_ids)
    except ValueError as exc:
        parser.error(str(exc))


def _rerender(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.specs or args.matrix is not None:
        parser.error("--rerender re-reports saved results and takes no --provider or --matrix")
    source: Path = args.rerender
    if not (source / "comparison.json").exists():
        parser.error(f"no comparison.json in {source}")
    saved = ComparisonReport.model_validate_json(
        (source / "comparison.json").read_text(encoding="utf-8")
    )
    diagnostics = _diagnostics(args.diagnostic, parser, {m.config_id for m in saved.models})
    try:
        result = rerender(source, diagnostics)
    except VerdictChanged as exc:
        parser.error(f"refusing to re-render: {exc}")
    write_rerendered(result, args.out)
    rec = result.comparison.recommendation
    print(f"re-rendered {len(result.comparison.models)} models; {rec.decision}")
    return 0


def _spec(raw: dict[str, Any]) -> ModelSpec:
    raw = dict(raw)
    price_in, price_out = raw.pop("price_input", None), raw.pop("price_output", None)
    if (price_in is None) != (price_out is None):
        raise ValueError("--price-input and --price-output must be given together")
    if price_in is not None:
        raw["pricing"] = {
            "input_per_million_tokens": price_in,
            "output_per_million_tokens": price_out,
        }
    return ModelSpec.model_validate(raw)


def parse_specs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[ModelSpec]:
    specs: list[ModelSpec] = []
    try:
        if args.matrix is not None:
            specs += load_matrix(args.matrix)
        specs += [_spec(raw) for raw in args.specs or []]
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        parser.error(f"invalid model options: {fields}")
    except ValueError as exc:
        parser.error(str(exc))
    if not specs:
        parser.error("give at least one --provider or a --matrix")
    return specs


def write_outputs(result: SuiteResult, out: Path, debug_dir: Path | None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "comparison.json").write_text(result.comparison.to_json(), encoding="utf-8")
    (out / "comparison.md").write_text(result.comparison.to_markdown(), encoding="utf-8")
    for run in result.runs:
        stem = f"{run.spec.label}-{run.spec.config_id}"
        if run.report is not None:
            (out / f"{stem}.json").write_text(run.report.to_json(), encoding="utf-8")
            (out / f"{stem}.md").write_text(run.report.to_markdown(), encoding="utf-8")
        if debug_dir is not None and run.raw_answers:
            debug_dir.mkdir(parents=True, exist_ok=True)
            lines = [
                json.dumps({"case_id": a.case_id, "status": a.status, "raw": a.text})
                for a in run.raw_answers
            ]
            (debug_dir / f"{stem}.responses.jsonl").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )


def main(argv: Sequence[str] | None = None, *, suite: Suite | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.rerender is not None:
        return _rerender(args, parser)
    specs = parse_specs(args, parser)
    cases = build_benchmark()
    if args.case:
        unknown = set(args.case) - {c.case_id for c in cases}
        if unknown:
            parser.error(f"unknown case ids: {sorted(unknown)}")
        cases = [c for c in cases if c.case_id in args.case]
    runner = suite or Suite(Settings(), keep_raw=args.debug_responses is not None)
    try:
        resolved = runner.resolve_all(specs)
    except ValueError as exc:
        parser.error(str(exc))
    for spec in resolved:
        if spec.host_mode == "remote" and spec.environment == "UNKNOWN":
            print(
                f"note: {spec.label} runs on a remote host without --environment; remote hosts "
                "with the same endpoint and settings would share a configuration id",
                file=sys.stderr,
            )
    result = asyncio.run(runner.run(specs, cases))
    if args.diagnostic is not None:
        ids = {m.config_id for m in result.comparison.models}
        evidence = _diagnostics(args.diagnostic, parser, ids)
        result.comparison = result.comparison.model_copy(update={"diagnostics": evidence})
    write_outputs(result, args.out, args.debug_responses)
    for model in result.comparison.models:
        print(
            f"{model.rank}. {model.label} [{model.config_id}] {model.status.value}: "
            f"{model.classification.value}, overall {model.overall:.3f}, "
            f"safety {model.safety if model.safety is not None else 'unavailable'}, "
            f"critical {model.critical_failures}"
        )
    rec = result.comparison.recommendation
    print(f"{rec.decision}: {rec.label or '-'} ({' '.join(rec.reasons)})")
    baseline = [r for r in result.runs if r.spec.provider == "null" and r.report is not None]
    return 1 if any(r.report and r.report.pass_rate < 1.0 for r in baseline) else 0


if __name__ == "__main__":
    sys.exit(main())
