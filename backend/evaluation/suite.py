"""
The evaluation suite: every model in the matrix, the same benchmark, one comparison.

Fair comparison: every model receives exactly the same cases, sanitised context,
production prompt and output schema, and is judged by the same validator,
safety policy, scoring rules and threshold profile. Only the provider adapter
differs. A model that cannot be evaluated (unavailable provider, unexpected
error) is reported as such and the suite continues with the next one.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from core.config import Settings
from evaluation.case import ExplanationEvalCase
from evaluation.comparison import ComparisonReport
from evaluation.dataset import BENCHMARK_VERSION, build_benchmark
from evaluation.hardware import (
    HardwareInfo,
    HardwareProbe,
    inference_host_hardware,
    probe_evaluator,
)
from evaluation.matrix import (
    EVALUATOR_VERSION,
    PRODUCTION_V1,
    ModelSpec,
    ResolvedSpec,
    ThresholdProfile,
    prompt_version,
)
from evaluation.providers import OllamaCheck, check_ollama, limits_for, prepare, resolve
from evaluation.report import EvaluationReport, RunMetadata
from evaluation.resources import ResourceSampler, ResourceUsage, ollama_loaded
from evaluation.runner import SCORING_VERSION, EvalConfig, EvaluationRunner, RawAnswer
from evaluation.selection import (
    ModelSummary,
    RunStatus,
    rank,
    recommend,
    summarize,
    unavailable_summary,
)
from evaluation.stats import estimate_cost

LoadedCheck = Callable[[str, str], Awaitable[tuple[bool | None, int | None]]]


def utc_now() -> datetime:
    return datetime.now(UTC)


async def _loaded(base_url: str, model: str) -> tuple[bool | None, int | None]:
    return await ollama_loaded(base_url, model)


@dataclass
class ModelRun:
    spec: ResolvedSpec
    summary: ModelSummary
    report: EvaluationReport | None = None
    raw_answers: list[RawAnswer] = field(default_factory=list)


@dataclass
class SuiteResult:
    comparison: ComparisonReport
    runs: list[ModelRun]


@dataclass
class Suite:
    settings: Settings
    profile: ThresholdProfile = PRODUCTION_V1
    clock: Callable[[], datetime] = utc_now
    monotonic: Callable[[], float] = time.perf_counter
    ollama_check: OllamaCheck = check_ollama
    loaded_check: LoadedCheck = _loaded
    keep_raw: bool = False
    # HTTP transport for the provider adapters (tests inject a mock; None in real runs).
    transport: httpx.AsyncBaseTransport | None = None
    # Evaluator hardware metadata (read-only, non-identifying).
    hardware_probe: HardwareProbe = probe_evaluator

    def resolve_all(self, specs: Sequence[ModelSpec]) -> list[ResolvedSpec]:
        """Resolve every spec. Raises ValueError for an inconsistent host declaration."""
        return [resolve(spec, self.settings) for spec in specs]

    async def run(
        self, specs: Sequence[ModelSpec], cases: Sequence[ExplanationEvalCase] | None = None
    ) -> SuiteResult:
        benchmark = list(cases) if cases is not None else build_benchmark()
        resolved: dict[str, ResolvedSpec] = {}
        for one in self.resolve_all(specs):
            resolved.setdefault(one.config_id, one)  # identical configurations run once
        started = self.clock().isoformat()
        evaluator_hw = self._probe()
        runs = [
            await self._evaluate(spec, benchmark, started, evaluator_hw)
            for spec in resolved.values()
        ]
        ranked = rank([r.summary for r in runs])
        by_id = {s.config_id: s for s in ranked}
        for r in runs:
            r.summary = by_id[r.spec.config_id]
        comparison = ComparisonReport(
            generated_at=started,
            evaluator_version=EVALUATOR_VERSION,
            scoring_version=SCORING_VERSION,
            prompt_version=prompt_version(),
            benchmark_version=BENCHMARK_VERSION,
            case_count=len(benchmark),
            threshold_profile=self.profile,
            models=ranked,
            recommendation=recommend(ranked),
            evaluator_hardware=evaluator_hw,
        )
        runs.sort(key=lambda r: r.summary.rank)
        return SuiteResult(comparison, runs)

    async def _evaluate(
        self,
        spec: ResolvedSpec,
        cases: list[ExplanationEvalCase],
        started: str,
        evaluator_hw: HardwareInfo,
    ) -> ModelRun:
        baseline = spec.provider == "null"
        try:
            prepared = await prepare(
                spec, self.settings, ollama_check=self.ollama_check, transport=self.transport
            )
            if prepared.provider is None:
                reason = prepared.unavailable or "UNKNOWN"
                return ModelRun(spec, unavailable_summary(spec, reason, is_baseline=baseline))
            runner = EvaluationRunner(
                prepared.provider,
                limits_for(spec, self.settings),
                EvalConfig(latency_budget_ms=self.profile.latency_budget_ms),
                monotonic=self.monotonic,
                keep_raw=self.keep_raw,
            )
            # The evaluator is sampled for every real provider; the null baseline is not.
            sampler = ResourceSampler() if not baseline else None
            if sampler is not None:
                sampler.start()
            report = await runner.run(
                cases,
                benchmark_version=BENCHMARK_VERSION,
                metadata=self._metadata(
                    spec, prepared.model_version, started, len(cases), evaluator_hw
                ),
                sampler=sampler,
            )
            evaluator, host = await self._resources(spec, sampler, prepared.model_size_bytes)
            summary = summarize(
                report,
                spec,
                profile=self.profile,
                resources=host,
                evaluator_resources=evaluator,
                inference_host_hardware=inference_host_hardware(spec.host_mode, evaluator_hw),
                cost=estimate_cost(report.cases, spec.pricing),
                model_version=prepared.model_version or report.model,
                is_baseline=baseline,
            )
            return ModelRun(spec, summary, report, runner.raw_answers)
        except Exception as exc:
            # One model's failure never stops the suite; only the exception type is kept.
            summary = unavailable_summary(
                spec,
                f"EVALUATION_ERROR:{type(exc).__name__}",
                status=RunStatus.EVALUATION_FAILED,
                is_baseline=baseline,
            )
            return ModelRun(spec, summary)

    async def _resources(
        self, spec: ResolvedSpec, sampler: ResourceSampler | None, size: int | None
    ) -> tuple[ResourceUsage, ResourceUsage]:
        """
        (evaluator, inference host). The sampler always measures this machine. Its
        figures describe the inference host only when inference is local; for a
        remote host or hosted API the host's CPU, RAM and pressure stay UNKNOWN,
        and only what the inference server itself reports is recorded.
        """
        evaluator = (
            sampler.usage(
                high_cpu=self.profile.high_cpu_percent,
                high_memory=self.profile.high_memory_percent,
            )
            if sampler is not None
            else ResourceUsage()
        )
        if spec.host_mode == "in_process":
            return evaluator, ResourceUsage()
        reported: dict[str, object] = {}
        if spec.provider == "ollama":
            # /api/ps and /api/tags are answered by the inference server itself.
            loaded, vram = await self.loaded_check(spec.base_url or "", spec.model)
            reported = {"model_loaded": loaded, "model_gpu_memory_bytes": vram,
                        "model_size_bytes": size}  # fmt: skip
        if spec.host_mode == "local":
            return evaluator, evaluator.model_copy(update=reported)
        return evaluator, ResourceUsage.model_validate(reported)

    def _metadata(
        self,
        spec: ResolvedSpec,
        version: str | None,
        started: str,
        count: int,
        evaluator_hw: HardwareInfo,
    ) -> RunMetadata:
        return RunMetadata(
            evaluator_version=EVALUATOR_VERSION,
            scoring_version=SCORING_VERSION,
            prompt_version=prompt_version(),
            benchmark_version=BENCHMARK_VERSION,
            threshold_profile=self.profile.name,
            config_id=spec.config_id,
            label=spec.label,
            provider=spec.provider,
            model=spec.model,
            model_version=version,
            base_url=spec.public_base_url,
            timeout_seconds=spec.timeout_seconds,
            max_output_tokens=spec.max_output_tokens,
            temperature=spec.temperature,
            max_attempts=spec.max_attempts,
            evaluated_at=started,
            case_count=count,
            host_mode=spec.host_mode,
            host_mode_source=spec.host_mode_source,
            environment=spec.environment,
            evaluator_hardware=evaluator_hw,
            inference_host_hardware=inference_host_hardware(spec.host_mode, evaluator_hw),
        )

    def _probe(self) -> HardwareInfo:
        try:
            return self.hardware_probe()
        except Exception:
            return HardwareInfo()
