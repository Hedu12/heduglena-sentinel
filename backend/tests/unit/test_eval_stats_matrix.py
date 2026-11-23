"""Latency statistics, cost, the model matrix and configuration identity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from core.config import Settings
from evaluation.matrix import ModelSpec, Pricing, load_matrix, prompt_version, redact_url
from evaluation.providers import limits_for, resolve
from evaluation.report import CaseResult
from evaluation.resources import ResourceSampler, ResourceUsage, estimate_pressure
from evaluation.stats import CostSource, estimate_cost, latency_stats, p95
from models.enums import ExplanationStatus


def case(latency: int, *, responded: bool = True, tokens: tuple[int, int] | None = None) -> Any:
    return CaseResult(
        case_id="c", category="x", status=ExplanationStatus.VALID if responded else
        ExplanationStatus.FAILED, model="m", latency_ms=latency, attempts=1, failure=None,
        responded=responded, failure_contained=True, safety_passed=True, safety_findings=(),
        metrics={}, overall=1.0, passed=True,
        prompt_tokens=tokens[0] if tokens else None, response_tokens=tokens[1] if tokens else None,
    )  # fmt: skip


class TestLatency:
    def test_statistics(self) -> None:
        cases = [case(v) for v in (100, 200, 300, 400, 10_000)]
        stats = latency_stats(cases, min_p95_samples=5)
        assert (stats.min_ms, stats.mean_ms, stats.median_ms, stats.p95_ms, stats.max_ms) == (
            100,
            2200.0,
            300.0,
            10_000,
            10_000,
        )

    def test_nearest_rank_p95(self) -> None:
        assert p95(list(range(1, 101))) == 95
        assert p95(list(range(1, 21))) == 19
        assert p95([7]) == 7

    def test_timeouts_are_not_latency_samples(self) -> None:
        stats = latency_stats([case(500), case(20_000, responded=False)], min_p95_samples=1)
        assert stats.samples == 1 and stats.max_ms == 500

    def test_too_few_samples_give_no_p95(self) -> None:
        stats = latency_stats([case(100)] * 9, min_p95_samples=10)
        assert stats.p95_ms is None and stats.max_ms == 100

    def test_no_samples(self) -> None:
        stats = latency_stats([case(1, responded=False)], min_p95_samples=1)
        assert stats.samples == 0 and stats.mean_ms is None


class TestCost:
    PRICES = Pricing(input_per_million_tokens=2.0, output_per_million_tokens=8.0)

    def test_no_pricing_means_cost_unavailable(self) -> None:
        cost = estimate_cost([case(1, tokens=(100, 50))], None)
        assert (cost.source, cost.reason) == (CostSource.COST_UNAVAILABLE, "PRICING_NOT_CONFIGURED")
        assert cost.source.value == "cost_unavailable"

    def test_no_token_counts_means_cost_unavailable(self) -> None:
        cost = estimate_cost([case(1)], self.PRICES)
        assert cost.reason == "TOKEN_COUNTS_UNAVAILABLE" and cost.per_evaluation is None

    def test_estimated_from_configured_prices(self) -> None:
        cost = estimate_cost(
            [case(1, tokens=(1000, 500)), case(1, tokens=(3000, 500)), case(1)], self.PRICES
        )
        # (1000*2 + 500*8)/1e6 = 0.006; (3000*2 + 500*8)/1e6 = 0.010; mean 0.008
        assert cost.source is CostSource.ESTIMATED_CONFIGURED_COST
        assert (cost.per_evaluation, cost.per_100, cost.per_1000) == (0.008, 0.8, 8.0)
        assert cost.priced_cases == 2 and cost.currency == "USD"

    def test_provider_reported_cost_is_never_claimed(self) -> None:
        cost = estimate_cost([case(1, tokens=(1, 1))], self.PRICES)
        assert cost.source is not CostSource.ACTUAL_PROVIDER_REPORTED_COST


class TestMatrix:
    @pytest.mark.parametrize("field", ["api_key", "openai_api_key", "token", "password"])
    def test_a_spec_cannot_carry_a_credential(self, field: str) -> None:
        with pytest.raises(ValidationError):
            ModelSpec.model_validate({"provider": "openai", field: "sk-secret"})

    def test_a_matrix_file_with_a_key_is_refused_without_echoing_it(self, tmp_path: Path) -> None:
        path = tmp_path / "m.json"
        path.write_text(json.dumps([{"provider": "openai", "api_key": "sk-leak-123456789"}]))
        with pytest.raises(ValueError) as raised:
            load_matrix(path)
        assert "sk-leak" not in str(raised.value) and "api_key" in str(raised.value)

    @pytest.mark.parametrize("content", ["{}", "[]", "not json"])
    def test_malformed_matrix_files_are_refused(self, tmp_path: Path, content: str) -> None:
        path = tmp_path / "m.json"
        path.write_text(content)
        with pytest.raises(ValueError):
            load_matrix(path)

    def test_a_valid_matrix_file(self, tmp_path: Path) -> None:
        path = tmp_path / "m.json"
        path.write_text(json.dumps([{"provider": "ollama", "model": "a"}, {"provider": "null"}]))
        assert [s.provider for s in load_matrix(path)] == ["ollama", "null"]

    def test_config_ids_are_stable_and_ignore_the_label(self) -> None:
        settings = Settings()
        a = resolve(ModelSpec(provider="ollama", model="m", label="one"), settings)
        b = resolve(ModelSpec(provider="ollama", model="m", label="two"), settings)
        c = resolve(ModelSpec(provider="ollama", model="m", temperature=0.7), settings)
        assert a.config_id == b.config_id != c.config_id
        assert a.config_id.startswith("cfg-") and len(a.config_id) == 16

    def test_urls_are_redacted_for_identity_and_reports(self) -> None:
        assert redact_url("https://user:sk-pass@llm.example:8443/v1?key=sk-q#frag") == (
            "https://llm.example:8443/v1"
        )
        with_query = resolve(
            ModelSpec(provider="openai", base_url="https://llm.example:8443/v1?key=sk-q"),
            Settings(),
        )
        plain = resolve(
            ModelSpec(provider="openai", base_url="https://llm.example:8443/v1"), Settings()
        )
        assert with_query.config_id == plain.config_id
        assert "sk-" not in (with_query.public_base_url or "")

    def test_a_url_carrying_credentials_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            ModelSpec(provider="openai", base_url="https://user:sk-pass@llm.example/v1")

    def test_resolution_fills_every_default_from_settings(self) -> None:
        settings = Settings()
        r = resolve(ModelSpec(provider="ollama"), settings)
        assert (r.model, r.base_url) == (settings.ollama_model, settings.ollama_base_url)
        assert (r.timeout_seconds, r.max_output_tokens, r.max_attempts) == (10.0, 500, 2)
        assert r.label == f"ollama-{settings.ollama_model}"
        limits = limits_for(resolve(ModelSpec(provider="openai", timeout_seconds=3,
                                              max_output_tokens=200, max_attempts=1), settings),
                            settings)  # fmt: skip
        assert (limits.timeout_seconds, limits.max_output_tokens, limits.max_attempts) == (
            3,
            200,
            1,
        )
        assert limits.max_field_chars == settings.ai_max_response_chars  # production validator cap

    def test_the_prompt_version_identifies_the_production_prompt(self) -> None:
        assert prompt_version() == prompt_version() and prompt_version().startswith("p-")

    def test_the_settings_key_never_appears_in_a_resolved_spec(self) -> None:
        settings = Settings(ai_provider="openai", openai_api_key=SecretStr("sk-never-12345678"))
        r = resolve(ModelSpec(provider="openai"), settings)
        assert "sk-never" not in r.model_dump_json()


class TestResources:
    def test_pressure_estimate(self) -> None:
        kw = {"high_cpu": 90.0, "high_memory": 90.0}
        assert estimate_pressure(None, 50, **kw) is None
        assert estimate_pressure(10, 40, **kw) == "LOW"
        assert estimate_pressure(70, 40, **kw) == "MODERATE"
        assert estimate_pressure(10, 95, **kw) == "HIGH"

    def test_unmeasured_metrics_are_reported_unavailable(self) -> None:
        usage = ResourceUsage(cpu_mean_percent=5.0)
        assert "gpu_utilization_percent" in usage.unavailable()
        assert "cpu_mean_percent" not in usage.unavailable()

    def test_a_sampler_failure_yields_unavailable_not_fabricated_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evaluation.resources as res

        def broken(*_a: object, **_k: object) -> float:
            raise PermissionError("denied")

        monkeypatch.setattr(res.psutil, "cpu_percent", broken)
        sampler = ResourceSampler()
        sampler.start()
        sampler.sample()
        usage = sampler.usage(high_cpu=90, high_memory=90)
        assert usage == ResourceUsage() and usage.pressure is None

    def test_the_sampler_reads_system_wide_figures(self) -> None:
        sampler = ResourceSampler()
        sampler.start()
        for _ in range(3):
            sampler.sample()
        usage = sampler.usage(high_cpu=90, high_memory=90)
        assert usage.samples == 3 and usage.memory_max_percent is not None
        assert usage.gpu_utilization_percent is None and usage.inference_duration_ms is None
