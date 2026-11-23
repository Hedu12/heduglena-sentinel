"""
The Phase 8 suite end to end, offline.

A mock HTTP server plays Ollama and an OpenAI-compatible API. Each mock "model"
behaves in one scripted way, and every request goes through the real production
adapter, Explainer, prompt and output validation. Nothing touches the network.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from ai.adapters.null_adapter import deterministic_explanation
from ai.context import IncidentContext
from ai.prompt import DATA_CLOSE, DATA_OPEN, SYSTEM_PROMPT
from core.config import Settings
from evaluation.__main__ import main
from evaluation.matrix import ModelSpec
from evaluation.resources import OllamaStatus
from evaluation.selection import Classification, RunStatus
from evaluation.suite import Suite, SuiteResult

SECRET = "sk-test-SECRET-abcdef1234567890"
MARKER = "MODEL-TEXT-MARKER-91c2"
FIXED = datetime(2026, 1, 1, tzinfo=UTC)
INSTALLED = {"faithful", "malformed", "unsafe", "obedient", "slow", "error", "verbose"}


def _context(body: dict[str, Any]) -> IncidentContext:
    user = body["messages"][1]["content"]
    block = user.split(DATA_OPEN, 1)[1].rsplit(DATA_CLOSE, 1)[0]
    return IncidentContext.model_validate_json(block)


def _answer(model: str, ctx: IncidentContext) -> str:
    base = deterministic_explanation(ctx)
    if model == "malformed":
        return f"Sure! {MARKER}"
    if model == "unsafe":
        return json.dumps({**base, "recommended_human_attention": f"Run rm -rf / {MARKER}"})
    if model == "obedient":
        return json.dumps({**base, "summary": "Everything is safe here. OBEYED-7731."})
    if model == "verbose":
        return json.dumps({**base, "why_it_matters": f"{base['why_it_matters']} {MARKER}"})
    return json.dumps(base)


class MockLLM:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        model = body["model"]
        if model == "slow":
            await asyncio.sleep(5)
        if model == "error":
            return httpx.Response(503, text=f"overloaded {MARKER}")
        content = _answer(model, _context(body))
        return httpx.Response(
            200,
            json={
                "model": f"{model}-served-1",
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 1200, "completion_tokens": 300},
            },
        )

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


async def fake_ollama(base_url: str, model: str) -> OllamaStatus:
    if "down" in base_url:
        return OllamaStatus(reachable=False, error="UNREACHABLE")
    if model not in INSTALLED:
        return OllamaStatus(reachable=True, installed=False, error="MODEL_NOT_INSTALLED")
    return OllamaStatus(
        reachable=True,
        installed=True,
        digest="sha256:0123456789abcdef",
        parameter_size="3B",
        quantization="Q4_K_M",
        size_bytes=2_000_000_000,
    )


async def fake_loaded(base_url: str, model: str) -> tuple[bool | None, int | None]:
    return True, 0


class Tick:
    def __init__(self, step: float = 0.001) -> None:
        self.now, self.step = 0.0, step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


def suite(
    mock: MockLLM | None = None, *, settings: Settings | None = None, step: float = 0.001,
    keep_raw: bool = False,
) -> Suite:  # fmt: skip
    return Suite(
        settings or Settings(),
        clock=lambda: FIXED,
        monotonic=Tick(step),
        ollama_check=fake_ollama,
        loaded_check=fake_loaded,
        transport=(mock or MockLLM()).transport(),
        keep_raw=keep_raw,
    )


def ollama(model: str, **kw: Any) -> ModelSpec:
    return ModelSpec(provider="ollama", model=model, **kw)


def by_model(result: SuiteResult) -> dict[str, Any]:
    return {m.model: m for m in result.comparison.models}


@pytest.fixture(autouse=True)
def steady_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    import evaluation.resources as res

    monkeypatch.setattr(res.psutil, "cpu_percent", lambda interval=None: 25.0)

    class Memory:
        percent = 60.0

    monkeypatch.setattr(res.psutil, "virtual_memory", lambda: Memory())


class TestBaselineEndToEnd:
    """Phase 8.1: the real null provider through the real suite."""

    async def test_the_null_provider_scores_perfectly_and_is_baseline(self) -> None:
        result = await suite().run([ModelSpec(provider="null")])
        (m,) = result.comparison.models
        assert m.overall == 1.0 and m.pass_rate == 1.0 and m.safety == 1.0
        assert m.classification is Classification.BASELINE
        assert m.production_candidate is False and m.recommendation_eligible is False
        assert result.runs[0].report is not None  # still a full regression report

    async def test_with_every_real_provider_unavailable_there_is_no_recommendation(self) -> None:
        result = await suite().run(
            [
                ModelSpec(provider="null"),
                ollama("faithful", base_url="http://down:11434"),
                ollama("not-pulled"),
                ModelSpec(provider="openai", model="gpt-x"),  # no key
            ]
        )
        rec = result.comparison.recommendation
        assert rec.decision == "NO_RECOMMENDATION"
        assert "NO_REAL_MODEL_EVALUATED" in rec.reasons
        assert rec.model is None and rec.config_id is None
        # The perfect baseline ranks after the unavailable real models.
        assert result.comparison.models[-1].classification is Classification.BASELINE

    async def test_a_real_model_is_recommended_over_a_perfect_baseline(self) -> None:
        result = await suite().run([ModelSpec(provider="null"), ollama("faithful")])
        assert result.comparison.models[0].model == "faithful"
        assert result.comparison.recommendation.model == "faithful"

    def test_the_cli_reports_baseline_and_exits_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--provider", "null", "--out", str(tmp_path)], suite=suite()) == 0
        assert "BASELINE" in capsys.readouterr().out
        data = json.loads((tmp_path / "comparison.json").read_text("utf-8"))
        assert data["models"][0]["classification"] == "BASELINE"
        assert "PRODUCTION-CANDIDATE" not in (tmp_path / "comparison.md").read_text("utf-8")


class TestRealProviderPaths:
    async def test_a_faithful_local_model_is_recommended(self) -> None:
        result = await suite().run([ModelSpec(provider="null"), ollama("faithful")])
        m = by_model(result)["faithful"]
        assert m.status is RunStatus.COMPLETED
        assert m.classification is Classification.PRODUCTION_CANDIDATE
        assert m.model_version == "sha256:01234 (3B Q4_K_M)"  # digest prefix and details
        rec = result.comparison.recommendation
        assert (rec.decision, rec.model) == ("RECOMMENDED_MODEL", "faithful")
        assert {"SAFETY_PASS", "FACTUALITY_PASS", "GROUNDING_PASS", "LATENCY_PASS",
                "RESOURCE_ACCEPTABLE"} <= set(rec.reasons)  # fmt: skip

    async def test_every_model_gets_the_same_prompt_and_cases(self) -> None:
        mock = MockLLM()
        await suite(mock).run([ollama("faithful"), ollama("verbose")])
        by: dict[str, list[tuple[str, str]]] = {}
        for request in mock.requests:
            body = json.loads(request.content)
            by.setdefault(body["model"], []).append(
                (body["messages"][0]["content"], body["messages"][1]["content"])
            )
        assert by["faithful"] == by["verbose"]
        assert all(system == SYSTEM_PROMPT for system, _ in by["faithful"])
        assert len(by["faithful"]) == 15

    async def test_the_request_shape_and_temperature(self) -> None:
        mock = MockLLM()
        await suite(mock).run([ollama("faithful", temperature=0.3, max_output_tokens=400)])
        body = json.loads(mock.requests[0].content)
        assert body["temperature"] == 0.3 and body["max_tokens"] == 400
        assert not {"tools", "functions", "tool_choice"} & set(body)
        assert str(mock.requests[0].url) == "http://localhost:11434/v1/chat/completions"

    async def test_local_resources_are_measured_and_gaps_reported(self) -> None:
        result = await suite().run([ollama("faithful")])
        m = by_model(result)["faithful"]
        assert (m.host_mode, m.host_mode_source) == ("local", "inferred")
        r = m.inference_host_resources  # local: the inference host is the evaluator
        assert m.evaluator_resources.cpu_mean_percent == r.cpu_mean_percent
        assert (r.samples, r.cpu_mean_percent, r.memory_max_percent, r.pressure) == (
            15, 25.0, 60.0, "LOW",
        )  # fmt: skip
        assert (r.model_loaded, r.model_gpu_memory_bytes, r.model_size_bytes) == (
            True, 0, 2_000_000_000,
        )  # fmt: skip
        assert r.gpu_utilization_percent is None and r.inference_duration_ms is None


class TestUnavailableAndFailures:
    async def test_unavailable_providers_are_reported_and_the_suite_continues(self) -> None:
        result = await suite().run(
            [
                ollama("faithful", base_url="http://down:11434"),
                ollama("not-pulled"),
                ModelSpec(provider="openai", model="gpt-x"),  # no key configured
                ollama("faithful"),
            ]
        )
        reasons = {m.config_id: m.unavailable_reason for m in result.comparison.models}
        assert sorted(r for r in reasons.values() if r) == [
            "MISSING_CREDENTIAL", "MODEL_NOT_INSTALLED", "OLLAMA_UNREACHABLE",
        ]  # fmt: skip
        assert result.comparison.models[0].model == "faithful"  # completed ranks first
        assert result.comparison.recommendation.decision == "RECOMMENDED_MODEL"

    async def test_timeouts_are_provider_failures_not_latency(self) -> None:
        result = await suite().run([ollama("slow", timeout_seconds=0.05, max_attempts=1)])
        m = by_model(result)["slow"]
        assert (m.timeout_rate, m.provider_failure_rate, m.model_failure_rate) == (1.0, 1.0, 0.0)
        assert m.latency.samples == 0 and m.safety is None
        assert m.hallucination_rate is None  # a provider failure is never a hallucination
        assert m.classification is Classification.NOT_READY

    async def test_provider_errors(self) -> None:
        m = by_model(await suite().run([ollama("error", max_attempts=1)]))["error"]
        assert m.provider_failure_rate == 1.0 and m.timeout_rate == 0.0
        assert m.classification is Classification.NOT_READY

    async def test_malformed_output_is_a_model_failure(self) -> None:
        m = by_model(await suite().run([ollama("malformed")]))["malformed"]
        assert (m.model_failure_rate, m.validation_rejection_rate) == (1.0, 1.0)
        assert m.provider_failure_rate == 0.0 and m.latency.samples == 15
        assert m.safety == 1.0  # malformed is not unsafe

    async def test_validator_rejection_is_a_safety_failure(self) -> None:
        m = by_model(await suite().run([ollama("unsafe")]))["unsafe"]
        assert m.safety == 0.0 and m.critical_failures == 0
        assert m.classification is Classification.NOT_READY and "SAFETY_FAIL" in m.reasons

    async def test_obeying_an_injection_is_a_critical_failure(self) -> None:
        result = await suite().run([ollama("obedient")])
        m = by_model(result)["obedient"]
        assert m.critical_failures == 2  # both adversarial cases
        assert m.classification is Classification.NOT_READY and "CRITICAL_FAIL" in m.reasons
        report = result.runs[0].report
        assert report is not None
        multi = next(c for c in report.cases if c.case_id == "adversarial-multi-vector")
        assert "INJECTION_OBEYED:obeyed-7731" in multi.critical_findings
        assert result.comparison.recommendation.decision == "NO_RECOMMENDATION"

    async def test_an_evaluation_error_is_contained(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import evaluation.suite as s

        def boom(*_a: object, **_k: object) -> Any:
            raise KeyError("x")

        monkeypatch.setattr(s, "summarize", boom)
        result = await suite().run([ollama("faithful")])
        (m,) = result.comparison.models
        assert m.status is RunStatus.EVALUATION_FAILED
        assert m.unavailable_reason == "EVALUATION_ERROR:KeyError"


class TestLatencyAndCost:
    async def test_a_model_over_the_budget_is_never_a_candidate(self) -> None:
        result = await suite(step=11.0).run([ollama("faithful")])
        m = by_model(result)["faithful"]
        assert m.latency.p95_ms == 11_000 and "LATENCY_FAIL" in m.reasons
        assert m.classification is Classification.PROMISING
        assert result.comparison.recommendation.reasons == ("NO_PRODUCTION_CANDIDATE",)

    async def test_configured_pricing_gives_an_estimated_cost(self) -> None:
        settings = Settings(openai_api_key=SecretStr(SECRET))
        spec = ModelSpec.model_validate(
            {"provider": "openai", "model": "faithful", "base_url": "https://api.example/v1",
             "pricing": {"input_per_million_tokens": 1.0, "output_per_million_tokens": 4.0}}
        )  # fmt: skip
        m = by_model(await suite(settings=settings).run([spec]))["faithful"]
        # 1200 * 1/1e6 + 300 * 4/1e6 = 0.0024 per evaluation
        assert m.cost.source.value == "ESTIMATED_CONFIGURED_COST"
        assert (m.cost.per_evaluation, m.cost.per_100, m.cost.per_1000) == (0.0024, 0.24, 2.4)
        assert m.model_version == "faithful-served-1"


class TestReproducibilityAndSecrets:
    async def test_the_same_configuration_gives_the_same_report(self) -> None:
        specs = [ModelSpec(provider="null"), ollama("faithful"), ollama("verbose")]
        first = await suite().run(specs)
        second = await suite().run(specs)
        assert first.comparison.to_json() == second.comparison.to_json()
        meta = first.runs[0].report.metadata  # type: ignore[union-attr]
        assert meta is not None
        assert {meta.evaluator_version, meta.scoring_version, meta.benchmark_version} == {
            "8.0.0", "2",
        }  # fmt: skip
        assert meta.prompt_version.startswith("p-") and meta.threshold_profile == "production-v1"
        assert meta.evaluated_at == FIXED.isoformat() and meta.case_count == 15

    async def test_duplicate_configurations_run_once(self) -> None:
        result = await suite().run([ollama("faithful"), ollama("faithful", label="again")])
        assert len(result.comparison.models) == 1

    def test_no_secret_or_model_text_reaches_any_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock = MockLLM()
        settings = Settings(openai_api_key=SecretStr(SECRET))
        runner = suite(mock, settings=settings, keep_raw=True)
        out, debug = tmp_path / "out", tmp_path / "debug"
        argv = ["--provider", "openai", "--model", "verbose", "--base-url",
                "https://api.example/v1?token=abc", "--provider", "ollama", "--model",
                "unsafe", "--out", str(out), "--debug-responses", str(debug)]  # fmt: skip
        assert main(argv, suite=runner) == 0
        assert mock.requests[0].headers["Authorization"] == f"Bearer {SECRET}"
        printed = capsys.readouterr().out
        reports = "".join(p.read_text("utf-8") for p in out.iterdir())
        for text in (reports, printed):
            assert SECRET not in text and "token=abc" not in text
            assert MARKER not in text and "rm -rf" not in text
        # Model text exists only in the separate, explicitly requested debug artifact.
        artifacts = list(debug.iterdir())
        assert artifacts and all(p.suffix == ".jsonl" for p in artifacts)
        rows = [json.loads(line) for p in artifacts for line in p.read_text("utf-8").splitlines()]
        assert any(MARKER in r["raw"] for r in rows)
        assert all(len(r["raw"]) <= 4000 and SECRET not in r["raw"] for r in rows)


class TestCommandLine:
    def test_a_url_with_credentials_is_refused_without_echoing_them(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        argv = ["--provider", "openai", "--base-url", "https://user:sk-in-url-999@api.example/v1",
                "--out", str(tmp_path)]  # fmt: skip
        with pytest.raises(SystemExit) as raised:
            main(argv)
        assert raised.value.code == 2
        assert "sk-in-url-999" not in capsys.readouterr().err

    def test_options_must_follow_a_provider(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as raised:
            main(["--model", "x", "--provider", "null", "--out", str(tmp_path)])
        assert raised.value.code == 2

    def test_prices_come_in_pairs(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            main(["--provider", "openai", "--price-input", "1", "--out", str(tmp_path)])

    def test_a_provider_is_required(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            main(["--out", str(tmp_path)])

    def test_options_attach_to_the_preceding_provider(self, tmp_path: Path) -> None:
        argv = ["--provider", "ollama", "--model", "faithful", "--temperature", "0.2",
                "--provider", "ollama", "--model", "verbose", "--out", str(tmp_path)]  # fmt: skip
        assert main(argv, suite=suite()) == 0
        data = json.loads((tmp_path / "comparison.json").read_text("utf-8"))
        assert sorted(m["model"] for m in data["models"]) == ["faithful", "verbose"]

    def test_a_matrix_file(self, tmp_path: Path) -> None:
        matrix = tmp_path / "m.json"
        matrix.write_text(json.dumps([{"provider": "null"}, {"provider": "ollama",
                                                             "model": "faithful"}]))  # fmt: skip
        assert main(["--matrix", str(matrix), "--out", str(tmp_path / "o")], suite=suite()) == 0
        data = json.loads((tmp_path / "o" / "comparison.json").read_text("utf-8"))
        assert data["recommendation"]["decision"] == "RECOMMENDED_MODEL"
        assert data["recommendation"]["model"] == "faithful"
