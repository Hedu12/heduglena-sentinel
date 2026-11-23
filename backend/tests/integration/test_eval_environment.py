"""
Phase 8.5.1: the evaluation reports where inference ran and on what hardware.

1. The evaluator's resources are never labelled as a remote host's.
2. Local and remote configurations (even through a loopback tunnel) never share an id.
3. Remote hardware that cannot be observed is UNKNOWN, never copied or guessed.
4. No sensitive value (hostname, user, paths, secrets, private IPs) reaches metadata.
Scoring, thresholds, ranking and rerendering are unchanged.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from ai.adapters.null_adapter import deterministic_explanation
from ai.context import IncidentContext
from ai.prompt import DATA_CLOSE, DATA_OPEN
from core.config import Settings
from evaluation.__main__ import main
from evaluation.hardware import HardwareInfo, probe_evaluator
from evaluation.matrix import ModelSpec, redact_url
from evaluation.providers import resolve
from evaluation.rerender import rerender
from evaluation.resources import OllamaStatus
from evaluation.selection import Classification, ModelSummary
from evaluation.suite import Suite, SuiteResult

REPORTS = Path(__file__).resolve().parents[3] / "reports"
FAKE_HW = HardwareInfo(
    source="MEASURED_EVALUATOR", cpu_model="Test CPU 4000", cpu_logical_cores=8,
    cpu_physical_cores=4, ram_total_bytes=8 * 1024**3, os="TestOS 1", architecture="x86_64",
)  # fmt: skip
UNKNOWN_FIELDS = ("cpu_model", "cpu_logical_cores", "cpu_physical_cores", "ram_total_bytes",
                  "gpu", "gpu_memory_bytes", "os", "architecture")  # fmt: skip


async def answer(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    user = body["messages"][1]["content"]
    ctx = IncidentContext.model_validate_json(user.split(DATA_OPEN, 1)[1].rsplit(DATA_CLOSE, 1)[0])
    content = json.dumps(deterministic_explanation(ctx))
    return httpx.Response(
        200,
        json={
            "model": body["model"],
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        },
    )


async def installed(base_url: str, model: str) -> OllamaStatus:
    return OllamaStatus(reachable=True, installed=True, digest="sha256:feedfacecafe", size_bytes=5)


async def on_gpu(base_url: str, model: str) -> tuple[bool | None, int | None]:
    return True, 4_000_000_000  # what the inference server reports for its loaded model


def suite(settings: Settings | None = None, probe: Any = None) -> Suite:
    ticks = iter(range(10**9))
    return Suite(
        settings or Settings(),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        monotonic=lambda: next(ticks) / 1000,
        ollama_check=installed,
        loaded_check=on_gpu,
        transport=httpx.MockTransport(answer),
        hardware_probe=probe or (lambda: FAKE_HW),
    )


@pytest.fixture(autouse=True)
def evaluator_load(monkeypatch: pytest.MonkeyPatch) -> None:
    import evaluation.resources as res

    monkeypatch.setattr(res.psutil, "cpu_percent", lambda interval=None: 25.0)

    class Memory:
        percent = 60.0

    monkeypatch.setattr(res.psutil, "virtual_memory", lambda: Memory())


LOCAL = ModelSpec(provider="ollama", model="faithful")
TUNNEL = ModelSpec(provider="ollama", model="faithful", base_url="http://localhost:11434",
                   host_mode="remote", environment="cloud-gpu-test")  # fmt: skip


def by_mode(result: SuiteResult) -> dict[str, ModelSummary]:
    return {m.host_mode or "": m for m in result.comparison.models}


class TestResourceAttribution:
    """Requirement 1: evaluator resources are never labelled as a remote host's."""

    async def test_a_tunnelled_remote_run_does_not_report_the_laptop_as_the_host(self) -> None:
        result = await suite().run([LOCAL, TUNNEL])
        local, remote = by_mode(result)["local"], by_mode(result)["remote"]
        assert (remote.host_mode_source, remote.environment) == ("declared", "cloud-gpu-test")
        host = remote.inference_host_resources
        assert (host.cpu_mean_percent, host.cpu_max_percent, host.memory_max_percent,
                host.pressure) == (None, None, None, None)  # fmt: skip
        # Only what the inference server itself reports is attributed to the host.
        assert (host.model_loaded, host.model_gpu_memory_bytes) == (True, 4_000_000_000)
        assert remote.evaluator_resources.cpu_mean_percent == 25.0
        assert remote.evaluator_resources.model_loaded is None
        assert "RESOURCE_UNKNOWN" in remote.reasons
        assert "RESOURCE_ACCEPTABLE" not in remote.reasons
        # Local inference: the host is the evaluator, so the figures are the same.
        assert local.inference_host_resources.cpu_mean_percent == 25.0
        assert "RESOURCE_ACCEPTABLE" in local.reasons

    async def test_the_reports_label_both_machines(self) -> None:
        result = await suite().run([LOCAL, TUNNEL])
        md = result.comparison.to_markdown()
        host_table = md.split("## Inference host resources", 1)[1].split("## Evaluator", 1)[0]
        evaluator_table = md.split("## Evaluator resources", 1)[1].split("## Hardware", 1)[0]
        remote_host_row = next(r for r in host_table.splitlines() if "| remote |" in r)
        assert "25%" not in remote_host_row and "UNKNOWN" in remote_host_row
        remote_eval_row = next(r for r in evaluator_table.splitlines() if "| remote |" in r)
        assert "25%" in remote_eval_row
        meta = next(r.report for r in result.runs if r.summary.host_mode == "remote")
        assert meta is not None and meta.metadata is not None
        assert (meta.metadata.host_mode, meta.metadata.environment) == ("remote", "cloud-gpu-test")
        assert "Inference: host mode remote (declared)" in meta.to_markdown()

    async def test_a_hosted_api_host_is_unknown(self) -> None:
        settings = Settings(openai_api_key=SecretStr("sk-test-abcdefghijk"))
        spec = ModelSpec(provider="openai", model="faithful", base_url="https://api.example/v1")
        (m,) = (await suite(settings).run([spec])).comparison.models
        assert (m.host_mode, m.host_mode_source) == ("hosted_api", "inferred")
        assert m.inference_host_resources.cpu_mean_percent is None
        assert m.evaluator_resources.cpu_mean_percent == 25.0
        assert m.inference_host_hardware is not None
        assert m.inference_host_hardware.source == "UNKNOWN"

    async def test_scores_and_classification_do_not_depend_on_the_host(self) -> None:
        result = await suite().run([LOCAL, TUNNEL])
        local, remote = by_mode(result)["local"], by_mode(result)["remote"]
        assert local.classification is remote.classification is Classification.PRODUCTION_CANDIDATE
        quality = (
            "safety",
            "factual_accuracy",
            "evidence_grounding",
            "completeness",
            "hallucination_rate",
            "action_consistency",
            "presentation_quality",
            "overall",
        )
        assert [getattr(local, q) for q in quality] == [getattr(remote, q) for q in quality]


PINNED = Settings(ai_explanation_timeout_seconds=10.0, ai_max_output_tokens=500,
                  ai_max_attempts=2, ollama_base_url="http://localhost:11434")  # fmt: skip


class TestConfigurationIdentity:
    """Requirement 2: local and remote configurations cannot collide."""

    def test_a_declared_tunnel_differs_from_a_local_run_on_the_same_url(self) -> None:
        local = resolve(ModelSpec(provider="ollama", model="m"), PINNED)
        tunnel = resolve(ModelSpec(provider="ollama", model="m", host_mode="remote"), PINNED)
        assert local.base_url == tunnel.base_url == "http://localhost:11434"
        assert local.config_id != tunnel.config_id
        assert (local.host_mode, tunnel.host_mode) == ("local", "remote")

    def test_environment_labels_separate_remote_hosts(self) -> None:
        a = resolve(ModelSpec(provider="ollama", model="m", host_mode="remote",
                              environment="gpu-a"), PINNED)  # fmt: skip
        b = resolve(ModelSpec(provider="ollama", model="m", host_mode="remote",
                              environment="gpu-b"), PINNED)  # fmt: skip
        assert a.config_id != b.config_id

    def test_a_self_hosted_openai_compatible_server_differs_from_the_hosted_api(self) -> None:
        url = "https://llm.example/v1"
        hosted = resolve(ModelSpec(provider="openai", base_url=url), PINNED)
        remote = resolve(ModelSpec(provider="openai", base_url=url, host_mode="remote"), PINNED)
        assert hosted.config_id != remote.config_id

    def test_a_non_loopback_endpoint_is_remote(self) -> None:
        spec = resolve(ModelSpec(provider="ollama", base_url="http://gpu.example:11434"), PINNED)
        assert (spec.host_mode, spec.host_mode_source) == ("remote", "inferred")

    @pytest.mark.parametrize(
        ("model", "config_id"),
        [("llama3.2", "cfg-4ffc5c9ec72c"), ("qwen2.5:0.5b", "cfg-50b082296789")],
    )
    def test_phase8_configuration_ids_are_unchanged(self, model: str, config_id: str) -> None:
        assert resolve(ModelSpec(provider="ollama", model=model), PINNED).config_id == config_id
        assert resolve(ModelSpec(provider="null"), PINNED).config_id == "cfg-bdd11b17774a"

    async def test_both_runs_are_kept_in_one_suite(self) -> None:
        result = await suite().run([LOCAL, TUNNEL])
        assert sorted(m.host_mode or "" for m in result.comparison.models) == ["local", "remote"]

    @pytest.mark.parametrize(
        "spec",
        [{"provider": "null", "host_mode": "local"},
         {"provider": "ollama", "host_mode": "local", "base_url": "http://gpu.example:11434"},
         {"provider": "ollama", "host_mode": "hosted_api"},
         {"provider": "ollama", "host_mode": "sideways"}],
    )  # fmt: skip
    def test_inconsistent_host_declarations_are_refused(self, spec: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            ModelSpec.model_validate(spec)

    def test_a_local_declaration_against_a_remote_default_is_refused(self, tmp_path: Path) -> None:
        settings = Settings(ollama_base_url="http://gpu.example:11434")
        argv = ["--provider", "ollama", "--host-mode", "local", "--out", str(tmp_path)]
        with pytest.raises(SystemExit) as raised:
            main(argv, suite=suite(settings))
        assert raised.value.code == 2


class TestHardwareMetadata:
    """Requirement 3: unobservable hardware is UNKNOWN."""

    async def test_remote_hardware_is_unknown_and_local_is_the_evaluator(self) -> None:
        result = await suite().run([LOCAL, TUNNEL])
        local, remote = by_mode(result)["local"], by_mode(result)["remote"]
        assert remote.inference_host_hardware == HardwareInfo()
        assert all(getattr(remote.inference_host_hardware, f) == "UNKNOWN" for f in UNKNOWN_FIELDS)
        assert local.inference_host_hardware is not None
        assert local.inference_host_hardware.source == "SAME_AS_EVALUATOR"
        assert local.inference_host_hardware.cpu_model == "Test CPU 4000"
        assert result.comparison.evaluator_hardware == FAKE_HW
        data = json.loads(result.comparison.to_json())
        remote_hw = next(m for m in data["models"] if m["host_mode"] == "remote")
        assert remote_hw["inference_host_hardware"]["ram_total_bytes"] == "UNKNOWN"

    async def test_a_failing_probe_records_unknown(self) -> None:
        def broken() -> HardwareInfo:
            raise PermissionError("denied")

        result = await suite(probe=broken).run([LOCAL])
        assert result.comparison.evaluator_hardware == HardwareInfo()
        assert "CPU UNKNOWN" in result.comparison.to_markdown()

    def test_the_real_probe_measures_this_machine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.undo()  # the real psutil, not the fixture's stubs
        hw = probe_evaluator()
        assert hw.source == "MEASURED_EVALUATOR"
        assert isinstance(hw.cpu_logical_cores, int) and isinstance(hw.ram_total_bytes, int)
        assert hw.gpu == "UNKNOWN" and hw.gpu_memory_bytes == "UNKNOWN"  # no vendor tool


class TestSensitiveValues:
    """Requirement 4: nothing identifying or secret reaches metadata or reports."""

    async def test_no_identity_secret_or_path_in_any_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import getpass
        import platform

        monkeypatch.setenv("OPENAI_API_KEY", "sk-envsecret-1234567890")
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent-secret.sock")
        spec = ModelSpec(provider="ollama", model="faithful", base_url="http://10.20.30.40:11434",
                         environment="lab-gpu")  # fmt: skip
        result = await suite(probe=probe_evaluator).run([spec, TUNNEL])
        out = tmp_path / "out"
        out.mkdir()
        texts = [result.comparison.to_json(), result.comparison.to_markdown()]
        texts += [r.report.to_json() for r in result.runs if r.report is not None]
        blob = "\n".join(texts)
        forbidden = ["sk-envsecret", "ssh-agent-secret", "10.20.30.40", str(Path.home()),
                     platform.node()]  # fmt: skip
        user = getpass.getuser()
        if len(user) >= 3:
            forbidden.append(user)
        for value in filter(None, forbidden):
            assert value not in blob, value
        assert "http://private-address:11434" in blob

    @pytest.mark.parametrize(
        ("url", "public"),
        [("http://192.168.1.7:11434", "http://private-address:11434"),
         ("http://[fd00::7]:11434/v1", "http://private-address:11434/v1"),
         ("http://169.254.1.1:11434", "http://private-address:11434"),
         ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
         ("https://api.example/v1?key=sk-q", "https://api.example/v1")],
    )  # fmt: skip
    def test_private_addresses_are_masked(self, url: str, public: str) -> None:
        assert redact_url(url) == public

    @pytest.mark.parametrize(
        "label", ["10.0.0.5", "192.168.1.1", "/home/user", "user@host", "a b", "x" * 49,
                  "C:\\Users", "host:11434", ""],
    )  # fmt: skip
    def test_unsafe_environment_labels_are_refused(self, label: str) -> None:
        with pytest.raises(ValidationError):
            ModelSpec(provider="ollama", environment=label)


@pytest.mark.parametrize("phase", ["phase8.3", "phase8.4"])
def test_saved_reports_rerender_with_the_same_verdict_and_reasons(phase: str) -> None:
    source = REPORTS / phase
    if not (source / "comparison.json").exists():
        pytest.skip(f"no saved {phase} report")
    saved = json.loads((source / "comparison.json").read_text("utf-8"))
    new = rerender(source).comparison
    assert [m.config_id for m in new.models] == [m["config_id"] for m in saved["models"]]
    assert [m.classification.value for m in new.models] == [
        m["classification"] for m in saved["models"]
    ]
    assert [list(m.reasons) for m in new.models] == [m["reasons"] for m in saved["models"]]
    assert new.recommendation.decision == saved["recommendation"]["decision"]
    # Legacy "resources" are read as the (local) inference host's resources.
    real = next(m for m in new.models if not m.is_baseline)
    assert real.inference_host_resources.pressure == "HIGH"
    assert real.host_mode is None  # not recorded before Phase 8.5.1: reported UNKNOWN
