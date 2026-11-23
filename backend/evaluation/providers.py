"""
Provider preparation for evaluation runs.

Every model is driven through the production provider adapters and the
production Explainer. The single evaluation-only difference is
EvalOpenAICompatibleProvider, which lets the matrix set the sampling temperature
(production always sends 0; the default here is also 0). It changes nothing
else in the request: same messages, same token cap, no tools, no redirects.

Before a run, a read-only availability check decides whether a provider can be
evaluated at all: an unreachable Ollama server, a model that is not installed,
or a missing OpenAI key gives PROVIDER_UNAVAILABLE with a reason code, and the
suite continues with the other models. Keys come only from Settings and are
never placed in a spec, a report or an error message.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace

import httpx
from pydantic import SecretStr

from ai.adapters.null_adapter import NULL_MODEL_NAME, NullProvider
from ai.adapters.openai_compatible import OpenAICompatibleProvider
from ai.explainer import ExplainerLimits
from ai.factory import explainer_limits
from ai.protocols import ExplanationRequest, LLMProvider
from core.config import Settings
from evaluation.matrix import (
    UNKNOWN,
    HostMode,
    HostModeSource,
    ModelSpec,
    ResolvedSpec,
    is_loopback_url,
)
from evaluation.resources import OllamaStatus, ollama_status

OllamaCheck = Callable[[str, str], Awaitable[OllamaStatus]]


class EvalOpenAICompatibleProvider(OpenAICompatibleProvider):
    """The production adapter with a configurable temperature (evaluation only)."""

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        model: str,
        timeout_seconds: float,
        temperature: float,
        api_key: SecretStr | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            name=name,
            base_url=base_url,
            model=model,
            timeout_seconds=timeout_seconds,
            api_key=api_key,
            transport=transport,
        )
        self._temperature = temperature

    def payload(self, request: ExplanationRequest) -> dict[str, object]:
        body = super().payload(request)
        body["temperature"] = self._temperature
        return body


def _label(provider: str, model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", f"{provider}-{model}").strip("-")[:48] or provider


def resolve(spec: ModelSpec, settings: Settings) -> ResolvedSpec:
    """Fill every unset option from Settings, so the run is fully described."""
    if spec.provider == "null":
        model, base_url = NULL_MODEL_NAME, None
    elif spec.provider == "ollama":
        model = spec.model or settings.ollama_model
        base_url = spec.base_url or settings.ollama_base_url
    else:
        model = spec.model or settings.openai_model
        base_url = spec.base_url or settings.openai_base_url
    host_mode, source = host_mode_of(spec, base_url)
    return ResolvedSpec(
        provider=spec.provider,
        model=model,
        label=spec.label or _label(spec.provider, model),
        base_url=base_url,
        timeout_seconds=spec.timeout_seconds or settings.ai_explanation_timeout_seconds,
        max_output_tokens=spec.max_output_tokens or settings.ai_max_output_tokens,
        temperature=spec.temperature,
        max_attempts=spec.max_attempts or settings.ai_max_attempts,
        pricing=spec.pricing,
        host_mode=host_mode,
        host_mode_source=source,
        environment=spec.environment or UNKNOWN,
    )


def host_mode_of(spec: ModelSpec, base_url: str | None) -> tuple[HostMode, HostModeSource]:
    """
    Where inference runs. A declaration wins; otherwise a non-loopback endpoint is
    remote, a loopback endpoint is assumed local (a tunnel must be declared remote),
    an OpenAI-compatible API is hosted, and the null baseline runs in process.
    """
    if spec.provider == "null":
        return "in_process", "inferred"
    if spec.host_mode is not None:
        if spec.host_mode == "local" and base_url and not is_loopback_url(base_url):
            raise ValueError(f"{spec.provider}: host_mode=local requires a loopback endpoint")
        return spec.host_mode, "declared"
    if spec.provider == "openai":
        return "hosted_api", "inferred"
    return ("local" if is_loopback_url(base_url) else "remote"), "inferred"


def limits_for(spec: ResolvedSpec, settings: Settings) -> ExplainerLimits:
    """Production limits, with the spec's timeout, token cap and attempts."""
    return replace(
        explainer_limits(settings),
        timeout_seconds=spec.timeout_seconds,
        max_output_tokens=spec.max_output_tokens,
        max_attempts=spec.max_attempts,
    )


@dataclass(frozen=True, slots=True)
class Prepared:
    provider: LLMProvider | None
    unavailable: str | None = None  # reason code when provider is None
    model_version: str | None = None
    model_size_bytes: int | None = None


async def check_ollama(base_url: str, model: str) -> OllamaStatus:
    """The default, read-only Ollama availability check."""
    return await ollama_status(base_url, model)


async def prepare(
    spec: ResolvedSpec,
    settings: Settings,
    *,
    ollama_check: OllamaCheck = check_ollama,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Prepared:
    """A ready provider, or the reason it cannot be evaluated. Never raises."""
    if spec.provider == "null":
        return Prepared(NullProvider(), model_version=NULL_MODEL_NAME)
    base_url = spec.base_url or ""
    if spec.provider == "ollama":
        status = await ollama_check(base_url, spec.model)
        if not status.reachable:
            return Prepared(None, unavailable=f"OLLAMA_{status.error or 'UNREACHABLE'}")
        if not status.installed:
            return Prepared(None, unavailable="MODEL_NOT_INSTALLED")
        provider = EvalOpenAICompatibleProvider(
            name="ollama",
            base_url=base_url.rstrip("/") + "/v1",
            model=spec.model,
            timeout_seconds=spec.timeout_seconds,
            temperature=spec.temperature,
            transport=transport,
        )
        return Prepared(provider, model_version=status.version, model_size_bytes=status.size_bytes)
    key = settings.openai_api_key
    if not key.get_secret_value():
        return Prepared(None, unavailable="MISSING_CREDENTIAL")
    provider = EvalOpenAICompatibleProvider(
        name="openai",
        base_url=base_url,
        model=spec.model,
        timeout_seconds=spec.timeout_seconds,
        api_key=key,
        temperature=spec.temperature,
        transport=transport,
    )
    return Prepared(provider)
