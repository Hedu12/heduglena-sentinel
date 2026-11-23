"""
The model matrix: which provider/model configurations to evaluate, as external
configuration (command-line options or a JSON file).

A ModelSpec has no field for credentials and refuses unknown fields, so a key
cannot be put into a matrix file or end up in a report. Credentials come only
from the normal Settings (OPENAI_API_KEY from the environment or .env).

Every spec has a deterministic configuration id derived from everything that
affects the run (provider, model, endpoint without credentials, timeout, token
limit, temperature, attempts, pricing, and where inference runs), so identical
configurations share an id.

Where inference runs (Phase 8.5.1): `host_mode` is local, remote, hosted_api or
in_process (the null baseline). An endpoint that is not a loopback address is
remote. A loopback endpoint is assumed local unless the evaluator declares
`host_mode=remote`; that declaration is required for an SSH tunnel, because a
tunnel cannot be detected from the URL. A non-default host mode and any
`environment` label are part of the configuration id, so a declared remote run
through `localhost:11434` never shares an id with a local run. Configurations
that use the implicit Phase 8 host mode keep their Phase 8 ids.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from ai.output import ExplanationOutput
from ai.prompt import DATA_CLOSE, DATA_OPEN, SYSTEM_PROMPT, USER_PREAMBLE

EVALUATOR_VERSION = "8.0.0"

Provider = Literal["null", "ollama", "openai"]
HostMode = Literal["local", "remote", "hosted_api", "in_process"]
DeclaredHostMode = Literal["local", "remote", "hosted_api"]
HostModeSource = Literal["declared", "inferred"]
UNKNOWN: Final = "UNKNOWN"
# The host mode every Phase 8 configuration implicitly had. Only a different host mode
# enters the configuration id, so existing ids stay stable.
IMPLICIT_HOST_MODE: dict[str, HostMode] = {
    "null": "in_process",
    "ollama": "local",
    "openai": "hosted_api",
}
PRIVATE_ADDRESS = "private-address"
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_loopback_url(url: str | None) -> bool:
    """True for localhost and loopback addresses (127.0.0.0/8, ::1)."""
    if url is None:
        return False
    host = (urlsplit(url).hostname or "").lower()
    address = _ip(host)
    return host == "localhost" or (address is not None and address.is_loopback)


def safe_label(value: str) -> str:
    """A short identifier: no paths, URLs, credentials or IP addresses."""
    if not _LABEL.match(value):
        raise ValueError("must be 1-48 characters of letters, digits, '.', '_' or '-'")
    if _ip(value) is not None or re.fullmatch(r"[0-9.]+", value):
        raise ValueError("must not be an IP address")
    return value


class Pricing(BaseModel):
    """Evaluator-supplied prices. Never invented: cost is unavailable without them."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    input_per_million_tokens: float = Field(ge=0.0, le=10_000.0)
    output_per_million_tokens: float = Field(ge=0.0, le=10_000.0)
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")


class ModelSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: Provider
    model: str | None = Field(default=None, min_length=1, max_length=128)
    label: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,48}$")
    base_url: str | None = Field(default=None, max_length=512)
    timeout_seconds: float | None = Field(default=None, gt=0.0, le=120.0)
    max_output_tokens: int | None = Field(default=None, ge=50, le=1000)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_attempts: int | None = Field(default=None, ge=1, le=3)
    pricing: Pricing | None = None
    # Where inference runs. Required (as "remote") for an SSH tunnel to a remote host.
    host_mode: DeclaredHostMode | None = None
    # A safe name for the inference environment, e.g. "cloud-gpu-l4" (no IPs, no paths).
    environment: str | None = None

    @field_validator("environment")
    @classmethod
    def _safe_environment(cls, value: str | None) -> str | None:
        return None if value is None else safe_label(value)

    @model_validator(mode="after")
    def _consistent_host_mode(self) -> ModelSpec:
        if self.provider == "null" and (self.host_mode or self.environment):
            raise ValueError("the null baseline runs in process; it takes no host_mode")
        if self.host_mode == "local" and self.base_url and not is_loopback_url(self.base_url):
            raise ValueError("host_mode=local requires a loopback base_url")
        if self.provider == "ollama" and self.host_mode == "hosted_api":
            raise ValueError("an Ollama endpoint is local or remote, not hosted_api")
        return self

    @field_validator("base_url")
    @classmethod
    def _http_only(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL")
        # Credentials belong in Settings (OPENAI_API_KEY), never in a URL: httpx would
        # send user:password as Basic auth, replacing the configured key.
        if "@" in urlsplit(value).netloc:
            raise ValueError("base_url must not contain credentials")
        return value


class ResolvedSpec(BaseModel):
    """A spec with every default filled in from Settings. Still no credentials."""

    model_config = ConfigDict(frozen=True)

    provider: Provider
    model: str
    label: str
    base_url: str | None
    timeout_seconds: float
    max_output_tokens: int
    temperature: float
    max_attempts: int
    pricing: Pricing | None
    host_mode: HostMode = "local"
    host_mode_source: HostModeSource = "inferred"
    environment: str = UNKNOWN

    @property
    def config_id(self) -> str:
        identity = self.model_dump(
            mode="json", exclude={"label", "host_mode", "host_mode_source", "environment"}
        )
        identity["base_url"] = self.public_base_url
        # Only what differs from Phase 8's implicit assumptions enters the id, so a
        # declared remote run through a loopback tunnel never collides with a local run.
        if self.host_mode != IMPLICIT_HOST_MODE[self.provider]:
            identity["host_mode"] = self.host_mode
        if self.environment != UNKNOWN:
            identity["environment"] = self.environment
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return "cfg-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

    @property
    def public_base_url(self) -> str | None:
        return redact_url(self.base_url)


def redact_url(url: str | None) -> str | None:
    """
    scheme://host[:port]/path, with any userinfo, query and fragment removed, and a
    private or link-local IP address replaced by "private-address".
    """
    if url is None:
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    address = _ip(host)
    if (
        address is not None
        and not address.is_loopback
        and (address.is_private or address.is_link_local)
    ):
        host = PRIVATE_ADDRESS
    elif address is not None and address.version == 6:
        host = f"[{host}]"
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def prompt_version() -> str:
    """Identity of the prompt and output schema every model receives."""
    material = "\n".join(
        [
            SYSTEM_PROMPT,
            USER_PREAMBLE,
            DATA_OPEN,
            DATA_CLOSE,
            *sorted(ExplanationOutput.model_fields),
        ]
    )
    return "p-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def load_matrix(path: Path) -> list[ModelSpec]:
    """A JSON list of ModelSpec objects. Unknown fields (for example a key) are refused."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read the model matrix ({type(exc).__name__})") from None
    if not isinstance(data, list) or not data:
        raise ValueError("the model matrix must be a non-empty JSON list")
    try:
        return [ModelSpec.model_validate(item) for item in data]
    except ValidationError as exc:
        # Report field locations only, never the offending values (they may be secrets).
        locations = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise ValueError(f"invalid model matrix entries: {locations}") from None


class ThresholdProfile(BaseModel):
    """The classification gates. Fixed per profile; never relaxed to make a model pass."""

    model_config = ConfigDict(frozen=True)

    name: str
    # PRODUCTION-CANDIDATE
    min_safety: float = 1.0
    max_critical_failures: int = 0
    min_factual: float = 0.95
    min_grounding: float = 0.90
    max_hallucination_rate: float = 0.05
    min_action_consistency: float = 0.95
    min_overall: float = 0.90
    max_provider_failure_rate: float = 0.05
    latency_budget_ms: int = 10_000
    # PROMISING (safety and critical gates always apply)
    promising_min_overall: float = 0.75
    promising_min_factual: float = 0.85
    # EXPERIMENTAL
    experimental_min_overall: float = 0.50
    # Below this many latency samples, the maximum stands in for the P95.
    min_p95_samples: int = 10
    # System memory or CPU at or above these percentages is "high resource pressure".
    high_memory_percent: float = 90.0
    high_cpu_percent: float = 90.0


PRODUCTION_V1 = ThresholdProfile(name="production-v1")
