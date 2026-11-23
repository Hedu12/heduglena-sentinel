"""
Read-only provider checks and resource measurement for local models.

  * Ollama inventory: GET /api/tags (is the model installed, its digest and size)
    and GET /api/ps (is it loaded, how much is in GPU memory). Read-only endpoints;
    nothing is pulled, loaded or unloaded.
  * System-wide CPU and memory utilisation (psutil), sampled between cases. No
    per-process data, command lines, files or user data are read.

Anything that cannot be measured safely is reported as unavailable (None), never
estimated: GPU utilisation (would need a vendor tool via a subprocess) and
inference duration (the OpenAI-compatible endpoint does not report it).
This module is the only part of the evaluation package that may use httpx or psutil.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import psutil
from pydantic import BaseModel, ConfigDict

MAX_INVENTORY_BYTES = 2_000_000


@dataclass(frozen=True, slots=True)
class OllamaStatus:
    reachable: bool
    installed: bool = False
    digest: str | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    size_bytes: int | None = None
    error: str | None = None  # a fixed code, never response text

    @property
    def version(self) -> str | None:
        if self.digest is None:
            return None
        details = " ".join(x for x in (self.parameter_size, self.quantization) if x)
        return f"{self.digest[:12]}{f' ({details})' if details else ''}"


def _matches(name: str, wanted: str) -> bool:
    return name == wanted or name == f"{wanted}:latest" or name.split(":")[0] == wanted


async def _get_json(
    base_url: str, path: str, timeout: float, transport: httpx.AsyncBaseTransport | None
) -> object:
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, transport=transport
    ) as client:
        reply = await client.get(base_url.rstrip("/") + path)
    if reply.status_code != 200 or len(reply.content) > MAX_INVENTORY_BYTES:
        raise ValueError(f"HTTP {reply.status_code}")
    return reply.json()


def _entries(body: object) -> list[dict[str, object]]:
    models = body.get("models") if isinstance(body, dict) else None
    return [m for m in models if isinstance(m, dict)] if isinstance(models, list) else []


async def ollama_status(
    base_url: str,
    model: str,
    timeout: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> OllamaStatus:
    """Is the Ollama server reachable, and is the model installed? Never raises."""
    try:
        body = await _get_json(base_url, "/api/tags", timeout, transport)
    except (httpx.HTTPError, ValueError) as exc:
        code = "UNREACHABLE" if isinstance(exc, httpx.HTTPError) else "BAD_RESPONSE"
        return OllamaStatus(reachable=False, error=code)
    for entry in _entries(body):
        if not _matches(str(entry.get("name", "")), model):
            continue
        raw_details = entry.get("details")
        details = raw_details if isinstance(raw_details, dict) else {}
        size = entry.get("size")
        return OllamaStatus(
            reachable=True,
            installed=True,
            digest=str(entry.get("digest") or "") or None,
            parameter_size=str(details.get("parameter_size") or "") or None,
            quantization=str(details.get("quantization_level") or "") or None,
            size_bytes=size if isinstance(size, int) else None,
        )
    return OllamaStatus(reachable=True, installed=False, error="MODEL_NOT_INSTALLED")


async def ollama_loaded(
    base_url: str,
    model: str,
    timeout: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool | None, int | None]:
    """(loaded, bytes in GPU memory) from /api/ps; (None, None) if unavailable."""
    try:
        body = await _get_json(base_url, "/api/ps", timeout, transport)
    except (httpx.HTTPError, ValueError):
        return None, None
    for entry in _entries(body):
        if _matches(str(entry.get("name", "")), model):
            vram = entry.get("size_vram")
            return True, vram if isinstance(vram, int) else None
    return False, None


class ResourceUsage(BaseModel):
    """Resource measurements for one evaluated model. None means unavailable."""

    model_config = ConfigDict(frozen=True)

    samples: int = 0
    cpu_mean_percent: float | None = None
    cpu_max_percent: float | None = None
    memory_max_percent: float | None = None
    gpu_utilization_percent: float | None = None  # not measured: needs a vendor tool
    inference_duration_ms: float | None = None  # not reported by the endpoint used
    model_loaded: bool | None = None
    model_gpu_memory_bytes: int | None = None
    model_size_bytes: int | None = None
    pressure: str | None = None  # LOW | MODERATE | HIGH

    def unavailable(self) -> list[str]:
        names = [n for n in type(self).model_fields if n != "samples"]
        return [n for n in names if getattr(self, n) is None]


def estimate_pressure(
    cpu_mean: float | None, memory_max: float | None, *, high_cpu: float, high_memory: float
) -> str | None:
    """Estimated resource pressure from system-wide utilisation; None if unmeasured."""
    if cpu_mean is None or memory_max is None:
        return None
    if cpu_mean >= high_cpu or memory_max >= high_memory:
        return "HIGH"
    if cpu_mean >= high_cpu * 0.75 or memory_max >= high_memory * 0.85:
        return "MODERATE"
    return "LOW"


@dataclass
class ResourceSampler:
    """System-wide CPU and memory, sampled after each case. Never raises."""

    cpu: list[float] = field(default_factory=list)
    memory: list[float] = field(default_factory=list)
    failed: bool = False

    def start(self) -> None:
        try:
            psutil.cpu_percent(interval=None)  # primes the counter
        except Exception:
            self.failed = True

    def sample(self) -> None:
        if self.failed:
            return
        try:
            self.cpu.append(float(psutil.cpu_percent(interval=None)))
            self.memory.append(float(psutil.virtual_memory().percent))
        except Exception:
            self.failed = True

    def usage(self, *, high_cpu: float, high_memory: float) -> ResourceUsage:
        if self.failed or not self.cpu:
            return ResourceUsage()
        cpu_mean = round(sum(self.cpu) / len(self.cpu), 1)
        memory_max = max(self.memory)
        return ResourceUsage(
            samples=len(self.cpu),
            cpu_mean_percent=cpu_mean,
            cpu_max_percent=max(self.cpu),
            memory_max_percent=memory_max,
            pressure=estimate_pressure(
                cpu_mean, memory_max, high_cpu=high_cpu, high_memory=high_memory
            ),
        )
