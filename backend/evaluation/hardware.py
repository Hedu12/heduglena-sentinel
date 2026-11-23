"""
Hardware metadata for evaluation reports (Phase 8.5.1). Read-only, in-process.

Records only non-identifying facts about the *evaluator* machine: CPU model and
core counts, total RAM, operating system and architecture. Sources: psutil
(counts, RAM), the platform module (OS name and release, architecture), and the
CPU name from the Windows registry (read-only) or /proc/cpuinfo on Linux.

Never recorded: hostname, user name, home or other paths, environment
variables, IP addresses, serial numbers. No subprocess is started, so GPU name
and GPU memory are UNKNOWN (they would need a vendor tool).

A remote inference host's hardware cannot be observed from here and is always
UNKNOWN; it is never inferred or copied from the evaluator.
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict

from evaluation.matrix import UNKNOWN, HostMode

Unknown = Literal["UNKNOWN"]
HardwareSource = Literal["MEASURED_EVALUATOR", "SAME_AS_EVALUATOR", "UNKNOWN"]
MAX_TEXT = 96


class HardwareInfo(BaseModel):
    """Hardware of one machine. Every unmeasured field is "UNKNOWN"."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: HardwareSource = "UNKNOWN"
    cpu_model: str = UNKNOWN
    cpu_logical_cores: int | Unknown = UNKNOWN
    cpu_physical_cores: int | Unknown = UNKNOWN
    ram_total_bytes: int | Unknown = UNKNOWN
    gpu: str = UNKNOWN
    gpu_memory_bytes: int | Unknown = UNKNOWN
    os: str = UNKNOWN
    architecture: str = UNKNOWN


def _clean(value: object) -> str:
    """Printable, single-line, bounded text; UNKNOWN if empty."""
    text = " ".join(str(value).split())
    text = "".join(c for c in text if c.isprintable())[:MAX_TEXT].strip()
    return text or UNKNOWN


def _count(value: object) -> int | Unknown:
    return (
        value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else UNKNOWN
    )


def _cpu_name() -> str:
    if sys.platform == "win32":
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            with key:
                value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            return _clean(value)
        except OSError:
            return UNKNOWN
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    return _clean(line.split(":", 1)[1])
        except OSError:
            return UNKNOWN
    return UNKNOWN


def probe_evaluator() -> HardwareInfo:
    """The evaluator machine's hardware. Never raises; unmeasured fields are UNKNOWN."""
    try:
        logical = psutil.cpu_count(logical=True)
        physical = psutil.cpu_count(logical=False)
        ram = psutil.virtual_memory().total
    except Exception:
        logical = physical = ram = None
    try:
        system = f"{platform.system()} {platform.release()}"
        machine = platform.machine()
    except Exception:
        system = machine = ""
    return HardwareInfo(
        source="MEASURED_EVALUATOR",
        cpu_model=_cpu_name(),
        cpu_logical_cores=_count(logical),
        cpu_physical_cores=_count(physical),
        ram_total_bytes=_count(ram),
        os=_clean(system),
        architecture=_clean(machine),
    )


HardwareProbe = Callable[[], HardwareInfo]


def inference_host_hardware(host_mode: HostMode, evaluator: HardwareInfo) -> HardwareInfo:
    """
    The inference host's hardware. Local and in-process inference run on the
    evaluator; a remote host or hosted API is UNKNOWN (never copied or guessed).
    """
    if host_mode in ("local", "in_process"):
        return evaluator.model_copy(update={"source": "SAME_AS_EVALUATOR"})
    return HardwareInfo()
