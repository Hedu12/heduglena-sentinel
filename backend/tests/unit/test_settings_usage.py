"""
Every configuration setting must do something.

A setting that nothing reads is misleading: an operator changes it and nothing
happens. Each field of Settings must be read by production code, or be listed in
RESERVED with the phase that will read it. When that phase lands, its entry is
removed here and the test keeps holding the line.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.config import Settings

BACKEND = Path(__file__).resolve().parents[2]
PRODUCTION_DIRS = (
    "ai",
    "api",
    "app",
    "core",
    "database",
    "detection",
    "explanation",
    "models",
    "response",
    "telemetry",
    "threat",
)

# Settings declared ahead of the phase that reads them. Keep this list short.
RESERVED: dict[str, str] = {
    "log_level": "app phase: logging configuration",
}

# Removed in the Phase 4 reconciliation. They must not come back unnoticed.
REMOVED = (
    "decay_rate",
    "escalation_multiplier",
    "baseline_window_size",
    "baseline_warmup_samples",
    "rule_cpu_spike_threshold",
    "rule_memory_pressure_threshold",
    "rule_cpu_sustained_threshold",
    "rule_cpu_sustained_seconds",
)


def _production_sources() -> str:
    config = (BACKEND / "core" / "config.py").resolve()
    parts = []
    for name in PRODUCTION_DIRS:
        directory = BACKEND / name
        if directory.is_dir():
            parts.extend(
                p.read_text(encoding="utf-8")
                for p in directory.rglob("*.py")
                if p.resolve() != config
            )
    return "\n".join(parts)


SOURCES = _production_sources()


@pytest.mark.parametrize("field", sorted(Settings.model_fields))
def test_every_setting_is_read_by_production_code_or_explicitly_reserved(field: str) -> None:
    used = re.search(rf"\b{re.escape(field)}\b", SOURCES) is not None
    if field in RESERVED:
        assert not used, f"{field} is now read by code; remove it from RESERVED"
    else:
        assert used, (
            f"{field} is not read by any production code (wire it up, reserve it, or delete it)"
        )


def test_reserved_entries_are_real_settings() -> None:
    assert set(RESERVED) <= set(Settings.model_fields)


@pytest.mark.parametrize("field", REMOVED)
def test_superseded_settings_stay_removed(field: str) -> None:
    assert field not in Settings.model_fields


def test_env_example_documents_no_removed_setting() -> None:
    text = (BACKEND.parent / ".env.example").read_text(encoding="utf-8")
    keys = {
        line.split("=", 1)[0].strip()
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    assert not keys & {name.upper() for name in REMOVED}


def test_env_example_keys_are_all_real_settings() -> None:
    text = (BACKEND.parent / ".env.example").read_text(encoding="utf-8")
    keys = {
        line.split("=", 1)[0].strip().lower()
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    unknown = keys - set(Settings.model_fields)
    assert not unknown, f".env.example documents settings that do not exist: {sorted(unknown)}"
