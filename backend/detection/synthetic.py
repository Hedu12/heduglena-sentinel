"""
Synthetic security events.

Synthetic events let the demo produce deterministic security scenarios
(repeated authentication failures, a connection burst, a simulated malicious
process) without touching the host or attacking anything. They enter the
detection engine through the same rule pipeline as telemetry (P-10).

Every free-text field is untrusted: it is stripped of control characters,
length-limited, and only ever stored as a JSON string value. It is never
used to build commands, queries, or prompts by string interpolation.
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from models.enums import SyntheticEventType

# Security-type synthetic events the detection engine can evaluate. The other
# SyntheticEventType members (cpu_spike, ...) describe synthetic *telemetry*,
# which is injected at the telemetry layer, not here.
SECURITY_SYNTHETIC_TYPES: frozenset[SyntheticEventType] = frozenset(
    {
        SyntheticEventType.AUTH_FAILURE,
        SyntheticEventType.ACCESS_DENIED,
        SyntheticEventType.CONNECTION_BURST,
        SyntheticEventType.SUSPICIOUS_PROCESS,
    }
)

MAX_RAW_LABEL_LENGTH = 256
MAX_LABEL_LENGTH = 64

_RawLabel = Annotated[str, StringConstraints(max_length=MAX_RAW_LABEL_LENGTH)]


def sanitize_label(raw: str) -> str | None:
    """
    Reduce untrusted text to a short, printable label.

    Removes control, format and line/paragraph-separator characters, collapses
    whitespace, and truncates to MAX_LABEL_LENGTH. Returns None when nothing
    printable remains.
    """
    kept = []
    for char in raw:
        category = unicodedata.category(char)
        if category in {"Zl", "Zp"} or category.startswith("C"):
            kept.append(" ")  # treat as whitespace so words do not fuse
        else:
            kept.append(char)
    label = " ".join("".join(kept).split())[:MAX_LABEL_LENGTH].rstrip()
    return label or None


class SyntheticEvent(BaseModel):
    """One injected, clearly-synthetic security event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_type: SyntheticEventType
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Untrusted descriptive labels (user name, process name, scenario name).
    subject: _RawLabel | None = None
    source: _RawLabel = "demo"
    scenario_id: _RawLabel | None = None

    @field_validator("event_type")
    @classmethod
    def _security_type_only(cls, value: SyntheticEventType) -> SyntheticEventType:
        if value not in SECURITY_SYNTHETIC_TYPES:
            allowed = sorted(t.value for t in SECURITY_SYNTHETIC_TYPES)
            raise ValueError(f"event_type must be one of {allowed}")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("subject", "source", "scenario_id")
    @classmethod
    def _sanitize(cls, value: str | None) -> str | None:
        return None if value is None else sanitize_label(value)
