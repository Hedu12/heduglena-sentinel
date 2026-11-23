"""
The AI output contract and its validation pipeline.

A provider's answer becomes a displayable explanation only if it passes every
step, in order. Any failure rejects the whole answer; nothing is repaired:

  1. size      raw text no longer than the configured cap;
  2. JSON      exactly one JSON object, nothing around it (no fences, no prose);
  3. schema    ExplanationOutput: exactly the expected keys (extra="forbid"),
               strict types, bounded lengths, a fixed confidence vocabulary;
  4. policy    ai.policy: explanation only, no directives (commands, tool calls,
               state changes, authorisations, URLs, hidden characters);
  5. validator AIOutputValidator (ai.validator.validate) over every text field.
               It redacts; here any redaction rejects the answer instead of
               storing a redacted version.

AIOutputValidator stays the final safety boundary and is called unmodified.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from ai import validator
from ai.policy import first_violation
from models.enums import ExplanationConfidence, ExplanationFailure

_Short = Annotated[str, StringConstraints(min_length=1, max_length=400)]
_Long = Annotated[str, StringConstraints(min_length=1, max_length=1200)]
_Item = Annotated[str, StringConstraints(min_length=1, max_length=300)]


class ExplanationOutput(BaseModel):
    """The only shape of AI output Sentinel accepts. Display text only."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    summary: _Short
    what_happened: _Long
    why_it_matters: _Long
    evidence: list[_Item] = Field(min_length=1, max_length=8)
    current_state: _Short
    recommended_human_attention: _Long
    confidence: ExplanationConfidence

    def texts(self) -> Iterator[tuple[str, str]]:
        """Every text field as (name, value)."""
        yield "summary", self.summary
        yield "what_happened", self.what_happened
        yield "why_it_matters", self.why_it_matters
        for i, item in enumerate(self.evidence):
            yield f"evidence[{i}]", item
        yield "current_state", self.current_state
        yield "recommended_human_attention", self.recommended_human_attention


@dataclass(frozen=True, slots=True)
class OutputCheck:
    """Result of validating one raw answer."""

    output: ExplanationOutput | None
    failure: ExplanationFailure | None = None
    # Which step or rule rejected it (a fixed code, never model text).
    detail: str | None = None

    @property
    def valid(self) -> bool:
        return self.output is not None


def _reject(failure: ExplanationFailure, detail: str) -> OutputCheck:
    return OutputCheck(None, failure, detail)


def check_output(
    raw: str, *, max_raw_chars: int, max_field_chars: int, incident_id: str
) -> OutputCheck:
    """Validate a provider answer. Never raises."""
    if not raw.strip():
        return _reject(ExplanationFailure.EMPTY_RESPONSE, "empty")
    if len(raw) > max_raw_chars:
        return _reject(ExplanationFailure.OVERSIZED_OUTPUT, "raw_length")

    try:
        parsed = json.loads(raw)
    except (ValueError, RecursionError):
        return _reject(ExplanationFailure.MALFORMED_JSON, "not_json")
    if not isinstance(parsed, dict):
        return _reject(ExplanationFailure.MALFORMED_JSON, "not_an_object")

    try:
        # JSON-mode strict validation: no type coercion, enums only from their exact strings.
        output = ExplanationOutput.model_validate_json(raw, strict=True)
    except ValidationError as exc:
        first = exc.errors()[0]
        return _reject(ExplanationFailure.SCHEMA_VIOLATION, str(first.get("type", "invalid")))

    for name, text in output.texts():
        rule = first_violation(text)
        if rule is not None:
            return _reject(ExplanationFailure.UNSAFE_CONTENT, f"{name}:{rule}")

    for name, text in output.texts():
        if validator.validate(text, max_field_chars, incident_id) != text:
            return _reject(ExplanationFailure.VALIDATOR_REDACTED, name)

    return OutputCheck(output)
