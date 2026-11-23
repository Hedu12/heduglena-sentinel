"""
AS-02 drift detection: the steering requirement and the implementation must agree.

AS-02 in .kiro/steering/ai-safety-requirements.md is the single authoritative
definition of the AI explanation context. Its machine-readable blocks
(as02-allowed, as02-limits, as02-forbidden) are compared with the IncidentContext
schema and the configuration bounds. Changing either side alone fails here.
"""

from __future__ import annotations

import re
import types
import typing
from pathlib import Path

import pytest
from pydantic import BaseModel

from ai import context as ctx
from core.config import Settings

ROOT = Path(__file__).resolve().parents[3]
STEERING = (ROOT / ".kiro" / "steering" / "ai-safety-requirements.md").read_text(encoding="utf-8")
SPEC = (ROOT / ".kiro" / "specs" / "sentinel-spec.md").read_text(encoding="utf-8")


def _block(name: str) -> list[str]:
    match = re.search(rf"```{name}\n(.*?)```", STEERING, re.DOTALL)
    assert match, f"AS-02 has no {name} block"
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def _model_in(annotation: object) -> tuple[type[BaseModel] | None, bool]:
    """The pydantic model inside an annotation, and whether it is a list of them."""
    origin = typing.get_origin(annotation)
    if origin is list:
        (inner,) = typing.get_args(annotation)
        model, _ = _model_in(inner)
        return model, True
    if origin in (typing.Union, types.UnionType):
        for arg in typing.get_args(annotation):
            model, is_list = _model_in(arg)
            if model is not None:
                return model, is_list
        return None, False
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation, False
    return None, False


def _paths(model: type[BaseModel], prefix: str = "") -> set[str]:
    out: set[str] = set()
    for name, field in model.model_fields.items():
        nested, is_list = _model_in(field.annotation)
        path = f"{prefix}{name}"
        if nested is not None:
            out |= _paths(nested, f"{path}[]." if is_list else f"{path}.")
        else:
            out.add(path)
    return out


IMPLEMENTED = _paths(ctx.IncidentContext)
ALLOWED = set(_block("as02-allowed"))
LIMITS = {k.strip(): v.strip() for k, v in (line.split(":") for line in _block("as02-limits"))}
FORBIDDEN = set(_block("as02-forbidden"))


def test_the_implemented_context_is_exactly_the_allowed_list() -> None:
    assert sorted(IMPLEMENTED - ALLOWED) == [], "fields implemented but not allowed by AS-02"
    assert sorted(ALLOWED - IMPLEMENTED) == [], "fields allowed by AS-02 but not implemented"


def test_no_forbidden_name_is_a_context_field() -> None:
    leaf_names = {p.rsplit(".", 1)[-1] for p in IMPLEMENTED}
    assert not leaf_names & FORBIDDEN


@pytest.mark.parametrize(
    ("limit", "schema_value"),
    [
        ("evidence", ctx.MAX_EVIDENCE),
        ("transitions", ctx.MAX_TRANSITIONS),
        ("responses", ctx.MAX_RESPONSES),
        ("reasons", ctx.MAX_REASONS),
        ("active_categories", ctx.MAX_CATEGORIES),
        ("label_chars", ctx.LABEL_MAX),
        ("sentence_chars", ctx.SENTENCE_MAX),
    ],
)
def test_the_hard_caps_match(limit: str, schema_value: int) -> None:
    assert int(LIMITS[limit]) == schema_value


def _max_length(model: type[BaseModel], field: str) -> int:
    for meta in model.model_fields[field].metadata:
        if hasattr(meta, "max_length") and meta.max_length is not None:
            return int(meta.max_length)
    raise AssertionError(f"{model.__name__}.{field} has no max_length")


def test_the_schema_enforces_the_caps() -> None:
    assert _max_length(ctx.IncidentContext, "evidence") == int(LIMITS["evidence"])
    assert _max_length(ctx.IncidentContext, "transitions") == int(LIMITS["transitions"])
    assert _max_length(ctx.IncidentContext, "responses") == int(LIMITS["responses"])
    assert _max_length(ctx.IncidentContext, "reasons") == int(LIMITS["reasons"])


@pytest.mark.parametrize(
    ("setting", "limit"),
    [
        ("ai_max_context_events", "evidence"),
        ("ai_max_context_transitions", "transitions"),
        ("ai_max_context_actions", "responses"),
    ],
)
def test_configuration_can_narrow_but_never_widen_the_context(setting: str, limit: str) -> None:
    upper = next(
        m.le for m in Settings.model_fields[setting].metadata if getattr(m, "le", None) is not None
    )
    assert upper == int(LIMITS[limit])
    assert Settings.model_fields[setting].default <= upper


def test_the_spec_defers_to_as02_and_keeps_no_conflicting_definition() -> None:
    section = SPEC.split("### 10.5 Context Window", 1)[1].split("\n## ", 1)[0]
    assert "AS-02" in section
    assert "Up to 3 previously executed" not in SPEC
    for number, limit in (("8 state transitions", "transitions"), ("10 detection", "evidence")):
        assert number in section, number
        assert number.split()[0] == LIMITS[limit]
