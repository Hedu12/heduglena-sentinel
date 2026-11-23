"""The benchmark: deterministic, production-shaped, and internally consistent."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai.context import IncidentContext
from evaluation import text
from evaluation.case import ExpectedFacts, ExplanationEvalCase, check_consistency
from evaluation.dataset import CATEGORY, build_benchmark
from models.enums import ActionType, DefenseState
from threat import evidence

CASES = build_benchmark()

REQUIRED_CATEGORIES = {
    "normal",
    "single_anomaly",
    "multiple_signals",
    "critical",
    "guard",
    "recovery",
    "adversarial",
}


def test_the_benchmark_is_deterministic() -> None:
    assert [c.model_dump_json() for c in build_benchmark()] == [c.model_dump_json() for c in CASES]


def test_case_ids_are_unique() -> None:
    ids = [c.case_id for c in CASES]
    assert len(ids) == len(set(ids))


def test_every_required_scenario_is_covered() -> None:
    assert {c.category for c in CASES} >= REQUIRED_CATEGORIES
    ids = {c.case_id for c in CASES}
    assert {"normal-relaxed", "single-cpu", "single-memory", "single-network"} <= ids
    assert {"multi-cpu-network", "multi-auth-network", "multi-process-auth"} <= ids


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.case_id)
def test_expected_facts_agree_with_the_context(case: ExplanationEvalCase) -> None:
    assert check_consistency(case) == []


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.case_id)
def test_each_case_uses_the_production_context_schema(case: ExplanationEvalCase) -> None:
    # A round trip through the production model proves AS-02 applies to every case.
    assert IncidentContext.model_validate_json(case.context.model_dump_json()) == case.context
    assert all(r.simulated is True for r in case.context.responses)


def test_the_states_span_the_whole_machine() -> None:
    assert {c.expected.current_state for c in CASES} == set(DefenseState)


def test_an_inconsistent_case_is_detected() -> None:
    case = CASES[0]
    wrong = case.model_copy(
        update={
            "expected": ExpectedFacts(
                current_state=DefenseState.AGGRESSIVE,
                threat_score_min=0.8,
                threat_score_max=0.9,
                required_evidence=("suspicious_process",),
                required_transitions=("DEFENSIVE>AGGRESSIVE",),
                simulated_actions=(ActionType.SIMULATE_QUARANTINE,),
                denied_actions=(ActionType.SIMULATE_IP_BLOCK,),
                required_reasons=("CRITICAL_EVENT",),
            )
        }
    )
    # state, score, evidence, transition, simulated action, denied action, reason
    assert len(check_consistency(wrong)) == 7


def test_expected_facts_are_validated() -> None:
    with pytest.raises(ValidationError):
        ExpectedFacts(current_state=DefenseState.ALERT, threat_score_min=0.9, threat_score_max=0.1)
    with pytest.raises(ValidationError):
        ExpectedFacts(
            current_state=DefenseState.ALERT,
            threat_score_min=0.1,
            threat_score_max=0.2,
            required_transitions=("RELAXED to ALERT",),
        )


def test_the_event_vocabulary_matches_sentinel() -> None:
    known = set(evidence._CATEGORY_BY_EVENT_TYPE)  # noqa: SLF001 - vocabulary check
    assert set(text.KNOWN_EVENT_TYPES) == known
    assert set(CATEGORY) == known
    assert set(text.EVENT_BROAD) == set(text.EVENT_STRICT) == known
    assert {k: v.value for k, v in evidence._CATEGORY_BY_EVENT_TYPE.items()} == CATEGORY  # noqa: SLF001
