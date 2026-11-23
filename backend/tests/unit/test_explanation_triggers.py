"""
Explanation frequency: meaningful triggers only, deterministic, bounded.

The policy is pure; its memory comes from persisted records. `Store` stands in
for ai_explanations: it remembers exactly what a recorded explanation stores
(trigger key, decision time, evidence mark), nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

import pytest

from explanation.triggers import (
    CREATED_KEY,
    MAX_PENDING_TRANSITIONS,
    EvidenceMark,
    ExplanationTriggerPolicy,
    PendingExplanation,
    TriggerMemory,
    transition_key,
)
from models.enums import DefenseState, ExplanationTrigger, Severity
from tests.response_helpers import A, D, G, R, decision
from tests.threat_helpers import at
from threat.decision import Decision
from threat.evidence import SignalCategory

T = ExplanationTrigger


def policy(refresh: float = 30.0, delta: float = 0.15) -> ExplanationTriggerPolicy:
    return ExplanationTriggerPolicy(aggressive_refresh_seconds=refresh, evidence_score_delta=delta)


def d(
    t: float,
    state: DefenseState,
    *,
    situation: int | None = 1,
    previous: DefenseState | None = None,
    new: bool = False,
    transition: int | None = None,
    score: float = 0.6,
    categories: tuple[SignalCategory, ...] = (SignalCategory.EXECUTION,),
    severity: Severity | None = Severity.CRITICAL,
) -> Decision:
    base = decision(
        t, state, situation_id=situation, previous=previous, new_situation=new, score=score
    )
    breakdown = replace(
        base.breakdown,
        active_categories=categories,
        active_max_severity=severity,
        signal_count=len(categories),
    )
    return replace(base, breakdown=breakdown, transition_id=transition)


@dataclass
class Store:
    """The persisted explanation records of one situation."""

    keys: set[str] = field(default_factory=set)
    marks: list[EvidenceMark] = field(default_factory=list)

    def memory(self, pending: PendingExplanation) -> TriggerMemory:
        recorded = self.keys & set(pending.keys())
        last = max(self.marks, key=lambda m: m.decision_at) if self.marks else None
        # Exactly what the service rebuilds from a stored row.
        if last is not None:
            last = EvidenceMark.from_record(last.decision_at, last.to_json())
        return TriggerMemory(
            created=CREATED_KEY in recorded, explained=frozenset(recorded), last=last
        )


def run(
    p: ExplanationTriggerPolicy, decisions: list[Decision], store: Store | None = None
) -> list[T | None]:
    store = store if store is not None else Store()
    out: list[T | None] = []
    for item in decisions:
        pending = PendingExplanation.start(item.situation_id or 1, item)
        request = p.decide(pending.situation_id or 1, pending, store.memory(pending))
        if request is not None:
            assert request.trigger_key not in store.keys, "a trigger key is recorded only once"
            store.keys.add(request.trigger_key)
            store.marks.append(request.mark)
        out.append(request.trigger if request else None)
    return out


class TestIncidentCreation:
    def test_a_new_incident_is_explained_once(self) -> None:
        opening = d(0, A, previous=R, new=True, transition=1)
        assert run(policy(), [opening, opening, opening]) == [T.INCIDENT_CREATED, None, None]

    def test_a_decision_without_evidence_or_change_triggers_nothing(self) -> None:
        quiet = d(0, A, categories=(), severity=None)
        assert run(policy(), [quiet]) == [None]


class TestTransitions:
    def test_each_meaningful_transition_is_explained_once(self) -> None:
        path = [
            d(0, A, previous=R, new=True, transition=1),
            d(5, D, previous=A, transition=2),
            d(5, D, previous=A, transition=2),  # redelivered
            d(20, G, previous=D, transition=3),
            d(60, D, previous=G, transition=4),
            d(110, A, previous=D, transition=5),
            d(150, R, previous=A, transition=6, situation=None),  # recovery
        ]
        assert run(policy(), path) == [
            T.INCIDENT_CREATED,
            T.STATE_TRANSITION,
            None,
            T.STATE_TRANSITION,
            T.STATE_TRANSITION,
            T.STATE_TRANSITION,
            T.STATE_TRANSITION,
        ]

    def test_transition_keys_use_the_persisted_transition_id(self) -> None:
        assert transition_key(d(5, D, previous=A, transition=42)) == "STATE_TRANSITION:42"
        unpersisted = transition_key(d(5, D, previous=A))
        assert unpersisted.startswith("STATE_TRANSITION:") and "ALERT>DEFENSIVE" in unpersisted


class TestNewEvidence:
    def test_duplicate_evidence_is_not_explained_again(self) -> None:
        store = Store()
        run(policy(), [d(0, D, previous=A, new=True, transition=1)], store)
        assert run(policy(), [d(t, D) for t in (5, 10, 15)], store) == [None, None, None]

    def test_a_new_signal_category_is_significant(self) -> None:
        store = Store()
        run(policy(), [d(0, D, previous=A, new=True, transition=1)], store)
        wider = (SignalCategory.EXECUTION, SignalCategory.NETWORK)
        assert run(policy(), [d(5, D, categories=wider), d(6, D, categories=wider)], store) == [
            T.NEW_EVIDENCE,
            None,
        ]

    def test_a_higher_severity_is_significant(self) -> None:
        store = Store()
        run(policy(), [d(0, A, previous=R, new=True, transition=1, severity=Severity.HIGH)], store)
        assert run(policy(), [d(5, A, severity=Severity.CRITICAL)], store) == [T.NEW_EVIDENCE]

    def test_a_large_score_rise_is_significant_a_small_one_is_not(self) -> None:
        store = Store()
        run(policy(delta=0.15), [d(0, A, previous=R, new=True, transition=1, score=0.40)], store)
        assert run(policy(delta=0.15), [d(5, A, score=0.50), d(10, A, score=0.56)], store) == [
            None,
            T.NEW_EVIDENCE,
        ]

    def test_decay_is_not_new_evidence(self) -> None:
        store = Store()
        run(policy(), [d(0, D, previous=A, new=True, transition=1, score=0.8)], store)
        assert (
            run(policy(), [d(t, D, score=0.8 - t / 100) for t in (10, 20, 30)], store) == [None] * 3
        )


class TestAggressiveRefresh:
    def test_refreshes_obey_the_interval(self) -> None:
        store = Store()
        run(policy(refresh=30), [d(0, G, previous=D, new=True, transition=1)], store)
        times = list(range(5, 125, 5))
        result = run(policy(refresh=30), [d(t, G) for t in times], store)
        fired = [t for t, trig in zip(times, result, strict=True) if trig is T.AGGRESSIVE_REFRESH]
        assert fired == [30, 60, 90, 120]

    def test_no_refresh_outside_aggressive(self) -> None:
        store = Store()
        run(policy(refresh=30), [d(0, D, previous=A, new=True, transition=1)], store)
        assert set(run(policy(refresh=30), [d(t, D) for t in range(5, 200, 5)], store)) == {None}

    def test_a_stale_decision_triggers_nothing(self) -> None:
        store = Store()
        run(policy(refresh=30), [d(100, G, previous=D, new=True, transition=1)], store)
        assert run(policy(refresh=30), [d(40, G), d(100, G)], store) == [None, None]

    @pytest.mark.parametrize(("refresh", "delta"), [(0, 0.1), (30, 0)])
    def test_invalid_parameters_are_refused(self, refresh: float, delta: float) -> None:
        with pytest.raises(ValueError):
            policy(refresh, delta)


class TestPersistedMemory:
    def test_the_decision_depends_only_on_the_persisted_records(self) -> None:
        # A fresh policy object over the same records decides exactly the same.
        decisions = [
            d(0, A, previous=R, new=True, transition=1),
            d(5, D, previous=A, transition=2),
            d(20, G, previous=D, transition=3),
            *[d(t, G) for t in range(25, 140, 5)],
            d(150, D, previous=G, transition=4),
        ]
        uninterrupted = run(policy(), decisions)
        for split in range(1, len(decisions)):
            store = Store()
            first = run(policy(), decisions[:split], store)
            second = run(policy(), decisions[split:], store)  # "restarted" policy, same records
            assert first + second == uninterrupted, split

    def test_evidence_marks_round_trip_through_storage(self) -> None:
        mark = EvidenceMark.of(d(5, G, categories=(SignalCategory.NETWORK, SignalCategory.CPU)))
        again = EvidenceMark.from_record(mark.decision_at, mark.to_json())
        assert again == mark

    def test_unreadable_stored_evidence_counts_as_nothing_known(self) -> None:
        mark = EvidenceMark.from_record(datetime(2026, 1, 1), "{broken")
        assert (mark.categories, mark.severity_rank, mark.score) == (frozenset(), -1, 0.0)
        assert mark.decision_at.tzinfo is not None


class TestPendingCoalescing:
    def test_the_newest_decision_and_every_transition_are_kept(self) -> None:
        pending = PendingExplanation.start(1, d(0, A, previous=R, new=True, transition=1))
        pending.absorb(d(5, D, previous=A, transition=2))
        pending.absorb(d(3, A))  # older: does not replace the newest
        assert pending.opened and pending.decision.calculated_at == at(5)
        assert pending.transition_keys == ["STATE_TRANSITION:1", "STATE_TRANSITION:2"]
        assert pending.keys()[0] == CREATED_KEY

    def test_pending_transitions_are_bounded(self) -> None:
        pending = PendingExplanation.start(1, d(0, A, previous=R, transition=0))
        for i in range(1, 100):
            pending.absorb(d(i, D if i % 2 else A, previous=A if i % 2 else D, transition=i))
        assert len(pending.transition_keys) == MAX_PENDING_TRANSITIONS
