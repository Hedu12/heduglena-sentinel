"""Unit tests for SituationTracker: one situation, one incident recommendation."""

from __future__ import annotations

import pytest

from models.enums import DefenseState
from tests.threat_helpers import at
from threat.situation import ENDED_QUIET, ENDED_SUPERSEDED, EndedSituation, SituationTracker

R, A, D, G = (
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
)


def tracker(reopen: float = 300.0) -> SituationTracker:
    return SituationTracker(reopen)


class TestOpening:
    def test_starts_with_no_situation(self) -> None:
        assert tracker().active_id is None

    def test_leaving_relaxed_opens_a_situation_identified_by_its_transition(self) -> None:
        t = tracker()
        update = t.apply(transition_id=7, previous=R, new=A, at=at(0))
        assert update.opened is True
        assert update.situation_id == 7
        assert t.active_id == 7

    def test_leaving_relaxed_straight_to_a_higher_state_also_opens_one(self) -> None:
        t = tracker()
        assert t.apply(transition_id=3, previous=R, new=D, at=at(0)).opened is True


class TestOneSituationManyTransitions:
    def test_escalating_inside_a_situation_does_not_open_another(self) -> None:
        t = tracker()
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        for tid, (prev, new) in enumerate([(A, D), (D, G)], start=2):
            update = t.apply(transition_id=tid, previous=prev, new=new, at=at(tid))
            assert update.opened is False
            assert update.situation_id == 1

    def test_de_escalating_inside_a_situation_does_not_open_another(self) -> None:
        t = tracker()
        t.apply(transition_id=1, previous=R, new=G, at=at(0))
        update = t.apply(transition_id=2, previous=G, new=D, at=at(40))
        assert (update.opened, update.closed, update.situation_id) == (False, False, 1)

    def test_returning_to_relaxed_closes_it(self) -> None:
        t = tracker()
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        update = t.apply(transition_id=2, previous=A, new=R, at=at(60))
        assert update.closed is True
        assert update.situation_id is None
        assert t.active_id is None


class TestReopening:
    def test_a_quick_re_escalation_continues_the_same_situation(self) -> None:
        t = tracker(reopen=300)
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        t.apply(transition_id=2, previous=A, new=R, at=at(60))
        update = t.apply(transition_id=3, previous=R, new=A, at=at(120))  # 60 s later
        assert update.opened is False
        assert update.reopened is True
        assert update.situation_id == 1
        assert t.active_id == 1

    def test_a_re_escalation_after_the_window_is_a_new_situation(self) -> None:
        t = tracker(reopen=300)
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        t.apply(transition_id=2, previous=A, new=R, at=at(60))
        update = t.apply(transition_id=3, previous=R, new=A, at=at(60 + 300))
        assert update.opened is True
        assert update.situation_id == 3

    def test_a_noisy_boundary_does_not_produce_repeated_incidents(self) -> None:
        t = tracker(reopen=300)
        opened = 0
        tid = 0
        for cycle in range(20):  # flap RELAXED <-> ALERT every 40 s
            tid += 1
            opened += t.apply(transition_id=tid, previous=R, new=A, at=at(cycle * 80)).opened
            tid += 1
            t.apply(transition_id=tid, previous=A, new=R, at=at(cycle * 80 + 40))
        assert opened == 1

    def test_zero_window_never_merges(self) -> None:
        t = tracker(reopen=0)
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        t.apply(transition_id=2, previous=A, new=R, at=at(1))
        assert t.apply(transition_id=3, previous=R, new=A, at=at(1)).opened is True

    def test_time_going_backwards_errs_towards_not_duplicating(self) -> None:
        t = tracker(reopen=300)
        t.apply(transition_id=1, previous=R, new=A, at=at(1000))
        t.apply(transition_id=2, previous=A, new=R, at=at(1010))
        assert t.apply(transition_id=3, previous=R, new=A, at=at(5)).opened is False


class TestEnded:
    """A situation is over for good once it can no longer resume."""

    def _closed_at_60(self, reopen: float = 300) -> SituationTracker:
        t = tracker(reopen)
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        t.apply(transition_id=2, previous=A, new=R, at=at(60))
        return t

    def test_nothing_has_ended_before_any_situation(self) -> None:
        assert tracker().ended(at(10_000)) is None

    def test_an_active_situation_has_not_ended(self) -> None:
        t = tracker()
        t.apply(transition_id=1, previous=R, new=G, at=at(0))
        assert t.ended(at(10_000)) is None

    def test_a_recovered_situation_has_not_ended_inside_the_reopen_window(self) -> None:
        t = self._closed_at_60()
        assert t.ended(at(60)) is None
        assert t.ended(at(60 + 299)) is None

    def test_it_ends_exactly_when_it_can_no_longer_resume(self) -> None:
        t = self._closed_at_60()
        ended = t.ended(at(60 + 300))
        assert ended == EndedSituation(1, at(60), ENDED_QUIET)
        # The same boundary the tracker uses for reopening: now a new situation.
        assert t.apply(transition_id=3, previous=R, new=A, at=at(360)).opened is True

    def test_the_ended_situation_is_reported_repeatedly(self) -> None:
        t = self._closed_at_60()
        assert t.ended(at(400)) == t.ended(at(5_000)) is not None

    def test_a_resumed_situation_is_not_ended(self) -> None:
        t = self._closed_at_60()
        t.apply(transition_id=3, previous=R, new=A, at=at(120))
        assert t.ended(at(10_000)) is None

    def test_a_new_situation_ends_the_previous_one_even_without_a_quiet_evaluation(
        self,
    ) -> None:
        t = self._closed_at_60()
        t.apply(transition_id=5, previous=R, new=A, at=at(500))
        assert t.ended(at(500)) == EndedSituation(1, at(60), ENDED_SUPERSEDED)
        t.apply(transition_id=6, previous=A, new=R, at=at(560))
        assert t.ended(at(600)) == EndedSituation(1, at(60), ENDED_SUPERSEDED)
        assert t.ended(at(860)) == EndedSituation(5, at(560), ENDED_QUIET)

    def test_time_going_backwards_does_not_end_a_situation(self) -> None:
        t = self._closed_at_60()
        assert t.ended(at(0)) is None

    def test_reset_forgets_ended_situations(self) -> None:
        t = self._closed_at_60()
        t.apply(transition_id=5, previous=R, new=A, at=at(500))
        t.reset()
        assert t.ended(at(10_000)) is None


class TestAdoptAndReset:
    def test_adopt_resumes_a_known_situation(self) -> None:
        t = tracker()
        t.adopt(42)
        assert t.active_id == 42
        assert t.apply(transition_id=43, previous=A, new=D, at=at(0)).opened is False

    def test_reset_forgets_everything(self) -> None:
        t = tracker()
        t.apply(transition_id=1, previous=R, new=A, at=at(0))
        t.reset()
        assert t.active_id is None
        assert t.apply(transition_id=9, previous=R, new=A, at=at(1)).situation_id == 9

    def test_negative_reopen_window_rejected(self) -> None:
        with pytest.raises(ValueError):
            SituationTracker(-1)
