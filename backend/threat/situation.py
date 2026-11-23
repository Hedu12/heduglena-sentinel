"""
SituationTracker: one security situation, however many evaluations it spans.

A *situation* begins when the defense state leaves RELAXED and ends when it
returns to RELAXED. Escalating or de-escalating inside it (ALERT to DEFENSIVE
and so on) does not start a new one, and neither does a fresh escalation soon
after it ended (`reopen_seconds`), which would otherwise turn a noisy boundary
into a stream of duplicate incidents.

This is what keeps `RECORD_INCIDENT` from firing repeatedly: the decision layer
recommends it only at the instant a *new* situation opens. Every decision also
carries the situation's id, so a response layer can ensure exactly one incident
per id even if a recommendation is lost.

The id is the database id of the transition that opened the situation, so it
needs no storage of its own and is recovered by replaying the persisted
transitions after a restart.

A situation is *ended* (over for good, so its incident can be resolved) once it
can no longer resume: it has been RELAXED for at least `reopen_seconds`, or a
new situation has replaced it. `ended(now)` reports the most recent ended
situation on every call, so a consumer that misses one report sees it again.

State is a few scalars. Time comes from the transitions and the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models.enums import DefenseState


@dataclass(frozen=True, slots=True)
class SituationUpdate:
    """What a state transition did to the current situation."""

    situation_id: int | None  # the active situation after the update, if any
    opened: bool = False  # a NEW situation began: the one moment to record an incident
    reopened: bool = False  # a recent situation resumed: no new incident
    closed: bool = False


@dataclass(frozen=True, slots=True)
class EndedSituation:
    """A situation that can no longer resume."""

    situation_id: int
    recovered_at: datetime  # when the defense state returned to RELAXED
    # What made it final: the reopen window passed, or a new situation began.
    reason: str


ENDED_QUIET = "QUIET_FOR_REOPEN_WINDOW"
ENDED_SUPERSEDED = "SUPERSEDED_BY_NEW_SITUATION"


class SituationTracker:
    def __init__(self, reopen_seconds: float) -> None:
        if reopen_seconds < 0:
            raise ValueError("reopen_seconds must be >= 0")
        self._reopen_seconds = reopen_seconds
        self._id: int | None = None
        self._active = False
        self._closed_at: datetime | None = None
        # The situation a new one replaced; it is over even if the window had not passed.
        self._superseded: EndedSituation | None = None

    @property
    def active_id(self) -> int | None:
        """Id of the situation in progress, or None while RELAXED."""
        return self._id if self._active else None

    def apply(
        self,
        *,
        transition_id: int,
        previous: DefenseState,
        new: DefenseState,
        at: datetime,
    ) -> SituationUpdate:
        """Fold one persisted state transition into the situation."""
        leaving_relaxed = previous is DefenseState.RELAXED and new is not DefenseState.RELAXED
        entering_relaxed = new is DefenseState.RELAXED and previous is not DefenseState.RELAXED

        if leaving_relaxed:
            if self._resumes_recent_situation(at):
                self._active = True
                self._closed_at = None
                return SituationUpdate(self._id, reopened=True)
            if self._id is not None and self._closed_at is not None:
                self._superseded = EndedSituation(self._id, self._closed_at, ENDED_SUPERSEDED)
            self._id = transition_id
            self._active = True
            self._closed_at = None
            return SituationUpdate(self._id, opened=True)

        if entering_relaxed:
            self._active = False
            self._closed_at = at
            return SituationUpdate(None, closed=True)

        return SituationUpdate(self.active_id)

    def adopt(self, situation_id: int) -> None:
        """
        Resume a situation whose opening transition is outside the replayed history.

        Used only when a restart finds the state already raised but the opening
        transition is older than the history window. The id stays stable.
        """
        self._id = situation_id
        self._active = True
        self._closed_at = None

    def ended(self, now: datetime) -> EndedSituation | None:
        """
        The most recent situation that is over for good, if any.

        The current situation counts once it has been RELAXED for the whole reopen
        window (the same boundary at which a new escalation stops resuming it).
        Otherwise the situation that the current one replaced, if any.
        """
        if (
            not self._active
            and self._id is not None
            and self._closed_at is not None
            and not self._resumes_recent_situation(now)
        ):
            return EndedSituation(self._id, self._closed_at, ENDED_QUIET)
        return self._superseded

    def reset(self) -> None:
        self._id = None
        self._active = False
        self._closed_at = None
        self._superseded = None

    def _resumes_recent_situation(self, at: datetime) -> bool:
        if self._id is None or self._closed_at is None:
            return False
        # Negative elapsed (time went backwards) counts as "recent": err on the side
        # of not duplicating an incident.
        return (at - self._closed_at).total_seconds() < self._reopen_seconds
