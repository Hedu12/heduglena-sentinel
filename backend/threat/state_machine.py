"""
DefenseStateMachine: RELAXED / ALERT / DEFENSIVE / AGGRESSIVE with hysteresis.

Escalation is fast, de-escalation is slow:

  Up    A state is entered when the score has stayed at or above its entry
        threshold for `dwell_seconds` (AC-F04-1). The dwell is skipped for a
        severe escalation: an active CRITICAL, high-confidence event, or a
        score `bypass_margin` above the entry threshold. The state climbs at
        most ONE level per evaluation, so every level appears in the audit
        trail. The bypass into AGGRESSIVE additionally requires corroboration
        (enough independent signal categories); without it AGGRESSIVE needs
        the full dwell, and the withheld bypass is reported.
  Floor Active CRITICAL / HIGH evidence keeps the state at least at the
        configured floor, immediately and regardless of score. A weaker event
        therefore can never pull the state below what a stronger active
        threat requires. A floor can never be AGGRESSIVE (see StateConfig).
  Down  A state is left only after the score has stayed below its *exit*
        threshold (entry minus the hysteresis margin) for `cooldown_seconds`,
        and only one level at a time (AC-F04-2). Each step needs a fresh
        cooldown. Scores between exit and entry hold the state (hysteresis).

The machine only decides. It performs no I/O, reads no clock (callers pass
`now`), and executes nothing. Memory is O(1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models.enums import DefenseState
from threat.config import STATE_ORDER, StateConfig, state_rank
from threat.reasons import ReasonCode

_UPWARD = STATE_ORDER[1:]


@dataclass(frozen=True, slots=True)
class StateEvaluation:
    """Result of one evaluation. `changed` is True only for a real transition."""

    previous_state: DefenseState
    new_state: DefenseState
    previous_score: float | None
    score: float
    evaluated_at: datetime
    reason_codes: tuple[ReasonCode, ...]

    @property
    def changed(self) -> bool:
        return self.previous_state != self.new_state

    @property
    def escalated(self) -> bool:
        return state_rank(self.new_state) > state_rank(self.previous_state)


@dataclass(frozen=True, slots=True)
class MachineSnapshot:
    """Immutable copy of the machine's internal state, for rollback."""

    state: DefenseState
    last_score: float | None
    last_transition_at: datetime | None
    below_since: datetime | None
    above_since: tuple[tuple[DefenseState, datetime | None], ...]


class DefenseStateMachine:
    """Deterministic four-state machine driven by a score, a floor, and a severity flag."""

    def __init__(
        self,
        config: StateConfig,
        initial: DefenseState = DefenseState.RELAXED,
        initial_at: datetime | None = None,
    ) -> None:
        self._cfg = config
        self._state = initial
        self._last_score: float | None = None
        self._last_transition_at: datetime | None = initial_at
        self._below_since: datetime | None = None
        self._above_since: dict[DefenseState, datetime | None] = dict.fromkeys(_UPWARD)

    @property
    def state(self) -> DefenseState:
        return self._state

    @property
    def last_transition_at(self) -> datetime | None:
        return self._last_transition_at

    def restore(self, state: DefenseState, at: datetime | None) -> None:
        """Resume from a persisted state (for example after a restart)."""
        self._state = state
        self._last_transition_at = at
        self._below_since = None
        self._above_since = dict.fromkeys(_UPWARD)
        self._last_score = None

    def snapshot(self) -> MachineSnapshot:
        return MachineSnapshot(
            state=self._state,
            last_score=self._last_score,
            last_transition_at=self._last_transition_at,
            below_since=self._below_since,
            above_since=tuple(self._above_since.items()),
        )

    def rollback(self, snapshot: MachineSnapshot) -> None:
        """Undo evaluations made since `snapshot` (used when a transition can't be saved)."""
        self._state = snapshot.state
        self._last_score = snapshot.last_score
        self._last_transition_at = snapshot.last_transition_at
        self._below_since = snapshot.below_since
        self._above_since = dict(snapshot.above_since)

    # ── Evaluation ─────────────────────────────────────────────────────────

    def evaluate(
        self,
        *,
        now: datetime,
        score: float,
        floor: DefenseState = DefenseState.RELAXED,
        severe: bool = False,
        corroborated: bool = False,
    ) -> StateEvaluation:
        """
        Decide the state at `now`.

        Args:
            score:        current threat score in [0, 1].
            floor:        lowest state allowed by active high-severity evidence.
            severe:       True when a severe, high-confidence event is active.
            corroborated: True when enough independent signal categories support
                          the evidence. Required to bypass the dwell into AGGRESSIVE;
                          defaults to False so the safe behaviour is the default.
        """
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        if not 0.0 <= score <= 1.0:
            raise ValueError("score must be within [0, 1]")

        previous = self._state
        previous_score = self._last_score
        self._track_dwell(now, score)

        new = previous
        reasons: list[ReasonCode] = []

        climb = self._climb(previous, now, score, severe, corroborated)
        if climb is not None:
            new, code = climb
            reasons.append(code)
        elif self._bypass_withheld(previous, now, score, severe, corroborated):
            reasons.append(ReasonCode.AGGRESSIVE_NEEDS_CORROBORATION)

        if state_rank(new) < state_rank(floor):
            new = floor
            reasons.append(ReasonCode.ACTIVE_THREAT_FLOOR)

        if new == previous:
            new, hold_reasons = self._maybe_descend(previous, now, score, floor)
            reasons.extend(hold_reasons)
            if new == previous and self._pending_dwell(previous, score):
                reasons.append(ReasonCode.DWELL_PENDING)

        if new != previous:
            descended = state_rank(new) < state_rank(previous)
            self._state = new
            self._last_transition_at = now
            # After stepping down, the next step needs a full cooldown measured from
            # this transition, but only if the score is already below the NEW state's
            # exit threshold. If it is inside the new state's hysteresis band, the
            # clock must wait until it actually falls below; otherwise the time spent
            # in the band would count toward leaving, and the band would not hold.
            below_new_exit = score < self._cfg.exit(new)
            self._below_since = now if descended and below_new_exit else None
        self._last_score = score
        return StateEvaluation(
            previous_state=previous,
            new_state=new,
            previous_score=previous_score,
            score=score,
            evaluated_at=now,
            reason_codes=tuple(reasons),
        )

    # ── Internals ──────────────────────────────────────────────────────────

    def _track_dwell(self, now: datetime, score: float) -> None:
        """Remember since when the score has continuously met each entry threshold."""
        for state in _UPWARD:
            if score >= self._cfg.entry(state):
                if self._above_since[state] is None:
                    self._above_since[state] = now
            else:
                self._above_since[state] = None

    def _next_state(self, current: DefenseState) -> DefenseState | None:
        rank = state_rank(current)
        return STATE_ORDER[rank + 1] if rank + 1 < len(STATE_ORDER) else None

    def _dwell_satisfied(self, state: DefenseState, now: datetime) -> bool:
        since = self._above_since[state]
        return since is not None and (now - since).total_seconds() >= self._cfg.dwell_seconds

    def _bypass_requested(self, state: DefenseState, score: float, severe: bool) -> bool:
        return severe or score >= self._cfg.entry(state) + self._cfg.bypass_margin

    def _climb(
        self,
        current: DefenseState,
        now: datetime,
        score: float,
        severe: bool,
        corroborated: bool,
    ) -> tuple[DefenseState, ReasonCode] | None:
        """
        The next state up, if the score has earned it. One level at most.

        The dwell always suffices. A bypass also suffices, except into
        AGGRESSIVE, where it additionally needs corroboration.
        """
        target = self._next_state(current)
        if target is None or score < self._cfg.entry(target):
            return None
        if self._dwell_satisfied(target, now):
            return target, ReasonCode.DWELL_SATISFIED
        if self._bypass_requested(target, score, severe):
            if target is DefenseState.AGGRESSIVE and not corroborated:
                return None
            return target, ReasonCode.SEVERE_ESCALATION_BYPASS
        return None

    def _bypass_withheld(
        self, current: DefenseState, now: datetime, score: float, severe: bool, corroborated: bool
    ) -> bool:
        """True if only the missing corroboration is stopping a bypass into AGGRESSIVE."""
        target = self._next_state(current)
        return (
            target is DefenseState.AGGRESSIVE
            and not corroborated
            and score >= self._cfg.entry(target)
            and not self._dwell_satisfied(target, now)
            and self._bypass_requested(target, score, severe)
        )

    def _pending_dwell(self, current: DefenseState, score: float) -> bool:
        return any(
            state_rank(state) > state_rank(current) and score >= self._cfg.entry(state)
            for state in _UPWARD
        )

    def _maybe_descend(
        self, current: DefenseState, now: datetime, score: float, floor: DefenseState
    ) -> tuple[DefenseState, list[ReasonCode]]:
        """Step down one level if the score has stayed below the exit threshold long enough."""
        if state_rank(current) <= state_rank(floor) or current is DefenseState.RELAXED:
            self._below_since = None
            return current, []
        if score >= self._cfg.exit(current):
            self._below_since = None
            if score < self._cfg.entry(current):
                return current, [ReasonCode.HYSTERESIS_HOLD]
            return current, []
        if self._below_since is None:
            self._below_since = now
        if (now - self._below_since).total_seconds() >= self._cfg.cooldown_seconds:
            lower = STATE_ORDER[state_rank(current) - 1]
            return lower, [ReasonCode.DE_ESCALATION_COOLDOWN_ELAPSED]
        return current, [ReasonCode.COOLDOWN_PENDING]
