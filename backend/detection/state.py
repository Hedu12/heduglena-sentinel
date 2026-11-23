"""
Bounded detection state.

Every structure here has a fixed upper bound on memory: deques use maxlen,
and the cooldown table is keyed by a small, rule-defined set of keys. No
rule keeps unbounded history.

All time comparisons use timestamps carried by the observed data, never the
wall clock, so detection is deterministic for a given input sequence.
"""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Violation:
    """One sample that breached a threshold."""

    value: float
    at: datetime
    sample_id: int | None


class ConsecutiveTracker:
    """
    Counts consecutive violating samples and remembers the most recent ones.

    Only the last `required` violations are retained, so memory is O(required).
    """

    def __init__(self, required: int) -> None:
        if required < 1:
            raise ValueError("required must be >= 1")
        self._required = required
        self._run = 0
        self._recent: deque[Violation] = deque(maxlen=required)

    @property
    def required(self) -> int:
        return self._required

    @property
    def run_length(self) -> int:
        return self._run

    @property
    def recent(self) -> tuple[Violation, ...]:
        return tuple(self._recent)

    @property
    def satisfied(self) -> bool:
        return self._run >= self._required

    def violate(self, value: float, at: datetime, sample_id: int | None) -> int:
        """Record a violating sample and return the new run length."""
        self._run += 1
        self._recent.append(Violation(value=value, at=at, sample_id=sample_id))
        return self._run

    def reset(self) -> None:
        """Break the run (recovery, or a missing/invalid sample)."""
        self._run = 0
        self._recent.clear()


class RollingBaseline:
    """Fixed-size window of recent values with a mean."""

    def __init__(self, maxlen: int) -> None:
        if maxlen < 1:
            raise ValueError("maxlen must be >= 1")
        self._values: deque[float] = deque(maxlen=maxlen)

    def __len__(self) -> int:
        return len(self._values)

    def add(self, value: float) -> None:
        self._values.append(value)

    def mean(self) -> float | None:
        if not self._values:
            return None
        return statistics.fmean(self._values)

    def clear(self) -> None:
        self._values.clear()


class Cooldown:
    """
    Per-key debounce with optional escalation.

    A key is ready when it has never fired, when `seconds` have elapsed since
    it last fired, or when the new event has a higher escalation `level` than
    the last one (so a worsening situation is never suppressed).

    `mark` remembers the previous entry so `release` can undo a mark when the
    event it guarded could not be persisted.
    """

    def __init__(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("seconds must be >= 0")
        self._seconds = seconds
        self._last: dict[str, tuple[datetime, int]] = {}
        self._previous: dict[str, tuple[datetime, int] | None] = {}

    def ready(self, key: str, now: datetime, level: int = 0) -> bool:
        entry = self._last.get(key)
        if entry is None:
            return True
        last_at, last_level = entry
        if level > last_level:
            return True
        elapsed = (now - last_at).total_seconds()
        # A negative elapsed time means timestamps went backwards; do not let
        # that block detection indefinitely.
        return elapsed < 0 or elapsed >= self._seconds

    def mark(self, key: str, now: datetime, level: int = 0) -> None:
        self._previous[key] = self._last.get(key)
        self._last[key] = (now, level)

    def release(self, key: str) -> None:
        """Undo the most recent mark for key."""
        if key not in self._previous:
            return
        previous = self._previous.pop(key)
        if previous is None:
            self._last.pop(key, None)
        else:
            self._last[key] = previous

    def clear(self) -> None:
        self._last.clear()
        self._previous.clear()
