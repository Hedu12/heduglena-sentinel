"""
Demo scenarios: deterministic synthetic security events, clearly marked as such.

Every scenario injects only allowlisted security synthetic event types through
SentinelRuntime.inject(), which feeds DetectionEngine.process_synthetic(), the
same intake as real detections (P-10). Nothing here touches the host, telemetry,
the database or any security decision directly. Each event carries
source="demo" and a scenario_id, and detections from it are stored with
is_synthetic=True.

One scenario runs at a time, as a tracked task that stop() cancels. Requests
are rate-limited (TM-02). Nothing here can reset the defense state: forcing it
to RELAXED would bypass the state machine and leave no transition in the audit
trail (AC-F04-3). The demo reset instead archives the whole session and starts
a new one from empty history (app/demo_reset.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from database.models import DetectionEvent
from detection.synthetic import SECURITY_SYNTHETIC_TYPES, SyntheticEvent
from models.enums import SyntheticEventType

logger = logging.getLogger(__name__)

DEMO_SOURCE = "demo"
MAX_INJECT_COUNT = 20


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    event_type: SyntheticEventType
    subject: str
    repeat: int = 1


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    description: str
    steps: tuple[ScenarioStep, ...]


_AUTH = SyntheticEventType.AUTH_FAILURE
SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario(
            "normal",
            "No synthetic events: Sentinel keeps monitoring real telemetry and stays RELAXED "
            "unless the host itself is under pressure.",
            (),
        ),
        Scenario(
            "suspicious",
            "A burst of failed logins: detection, a raised threat score and simulated "
            "responses. Suspicious normally reaches ALERT or DEFENSIVE. It may reach "
            "AGGRESSIVE when a real host signal corroborates the synthetic attack.",
            (ScenarioStep(_AUTH, "admin", 10),),
        ),
        Scenario(
            "critical",
            "Repeated failed logins corroborated by a simulated malicious process: escalation "
            "toward AGGRESSIVE, guarded simulated responses, an incident and an explanation.",
            (
                ScenarioStep(_AUTH, "admin", 10),
                ScenarioStep(SyntheticEventType.SUSPICIOUS_PROCESS, "simulated-malware"),
            ),
        ),
    )
}


class ScenarioBusyError(RuntimeError):
    """A scenario is already running."""


class UnknownScenarioError(KeyError):
    """No scenario has that name."""


@dataclass(frozen=True, slots=True)
class ScenarioRun:
    name: str
    status: str  # running | completed | failed | cancelled
    started_at: datetime
    finished_at: datetime | None
    events_injected: int
    detections: int


Inject = Callable[[Sequence[SyntheticEvent]], Awaitable[list[DetectionEvent]]]


class RateLimiter:
    """At most `limit` calls per rolling 60 seconds, measured on a monotonic clock."""

    def __init__(self, limit: int, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._limit = limit
        self._monotonic = monotonic
        self._calls: deque[float] = deque()

    def allow(self) -> bool:
        now = self._monotonic()
        while self._calls and now - self._calls[0] >= 60.0:
            self._calls.popleft()
        if len(self._calls) >= self._limit:
            return False
        self._calls.append(now)
        return True


class DemoController:
    def __init__(
        self,
        inject: Inject,
        *,
        step_interval: float,
        max_requests_per_minute: int,
        clock: Callable[[], datetime],
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._inject = inject
        self._interval = step_interval
        self.limiter = RateLimiter(max_requests_per_minute)
        self._clock = clock
        self._sleep = sleep
        self._task: asyncio.Task[None] | None = None
        self.last_run: ScenarioRun | None = None

    @property
    def running(self) -> str | None:
        if self._task is not None and not self._task.done() and self.last_run is not None:
            return self.last_run.name
        return None

    def event(self, event_type: SyntheticEventType, subject: str, scenario: str) -> SyntheticEvent:
        if event_type not in SECURITY_SYNTHETIC_TYPES:
            raise ValueError(f"{event_type.value} is not a security synthetic event type")
        return SyntheticEvent(
            event_type=event_type,
            occurred_at=self._clock(),
            subject=subject,
            source=DEMO_SOURCE,
            scenario_id=f"demo-{scenario}",
        )

    async def inject(self, event_type: SyntheticEventType, count: int) -> list[DetectionEvent]:
        """Inject `count` events of one type, back to back (manual demo injection)."""
        if not 1 <= count <= MAX_INJECT_COUNT:
            raise ValueError(f"count must be between 1 and {MAX_INJECT_COUNT}")
        events = [self.event(event_type, "demo-user", "manual") for _ in range(count)]
        return await self._inject(events)

    def start(self, name: str) -> Scenario:
        scenario = SCENARIOS.get(name)
        if scenario is None:
            raise UnknownScenarioError(name)
        if self.running is not None:
            raise ScenarioBusyError(self.running)
        self.last_run = ScenarioRun(name, "running", self._clock(), None, 0, 0)
        self._task = asyncio.create_task(self._play(scenario), name=f"sentinel-demo-{name}")
        return scenario

    async def wait(self) -> ScenarioRun | None:
        """Wait for the current scenario to finish (used by tests and shutdown)."""
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        return self.last_run

    async def stop(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
        await self.wait()
        self._task = None

    async def _play(self, scenario: Scenario) -> None:
        started = self._clock()
        injected = detections = 0
        status = "completed"
        logger.info("Demo: scenario %s started", scenario.name)
        try:
            for step in scenario.steps:
                for _ in range(step.repeat):
                    if injected:
                        await self._sleep(self._interval)
                    found = await self._inject(
                        [self.event(step.event_type, step.subject, scenario.name)]
                    )
                    injected += 1
                    detections += len(found)
        except asyncio.CancelledError:
            status = "cancelled"
            raise
        except Exception:
            status = "failed"
            logger.error("Demo: scenario %s failed", scenario.name, exc_info=True)
        finally:
            self.last_run = ScenarioRun(
                scenario.name, status, started, self._clock(), injected, detections
            )
            logger.info("Demo: scenario %s %s (%d events)", scenario.name, status, injected)
