"""
SentinelRuntime: runs the existing security decision pipeline inside the app.

    telemetry  -> TelemetryCollector.collect_once()          (validation, persistence)
               -> DetectionEngine.process_sample()            (rules, persistence)
    synthetic  -> DetectionEngine.process_synthetic()         (demo intake, P-10)
               -> ThreatAssessmentService.assess(events, now) (scoring + state machine)
               -> ResponseService.handle(decision)            (planner, guard, simulated executor)
               -> ExplanationService.observe(decision)        (explanation-only, after the above)
               -> LiveHub.publish(...)                        (sanitized read models, one-way)

The runtime is a coordinator. It contains no detection, scoring, state, response
or AI logic, and passes nothing from the explanation layer back into the
pipeline. Every pipeline step runs under one asyncio.Lock, so the monitoring loop
and demo injections never interleave inside the stateful services. All work is
async on the application's event loop; the only background tasks are the
monitoring loop, the explanation worker and at most one demo scenario, all
cancelled and awaited by stop().
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.protocols import LLMProvider
from core.config import Settings
from core.demo import DemoController
from core.live import LiveHub, LiveMessageType
from core.runtime_views import DemoRunSchema, RuntimeStatusSchema, event_view, telemetry_view
from database.models import DetectionEvent
from detection.engine import DetectionEngine
from detection.registry import build_default_rules
from detection.synthetic import SyntheticEvent
from explanation.service import ExplanationService
from models.enums import DefenseState
from response.actions import ActionOutcome
from response.service import ResponseService
from telemetry.collector import TelemetryCollector
from telemetry.protocols import TelemetryProvider
from threat.config import ThreatConfig
from threat.decision import Decision
from threat.service import ThreatAssessmentService

logger = logging.getLogger(__name__)

# Consecutive failed cycles after which the runtime reports itself unhealthy.
UNHEALTHY_AFTER_FAILURES = 3


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class RuntimeStats:
    """Basic runtime measurements. Durations are milliseconds of the last cycle."""

    started_at: datetime | None = None
    cycles: int = 0
    failed_cycles: int = 0
    consecutive_failures: int = 0
    telemetry_failures: int = 0
    last_cycle_at: datetime | None = None
    last_cycle_ms: float | None = None
    max_cycle_ms: float | None = None
    last_telemetry_ms: float | None = None
    last_detection_ms: float | None = None
    last_decision_ms: float | None = None
    detections: int = 0
    decisions: int = 0
    actions_recorded: int = 0
    synthetic_events: int = 0
    last_error: str | None = None  # exception class name only, never its message


class SentinelRuntime:
    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        telemetry: TelemetryProvider,
        *,
        llm: LLMProvider | None = None,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._interval = settings.poll_interval_seconds
        self._clock = clock
        self._sleep = sleep
        self.collector = TelemetryCollector(telemetry, session_factory, settings)
        self.detection = DetectionEngine(build_default_rules(settings), session_factory)
        self.threat = ThreatAssessmentService(ThreatConfig.from_settings(settings), session_factory)
        self.response = ResponseService(settings, session_factory)
        self.explanation = ExplanationService(settings, session_factory, provider=llm, clock=clock)
        self.live = LiveHub(
            max_subscribers=settings.live_max_subscribers, queue_size=settings.live_queue_size
        )
        self.demo = DemoController(
            self.inject,
            step_interval=settings.demo_step_interval_seconds,
            max_requests_per_minute=settings.demo_max_requests_per_minute,
            clock=clock,
            sleep=sleep,
        )
        self.stats = RuntimeStats()
        self._lock = asyncio.Lock()
        self._monitor: asyncio.Task[None] | None = None
        self._last: Decision | None = None

    # ── State exposed to the API ──────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._monitor is not None and not self._monitor.done()

    @property
    def defense_state(self) -> DefenseState:
        return self.threat.state

    @property
    def last_decision(self) -> Decision | None:
        return self._last

    @property
    def poll_interval_seconds(self) -> float:
        return self._interval

    def status_view(self) -> RuntimeStatusSchema:
        """A read-only snapshot for GET /api/v1/runtime."""
        s, last, run = self.stats, self._last, self.demo.last_run
        per_minute = None
        if s.started_at is not None:
            minutes = (self._clock() - s.started_at).total_seconds() / 60
            per_minute = round(s.detections / minutes, 3) if minutes > 0 else None
        return RuntimeStatusSchema(
            monitoring=self.running,
            healthy=self.running and s.consecutive_failures < UNHEALTHY_AFTER_FAILURES,
            started_at=s.started_at,
            poll_interval_seconds=self._interval,
            defense_state=self.defense_state,
            threat_score=last.threat_score if last else None,
            last_decision_at=last.calculated_at if last else None,
            cycles=s.cycles,
            failed_cycles=s.failed_cycles,
            consecutive_failures=s.consecutive_failures,
            telemetry_failures=s.telemetry_failures,
            last_cycle_at=s.last_cycle_at,
            last_cycle_ms=s.last_cycle_ms,
            max_cycle_ms=s.max_cycle_ms,
            last_telemetry_ms=s.last_telemetry_ms,
            last_detection_ms=s.last_detection_ms,
            last_decision_ms=s.last_decision_ms,
            detections=s.detections,
            decisions=s.decisions,
            actions_recorded=s.actions_recorded,
            synthetic_events=s.synthetic_events,
            events_per_minute=per_minute,
            last_error=s.last_error,
            explanations_pending=self.explanation.pending,
            live_subscribers=self.live.subscriber_count,
            live_messages_dropped=self.live.dropped,
            demo_running=self.demo.running,
            last_demo_run=DemoRunSchema(
                name=run.name,
                status=run.status,
                started_at=run.started_at,
                finished_at=run.finished_at,
                events_injected=run.events_injected,
                detections=run.detections,
            )
            if run
            else None,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self, *, monitor: bool = True) -> None:
        """Restore persisted state, start the explanation worker and the monitoring loop."""
        restored = await self.threat.restore_state(self._clock())
        logger.info("Runtime: restored defense state %s", restored.value)
        self.explanation.start()
        self.stats.started_at = self._clock()
        if monitor:
            self._monitor = asyncio.create_task(self._monitor_loop(), name="sentinel-monitor")

    async def stop(self) -> None:
        """Cancel and await every background task, then release the telemetry provider."""
        self.live.close()  # live clients are told to reconnect (to the next runtime, if any)
        await self.demo.stop()
        if self._monitor is not None:
            self._monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor
            self._monitor = None
        await self.explanation.stop()
        await self.collector.close()
        logger.info("Runtime: stopped")

    # ── Pipeline ──────────────────────────────────────────────────────────────

    async def run_cycle(self) -> Decision:
        """One monitoring cycle: collect, detect, decide. Re-evaluates decay if collection fails."""
        started = time.perf_counter()
        sample = await self.collector.collect_once()
        collected = time.perf_counter()
        if sample is None:
            self.stats.telemetry_failures += 1
        async with self._lock:
            events = await self.detection.process_sample(sample) if sample is not None else []
            detected = time.perf_counter()
            decision = await self._decide(events)
        finished = time.perf_counter()
        if sample is not None:
            snapshot = telemetry_view(sample).model_dump(mode="json")
            self.live.publish(LiveMessageType.TELEMETRY, snapshot)
        cycle_ms = (finished - started) * 1000
        self.stats.cycles += 1
        self.stats.last_cycle_at = self._clock()
        self.stats.last_cycle_ms = cycle_ms
        self.stats.max_cycle_ms = max(self.stats.max_cycle_ms or 0.0, cycle_ms)
        self.stats.last_telemetry_ms = (collected - started) * 1000
        self.stats.last_detection_ms = (detected - collected) * 1000
        self.stats.last_decision_ms = (finished - detected) * 1000
        return decision

    async def inject(self, events: Sequence[SyntheticEvent]) -> list[DetectionEvent]:
        """Feed synthetic events through detection and the full decision path, one by one."""
        found: list[DetectionEvent] = []
        async with self._lock:
            for event in events:
                detected = await self.detection.process_synthetic(event)
                found.extend(detected)
                await self._decide(detected)
        self.stats.synthetic_events += len(events)
        return found

    async def _decide(self, events: list[DetectionEvent]) -> Decision:
        """The authoritative path. Must be called with the lock held."""
        decision = await self.threat.assess(events, self._clock())
        result = await self.response.handle(decision)
        # Explanation strictly after scoring, state and response are decided and stored;
        # observe() never blocks or raises and returns nothing the pipeline uses.
        self.explanation.observe(decision)
        self._last = decision
        self.stats.decisions += 1
        self.stats.detections += len(events)
        recorded = [o for o in result.outcomes if o.recorded]
        self.stats.actions_recorded += len(recorded)
        self._publish(decision, events, recorded)
        return decision

    def _publish(
        self, decision: Decision, events: list[DetectionEvent], recorded: list[ActionOutcome]
    ) -> None:
        for event in events:
            payload = event_view(event).model_dump(mode="json")
            self.live.publish(LiveMessageType.DETECTION_EVENT, payload)
        self.live.publish(
            LiveMessageType.THREAT_SCORE,
            {
                "calculated_at": decision.calculated_at.isoformat(),
                "score": decision.threat_score,
                "defense_state": decision.defense_state.value,
            },
        )
        if decision.state_changed:
            self.live.publish(
                LiveMessageType.DEFENSE_STATE_CHANGE,
                {
                    "changed_at": decision.calculated_at.isoformat(),
                    "previous_state": decision.previous_state.value,
                    "new_state": decision.defense_state.value,
                    "trigger_score": decision.threat_score,
                },
            )
        for outcome in recorded:
            self.live.publish(
                LiveMessageType.RESPONSE_ACTION,
                {
                    "id": outcome.record_id,
                    "action_type": outcome.planned.action_type.value,
                    "status": outcome.status.value if outcome.status else None,
                    "incident_id": outcome.incident_id,
                },
            )

    async def _monitor_loop(self) -> None:
        logger.info("Runtime: monitoring started (interval %.2f s)", self._interval)
        while True:
            try:
                await self.run_cycle()
                self.stats.consecutive_failures = 0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Logged with its traceback and counted; the next cycle still runs.
                self.stats.failed_cycles += 1
                self.stats.consecutive_failures += 1
                self.stats.last_error = type(exc).__name__
                logger.error("Runtime: monitoring cycle failed", exc_info=True)
            await self._sleep(self._interval)
