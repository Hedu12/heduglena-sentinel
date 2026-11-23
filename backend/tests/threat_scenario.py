"""
The deterministic end-to-end demo scenario, shared by the integration tests.

    FakeTelemetryProvider -> TelemetryCollector -> DetectionEngine
                          -> ThreatAssessmentService -> persisted decisions

Everything runs on one injected clock (seconds after T0), so a run is fully
reproducible. Phases:

    NORMAL -> CPU ANOMALY -> NETWORK ANOMALY -> (quiet) -> AUTH FAILURE BURST
           -> REPEATED AUTH FAILURES -> CRITICAL ESCALATION -> RECOVERY
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import Settings
from database.models import DetectionEvent
from detection.engine import DetectionEngine
from detection.registry import build_default_rules
from detection.synthetic import SyntheticEvent
from models.enums import SyntheticEventType
from telemetry.collector import TelemetryCollector
from telemetry.providers.fake import FakeTelemetryProvider
from tests.threat_helpers import at
from threat.config import ThreatConfig
from threat.decision import Decision
from threat.service import ThreatAssessmentService

MB = 1_000_000


@dataclass
class Step:
    """One point on the timeline: what happened and what Sentinel decided."""

    t: float
    phase: str
    detections: list[DetectionEvent]
    decision: Decision


@dataclass
class ScenarioResult:
    steps: list[Step] = field(default_factory=list)

    @property
    def decisions(self) -> list[Decision]:
        return [s.decision for s in self.steps]

    def phase(self, name: str) -> list[Step]:
        return [s for s in self.steps if s.phase == name]

    def detections(self) -> list[DetectionEvent]:
        return [e for s in self.steps for e in s.detections]


class Scenario:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        settings = Settings()
        self.provider = FakeTelemetryProvider(
            cpu_percent=20.0, memory_percent=40.0, process_count=100, net_bytes_sent_total=0
        )
        self.collector = TelemetryCollector(self.provider, factory, settings)
        self.detection = DetectionEngine(build_default_rules(settings), factory)
        self.threat = ThreatAssessmentService(ThreatConfig.from_settings(settings), factory)
        self.result = ScenarioResult()
        self._net_total = 0

    async def telemetry(
        self, t: float, phase: str, *, cpu: float = 20.0, sent_mb: float = 0.0
    ) -> Step:
        """One monitoring cycle: collect, detect, assess. `sent_mb` = data sent since the last."""
        self._net_total += int(sent_mb * MB)
        self.provider._cpu_percent = cpu  # type: ignore[attr-defined]
        self.provider._net_bytes_sent_total = self._net_total  # type: ignore[attr-defined]
        self.provider._collected_at = at(t)  # type: ignore[attr-defined]
        sample = await self.collector.collect_once()
        assert sample is not None
        events = await self.detection.process_sample(sample)
        return await self._record(t, phase, events)

    async def security(
        self, t: float, phase: str, event_type: SyntheticEventType, subject: str
    ) -> Step:
        """One synthetic security event, through the same detection and threat pipeline."""
        event = SyntheticEvent(
            event_type=event_type, occurred_at=at(t), subject=subject, scenario_id="demo-scenario"
        )
        events = await self.detection.process_synthetic(event)
        return await self._record(t, phase, events)

    async def _record(self, t: float, phase: str, events: list[DetectionEvent]) -> Step:
        decision = await self.threat.assess(events, at(t))
        step = Step(t=t, phase=phase, detections=events, decision=decision)
        self.result.steps.append(step)
        return step


async def play_attack(s: Scenario, start: float = 0.0) -> None:
    """Play the whole attack timeline once, `start` seconds after T0 (420 s long)."""
    auth = SyntheticEventType.AUTH_FAILURE

    # NORMAL: five healthy samples.
    for t in range(0, 25, 5):
        await s.telemetry(start + t, "normal")

    # CPU ANOMALY: three consecutive samples above 90 %.
    for t in (25, 30, 35):
        await s.telemetry(start + t, "cpu", cpu=96.0)
    await s.telemetry(start + 40, "cpu")

    # NETWORK ANOMALY: 300 MB per 5 s = 60 MB/s outbound for three samples.
    for t in (45, 50, 55):
        await s.telemetry(start + t, "network", sent_mb=300)

    # Quiet period: evidence ages.
    for t in range(60, 100, 5):
        await s.telemetry(start + t, "quiet")

    # AUTH FAILURE BURST: five failures in five seconds.
    for t in range(100, 105):
        await s.security(start + t, "auth_burst", auth, "admin")

    # REPEATED AUTH FAILURES: failures 6-10; the tenth escalates the detection.
    for t in range(105, 110):
        await s.security(start + t, "auth_repeated", auth, "admin")
    await s.telemetry(start + 115, "auth_repeated")

    # CRITICAL ESCALATION: a simulated malicious process.
    await s.security(
        start + 125, "critical", SyntheticEventType.SUSPICIOUS_PROCESS, "simulated-malware"
    )

    # RECOVERY: no new evidence; decay and the cooldown bring the state down.
    for t in range(130, 421, 10):
        await s.telemetry(start + t, "recovery")


async def run_scenario(factory: async_sessionmaker[AsyncSession]) -> ScenarioResult:
    s = Scenario(factory)
    await play_attack(s)
    return s.result
