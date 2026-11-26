"""Unit tests for the Phase 2 runtime building blocks: LiveHub, RateLimiter, DemoController."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from core.demo import (
    MAX_INJECT_COUNT,
    SCENARIOS,
    DemoController,
    RateLimiter,
    ScenarioBusyError,
    UnknownScenarioError,
)
from core.live import LiveHub, LiveMessageType, SubscriberLimitError
from database.models import DetectionEvent
from detection.synthetic import SECURITY_SYNTHETIC_TYPES, SyntheticEvent
from models.enums import SyntheticEventType

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


# ── LiveHub ───────────────────────────────────────────────────────────────────


async def test_publish_reaches_every_subscriber_in_the_contract_shape() -> None:
    hub = LiveHub(max_subscribers=2, queue_size=10)
    async with hub.subscribe() as a, hub.subscribe() as b:
        hub.publish(LiveMessageType.THREAT_SCORE, {"score": 0.4})
        for queue in (a, b):
            message = queue.get_nowait()
            assert set(message) == {"type", "timestamp", "payload"}
            assert message["type"] == "threat_score"
            assert message["payload"] == {"score": 0.4}


async def test_a_full_queue_drops_the_oldest_message_and_never_blocks() -> None:
    hub = LiveHub(max_subscribers=1, queue_size=10)
    async with hub.subscribe() as queue:
        for i in range(25):
            hub.publish(LiveMessageType.TELEMETRY, {"i": i})
        assert queue.qsize() == 10
        assert queue.get_nowait()["payload"] == {"i": 15}
    assert hub.dropped == 15


async def test_publishing_without_subscribers_is_harmless() -> None:
    hub = LiveHub(max_subscribers=1, queue_size=10)
    hub.publish(LiveMessageType.TELEMETRY, {})
    assert hub.published == 1 and hub.dropped == 0


async def test_the_subscriber_limit_is_enforced_and_released_on_exit() -> None:
    hub = LiveHub(max_subscribers=1, queue_size=10)
    async with hub.subscribe():
        with pytest.raises(SubscriberLimitError):
            async with hub.subscribe():
                pass
    assert hub.subscriber_count == 0
    async with hub.subscribe():
        assert hub.subscriber_count == 1


# ── RateLimiter ───────────────────────────────────────────────────────────────


def test_the_rate_limit_allows_n_calls_per_rolling_minute() -> None:
    now = [0.0]
    limiter = RateLimiter(3, monotonic=lambda: now[0])
    assert [limiter.allow() for _ in range(4)] == [True, True, True, False]
    now[0] = 59.9
    assert not limiter.allow()
    now[0] = 60.0
    assert limiter.allow()


# ── DemoController ────────────────────────────────────────────────────────────


class Recorder:
    def __init__(self, fail: bool = False) -> None:
        self.events: list[SyntheticEvent] = []
        self.fail = fail
        self.gate: asyncio.Event | None = None

    async def __call__(self, events: Sequence[SyntheticEvent]) -> list[DetectionEvent]:
        if self.gate is not None:
            await self.gate.wait()
        if self.fail:
            raise RuntimeError("pipeline unavailable")
        self.events.extend(events)
        return []


def controller(recorder: Recorder, interval: float = 0.0) -> DemoController:
    return DemoController(
        recorder, step_interval=interval, max_requests_per_minute=5, clock=lambda: T0
    )


def test_every_scenario_uses_only_security_synthetic_types() -> None:
    assert set(SCENARIOS) == {"normal", "suspicious", "critical"}
    for scenario in SCENARIOS.values():
        assert all(step.event_type in SECURITY_SYNTHETIC_TYPES for step in scenario.steps)
    assert SCENARIOS["normal"].steps == ()


async def test_a_scenario_injects_clearly_marked_synthetic_events() -> None:
    recorder = Recorder()
    demo = controller(recorder)
    demo.start("critical")
    run = await demo.wait()
    assert run is not None and run.status == "completed"
    assert run.events_injected == len(recorder.events) == 11
    assert all(e.source == "demo" and e.scenario_id == "demo-critical" for e in recorder.events)
    assert recorder.events[-1].event_type is SyntheticEventType.SUSPICIOUS_PROCESS


async def test_the_normal_scenario_injects_nothing() -> None:
    recorder = Recorder()
    demo = controller(recorder)
    demo.start("normal")
    run = await demo.wait()
    assert run is not None and run.status == "completed" and recorder.events == []


async def test_unknown_and_concurrent_scenarios_are_refused() -> None:
    recorder = Recorder()
    recorder.gate = asyncio.Event()
    demo = controller(recorder)
    with pytest.raises(UnknownScenarioError):
        demo.start("rm-rf")
    demo.start("suspicious")
    with pytest.raises(ScenarioBusyError):
        demo.start("critical")
    recorder.gate.set()
    await demo.wait()
    assert demo.running is None


async def test_stop_cancels_a_running_scenario() -> None:
    recorder = Recorder()
    recorder.gate = asyncio.Event()
    demo = controller(recorder)
    demo.start("critical")
    await asyncio.sleep(0)
    await demo.stop()
    assert demo.last_run is not None and demo.last_run.status == "cancelled"


async def test_a_failing_scenario_is_recorded_not_raised() -> None:
    demo = controller(Recorder(fail=True))
    demo.start("suspicious")
    run = await demo.wait()
    assert run is not None and run.status == "failed"


async def test_manual_injection_is_bounded_and_security_typed() -> None:
    recorder = Recorder()
    demo = controller(recorder)
    await demo.inject(SyntheticEventType.ACCESS_DENIED, 3)
    assert len(recorder.events) == 3
    assert all(e.scenario_id == "demo-manual" for e in recorder.events)
    with pytest.raises(ValueError):
        await demo.inject(SyntheticEventType.AUTH_FAILURE, MAX_INJECT_COUNT + 1)
    with pytest.raises(ValueError):
        await demo.inject(SyntheticEventType.CPU_SPIKE, 1)
