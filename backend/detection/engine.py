"""
DetectionEngine: runs rules and persists the resulting DetectionEvents.

    TelemetrySample / SyntheticEvent -> rules -> DetectionResult -> DetectionEvent

The engine owns scheduling, failure isolation and persistence. Rules stay
pure and bounded. It has no dependency on any LLM and performs no I/O other
than the database write.

Failure handling:
  * A rule that raises is logged with its traceback and counted; the other
    rules still run. Errors are never silently swallowed.
  * If persisting fails, every cooldown consumed by the unsaved results is
    released, so the next occurrence is reported instead of suppressed.

Evaluation is synchronous and has no await points, so each sample/event is
evaluated atomically with respect to other asyncio tasks.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Sequence

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.exceptions import RuleNotFoundError
from database.models import DetectionEvent, TelemetrySample
from database.repositories import DetectionEventRepository
from detection.rules.base import DetectionRule
from detection.synthetic import SyntheticEvent
from detection.types import DetectionResult, RuleInfo, TelemetryObservation

logger = logging.getLogger(__name__)

EVENT_DATA_SCHEMA_VERSION = 1


def result_to_event(result: DetectionResult) -> DetectionEvent:
    """Translate a DetectionResult into the persisted DetectionEvent."""
    envelope = {
        "schema_version": EVENT_DATA_SCHEMA_VERSION,
        "source_kind": "synthetic" if result.is_synthetic else "telemetry",
        "evidence": result.evidence,
    }
    return DetectionEvent(
        detected_at=result.detected_at,
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        severity=result.severity.value,
        metric_key=result.metric_key,
        metric_value=result.metric_value,
        threshold_value=result.threshold_value,
        is_synthetic=result.is_synthetic,
        event_data=json.dumps(envelope, allow_nan=False, sort_keys=True),
        telemetry_sample_id=result.telemetry_sample_id,
        event_type=result.event_type,
        classification=result.classification.value,
        confidence=result.confidence,
    )


class DetectionEngine:
    """
    Evaluates enabled rules against telemetry and synthetic events.

    Args:
        rules:           Rules to run, in order. Rule IDs must be unique.
        session_factory: Produces AsyncSessions for persistence.
    """

    def __init__(
        self,
        rules: Sequence[DetectionRule],
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id in detection rule set")
        self._rules: list[DetectionRule] = list(rules)
        self._session_factory = session_factory
        self._rule_errors: dict[str, int] = {}

    # ── Rule management ────────────────────────────────────────────────────

    def list_rules(self) -> list[RuleInfo]:
        return [rule.info() for rule in self._rules]

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> RuleInfo:
        """Enable or disable a rule at runtime. Raises RuleNotFoundError."""
        rule = self._get_rule(rule_id)
        rule.enabled = enabled
        logger.info("Detection: rule %s %s", rule_id, "enabled" if enabled else "disabled")
        return rule.info()

    @property
    def rule_error_counts(self) -> dict[str, int]:
        """How many times each rule has raised since startup (a copy)."""
        return dict(self._rule_errors)

    def reset(self) -> None:
        """Clear all rule state (for example when a demo is reset)."""
        for rule in self._rules:
            rule.reset()

    # ── Processing ─────────────────────────────────────────────────────────

    async def process_sample(self, sample: TelemetrySample) -> list[DetectionEvent]:
        """Evaluate telemetry rules for one persisted sample."""
        observation = TelemetryObservation.from_sample(sample)
        results = self._evaluate(lambda rule: rule.evaluate_telemetry(observation))
        return await self._persist(results)

    async def process_synthetic(self, event: SyntheticEvent) -> list[DetectionEvent]:
        """Evaluate rules for one synthetic security event."""
        results = self._evaluate(lambda rule: rule.evaluate_synthetic(event))
        return await self._persist(results)

    # ── Internals ──────────────────────────────────────────────────────────

    def _get_rule(self, rule_id: str) -> DetectionRule:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        raise RuleNotFoundError(f"unknown detection rule: {rule_id}")

    def _evaluate(
        self, run: Callable[[DetectionRule], list[DetectionResult]]
    ) -> list[DetectionResult]:
        """Run every enabled rule, isolating failures from one another."""
        results: list[DetectionResult] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                results.extend(run(rule))
            except Exception:
                # Deliberately broad: a bug in one rule must not blind the
                # others. It is logged with a traceback and counted, never hidden.
                self._rule_errors[rule.rule_id] = self._rule_errors.get(rule.rule_id, 0) + 1
                logger.exception(
                    "Detection: rule %s raised; continuing with other rules", rule.rule_id
                )
        return results

    async def _persist(self, results: list[DetectionResult]) -> list[DetectionEvent]:
        if not results:
            return []
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    repo = DetectionEventRepository(session)
                    events = [await repo.insert(result_to_event(r)) for r in results]
        except asyncio.CancelledError:
            self._release(results)
            raise
        except Exception:
            self._release(results)
            logger.error(
                "Detection: failed to persist %d event(s); cooldowns released",
                len(results),
                exc_info=True,
            )
            return []
        for event in events:
            logger.info(
                "Detection: event id=%s rule=%s type=%s severity=%s classification=%s",
                event.id,
                event.rule_id,
                event.event_type,
                event.severity,
                event.classification,
            )
        return events

    def _release(self, results: list[DetectionResult]) -> None:
        """Undo the debounce consumed by results that were not saved."""
        for result in results:
            try:
                self._get_rule(result.rule_id).on_emission_failed(result)
            except Exception:
                logger.exception("Detection: could not release cooldown for %s", result.rule_id)
