"""
ResponseService: decision in, audited simulated actions out.

    Decision -> ResponsePlanner -> [dedup / idempotency / cooldown]
             -> ResponseGuard.evaluate() -> SimulatedActionExecutor
             -> response_actions (+ incidents)        one transaction per action

Each planned action is handled in its own transaction:

  1. Idempotency  if this (scope, decision) was already recorded, skip.
  2. Dedup        if a once-per-scope action already SUCCEEDED in this
                  situation, skip.
  3. Cooldown     after a BLOCKED/FAILED attempt, wait before retrying; alerts
                  outside a situation are rate limited. Measured on decision
                  timestamps, never the wall clock.
  4. Preconditions  the action belongs to a situation if it must, and the
                  triggering detection event still exists (spec section 11.2).
  5. ResponseGuard.evaluate() is the authority on whether the action may run.
  6. The executor refuses anything not simulated, then simulates the action.
  7. The finished record (terminal status + lifecycle) is written once, together
     with any incident row, and never updated (P-07).

Incident lifecycle: before the actions, if the decision reports a situation that
is over for good (`ended_situation_id`), its OPEN incident is marked resolved
with a conditional UPDATE. Incidents are mutable records, unlike the action
audit trail, and this is the only automatic status change Sentinel makes.

ResponseGuard is used, never modified. Its own cooldown reads the wall clock
and is keyed only by action type, process-wide, so it is not used here
(cooldown_seconds=0); the deterministic, situation-scoped cooldown above takes
its place. Its other checks (registered action, minimum state, live-action
gate) remain authoritative.

Failure and rollback: a failure while writing rolls back that action's
transaction completely, so no partial record or orphan incident is left, and
the outcome is reported as PERSIST_FAILED. Re-submitting the same decision is
safe: idempotency and the database's unique constraints make it exactly-once.
Because every action here is simulated, simulating it again on a retry has no
side effects.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import Settings
from database.models import Incident, ResponseAction
from database.repositories import (
    DetectionEventRepository,
    IncidentRepository,
    ResponseActionRepository,
)
from models.enums import ActionStatus
from response.actions import (
    ActionLifecycle,
    ActionOutcome,
    PlannedAction,
    ResponseResult,
    Scope,
    SkipReason,
    incident_id_for,
)
from response.executor import (
    LiveExecutionRefused,
    SimulatedActionExecutor,
    SimulationResult,
    describe_parameters,
)
from response.guard import GuardVerdict, ResponseGuard
from response.planner import PlanEntry, ResponsePlanner
from threat.decision import Decision

logger = logging.getLogger(__name__)

# ResponseGuard's cooldown is wall-clock based and process-wide; the service
# applies its own deterministic, situation-scoped cooldown instead.
GUARD_COOLDOWN_SECONDS = 0.0


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


class ResponseService:
    """Plans, authorises, simulates and audits the response to each decision."""

    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        guard: ResponseGuard | None = None,
        planner: ResponsePlanner | None = None,
        executor: SimulatedActionExecutor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._guard = guard or ResponseGuard(settings=settings)
        self._planner = planner or ResponsePlanner()
        self._executor = executor or SimulatedActionExecutor()
        self._retry_cooldown = settings.response_retry_cooldown_seconds
        self._alert_cooldown = settings.response_alert_cooldown_seconds
        # Ended situations whose incident needs no further attention. A cache only:
        # after a restart the conditional update simply runs once more.
        self._settled: set[int] = set()
        if settings.live_actions:
            logger.warning(
                "[WARNING] LIVE_ACTIONS=true is set, but live response is not implemented: "
                "every response action will be SIMULATED and live verdicts are refused."
            )

    async def handle(self, decision: Decision) -> ResponseResult:
        """Respond to one decision. Never raises for action-level problems."""
        # Resolve first: when one decision ends a situation and opens the next, the
        # old incident is closed before the new one is recorded.
        resolved, resolution_failed = await self._resolve_ended(decision)
        outcomes = [await self._process(entry) for entry in self._planner.plan(decision)]
        return ResponseResult(
            decided_at=decision.calculated_at,
            situation_id=decision.situation_id,
            outcomes=tuple(outcomes),
            resolved_incident_id=resolved,
            resolution_failed=resolution_failed,
        )

    async def handle_all(self, decisions: Sequence[Decision]) -> list[ResponseResult]:
        """Respond to decisions in order."""
        return [await self.handle(d) for d in decisions]

    # ── Incident lifecycle ─────────────────────────────────────────────────

    async def _resolve_ended(self, decision: Decision) -> tuple[str | None, bool]:
        """
        Resolve the incident of a situation that is over for good.

        Returns (incident id if this call resolved it, whether saving failed).
        The decision repeats the ended situation until a later one ends, so a
        failure here is retried on the next decision. The update applies only
        to an OPEN incident: idempotent, and it never overrides an analyst.
        Bookkeeping, not a response action: nothing is simulated or executed.
        """
        situation_id = decision.ended_situation_id
        recovered_at = decision.ended_situation_recovered_at
        if situation_id is None or recovered_at is None or situation_id in self._settled:
            return None, False
        incident_id = incident_id_for(situation_id)
        try:
            async with self._session_factory() as session, session.begin():
                incidents = IncidentRepository(session)
                resolved = await incidents.resolve_if_open(
                    incident_id,
                    recovered_at=recovered_at,
                    resolved_at=decision.calculated_at,
                    resolution=decision.ended_situation_reason or "SITUATION_ENDED",
                )
                # Stop checking once the incident exists in a final-for-us state. A
                # missing incident is checked again: it may still be recorded late
                # (for example a failed RECORD_INCIDENT that is resubmitted).
                exists = resolved or await incidents.get_by_incident_id(incident_id) is not None
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error(
                "Response: could not resolve incident %s; will retry on the next decision",
                incident_id,
                exc_info=True,
            )
            return None, True
        if exists:
            self._settled.add(situation_id)
        if resolved:
            logger.info(
                "Response: incident %s resolved (%s, recovered at %s)",
                incident_id,
                decision.ended_situation_reason,
                recovered_at.isoformat(),
            )
            return incident_id, False
        return None, False

    # ── One action ─────────────────────────────────────────────────────────

    async def _process(self, entry: PlanEntry) -> ActionOutcome:
        planned = entry.action
        try:
            outcome, verdict = await self._attempt(entry)
        except asyncio.CancelledError:
            raise
        except IntegrityError:
            # A concurrent or repeated submission won the race; classify it.
            return await self._classify_conflict(planned)
        except Exception:
            logger.error(
                "Response: could not record %s (%s); nothing was saved, safe to retry",
                planned.action_type.value,
                planned.scope_key,
                exc_info=True,
            )
            return ActionOutcome(planned, skip_reason=SkipReason.PERSIST_FAILED)

        if outcome.succeeded:
            # Only after the record is durable, and only for the guard's bookkeeping.
            self._guard.record_fired(planned.action_type)
        self._log(outcome, verdict)
        return outcome

    async def _attempt(self, entry: PlanEntry) -> tuple[ActionOutcome, GuardVerdict | None]:
        planned = entry.action
        async with self._session_factory() as session, session.begin():
            actions = ResponseActionRepository(session)

            existing = await actions.get_by_idempotency_key(planned.idempotency_key)
            if existing is not None:
                return self._skip(planned, SkipReason.ALREADY_PROCESSED, existing.id), None
            if planned.once_key is not None and await actions.has_success(planned.once_key):
                return self._skip(planned, SkipReason.DUPLICATE), None
            if await self._cooling_down(actions, planned):
                return self._skip(planned, SkipReason.COOLDOWN), None

            lifecycle = ActionLifecycle.planned(planned.planned_at, planned.scope.value)
            verdict: GuardVerdict | None = None
            simulation: SimulationResult | None = None

            error = entry.precondition_error or await self._event_missing(session, planned)
            if error is not None:
                lifecycle.advance(ActionStatus.BLOCKED, planned.planned_at, error)
            else:
                verdict = self._guard.evaluate(
                    planned.action_type,
                    planned.defense_state,
                    cooldown_seconds=GUARD_COOLDOWN_SECONDS,
                )
                if not verdict.allowed:
                    lifecycle.advance(ActionStatus.BLOCKED, planned.planned_at, verdict.reason)
                else:
                    lifecycle.advance(ActionStatus.AUTHORIZED, planned.planned_at, verdict.reason)
                    simulation = self._run(planned, verdict, lifecycle)

            incident_id: str | None = None
            if simulation is not None and simulation.incident is not None:
                spec = simulation.incident
                await IncidentRepository(session).insert(
                    Incident(
                        incident_id=spec.incident_id,
                        created_at=planned.planned_at,
                        defense_state=spec.defense_state.value,
                        threat_score_at_creation=spec.threat_score,
                        event_ids=json.dumps(list(spec.event_ids)),
                        summary=spec.summary,
                    )
                )
                incident_id = spec.incident_id

            record = await actions.insert(self._record(planned, verdict, lifecycle, simulation))
            return (
                ActionOutcome(
                    planned,
                    status=lifecycle.status,
                    detail=lifecycle.steps[-1].detail,
                    record_id=record.id,
                    incident_id=incident_id,
                ),
                verdict,
            )

    def _run(
        self, planned: PlannedAction, verdict: GuardVerdict, lifecycle: ActionLifecycle
    ) -> SimulationResult | None:
        """AUTHORIZED -> (BLOCKED | EXECUTING -> SUCCEEDED | FAILED). Never raises."""
        at = planned.planned_at
        try:
            self._executor.ensure_simulated(verdict)
        except LiveExecutionRefused as refused:
            lifecycle.advance(ActionStatus.BLOCKED, at, str(refused))
            return None
        lifecycle.advance(ActionStatus.EXECUTING, at, "simulated")
        try:
            simulation = self._executor.execute(planned, verdict)
        except Exception as exc:
            # Record the failure type only: exception text is not trusted audit data.
            lifecycle.advance(ActionStatus.FAILED, at, f"simulation failed: {type(exc).__name__}")
            return None
        # The machine-readable outcome (e.g. WOULD_QUARANTINE) is the audit detail.
        lifecycle.advance(ActionStatus.SUCCEEDED, at, simulation.outcome)
        return simulation

    async def _cooling_down(
        self, actions: ResponseActionRepository, planned: PlannedAction
    ) -> bool:
        """
        Is there a conflicting attempt near this decision's time?

        Measured around the decision's own timestamp, not against "the latest
        attempt", so the answer does not depend on the order decisions arrive in:
        a redelivered older decision is judged exactly as it was the first time.

          * a BLOCKED/FAILED attempt in the preceding retry cooldown -> wait;
          * for repeatable (COOLDOWN-scope) actions, a SUCCEEDED attempt within
            the alert cooldown on either side -> skip.
        """
        t = planned.planned_at
        retry = timedelta(seconds=self._retry_cooldown)
        alert = timedelta(seconds=self._alert_cooldown)
        window_start = t - max(retry, alert)
        window_end = t + alert if planned.scope is Scope.COOLDOWN else t
        for attempt in await actions.attempts_between(planned.scope_key, window_start, window_end):
            delta = (t - _aware(attempt.executed_at)).total_seconds()
            if attempt.status in (ActionStatus.BLOCKED.value, ActionStatus.FAILED.value):
                if 0 <= delta < self._retry_cooldown:
                    return True
            elif attempt.status == ActionStatus.SUCCEEDED.value and planned.scope is Scope.COOLDOWN:
                if abs(delta) < self._alert_cooldown:
                    return True
        return False

    @staticmethod
    async def _event_missing(session: AsyncSession, planned: PlannedAction) -> str | None:
        if planned.triggering_event_id is None:
            return None
        if await DetectionEventRepository(session).get_by_id(planned.triggering_event_id) is None:
            return f"triggering detection event {planned.triggering_event_id} not found"
        return None

    @staticmethod
    def _record(
        planned: PlannedAction,
        verdict: GuardVerdict | None,
        lifecycle: ActionLifecycle,
        simulation: SimulationResult | None,
    ) -> ResponseAction:
        if not lifecycle.is_terminal:  # pragma: no cover - guarded by the lifecycle itself
            raise RuntimeError("refusing to record a non-terminal action")
        description = (
            simulation.dry_run_description
            if simulation is not None
            else f"Not executed: {planned.action_type.value} ({lifecycle.steps[-1].detail})."
        )
        return ResponseAction(
            executed_at=planned.planned_at,
            action_type=planned.action_type.value,
            defense_state=planned.defense_state.value,
            dry_run_description=description,
            triggering_event_id=planned.triggering_event_id,
            # Every action in this phase is simulated; there is no live path.
            is_simulated=True,
            parameters=describe_parameters(planned),
            result=simulation.result if simulation is not None else lifecycle.steps[-1].detail,
            situation_id=planned.situation_id,
            status=lifecycle.status.value,
            action_class=verdict.action_class.value if verdict is not None else None,
            guard_reason=verdict.reason if verdict is not None else lifecycle.steps[-1].detail,
            scope_key=planned.scope_key,
            once_key=planned.once_key,
            idempotency_key=planned.idempotency_key,
            lifecycle=lifecycle.to_json(),
        )

    async def _classify_conflict(self, planned: PlannedAction) -> ActionOutcome:
        try:
            async with self._session_factory() as session:
                actions = ResponseActionRepository(session)
                existing = await actions.get_by_idempotency_key(planned.idempotency_key)
                if existing is not None:
                    return self._skip(planned, SkipReason.ALREADY_PROCESSED, existing.id)
                if planned.once_key is not None and await actions.has_success(planned.once_key):
                    return self._skip(planned, SkipReason.DUPLICATE)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error("Response: could not classify a write conflict", exc_info=True)
        return ActionOutcome(planned, skip_reason=SkipReason.PERSIST_FAILED)

    @staticmethod
    def _skip(
        planned: PlannedAction, reason: SkipReason, record_id: int | None = None
    ) -> ActionOutcome:
        return ActionOutcome(planned, skip_reason=reason, detail=reason.value, record_id=record_id)

    @staticmethod
    def _log(outcome: ActionOutcome, verdict: GuardVerdict | None) -> None:
        p = outcome.planned
        if outcome.skip_reason is not None:
            logger.debug(
                "Response: %s %s skipped (%s)",
                p.action_type.value,
                p.scope_key,
                outcome.skip_reason.value,
            )
            return
        logger.info(
            "Response: %s %s -> %s [simulated] situation=%s record=%s",
            p.action_type.value,
            p.scope_key,
            outcome.status.value if outcome.status else "-",
            p.situation_id,
            outcome.record_id,
        )
