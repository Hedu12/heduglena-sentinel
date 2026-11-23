"""
ThreatAssessmentService: evidence in, persisted decision out.

    DetectionEvents -> ThreatScorer -> DefenseStateMachine -> Decision
                                              |
                                  threat_scores / defense_state_changes

Responsibilities:
  * convert detection events into evidence and score them at `now`;
  * derive the active-threat floor and the severe-escalation flag;
  * evaluate the state machine;
  * persist the score and any state transition in ONE transaction.

The service reads no clock: callers pass `now`, so a given event sequence
always produces the same decisions. It never creates incidents (evidence is
aggregated here; incidents are a later lifecycle concern) and never executes
anything: it returns a Decision.

If a transition cannot be saved, the machine is rolled back to its state
before the evaluation and DatabaseError is raised, so memory never claims a
state the audit trail does not contain. The next call re-derives the same
transition from the same evidence.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.exceptions import DatabaseError
from database.models import DefenseStateChange, DetectionEvent, ThreatScore
from database.repositories import (
    DefenseStateChangeRepository,
    DetectionEventRepository,
    ThreatScoreRepository,
)
from models.enums import DefenseState, Severity
from threat.config import ThreatConfig
from threat.decision import Decision, merge_reasons, recommended_actions_for
from threat.evidence import EvidenceItem
from threat.scorer import ScoreBreakdown, ThreatScorer
from threat.situation import SituationTracker, SituationUpdate
from threat.state_machine import DefenseStateMachine, StateEvaluation

logger = logging.getLogger(__name__)

EVIDENCE_SCHEMA_VERSION = 1

# How many recent state transitions a restart replays to recover the situation. A
# situation is a handful of transitions; this bounds the work, not the semantics.
RESTORE_TRANSITION_LIMIT = 200


def _aware(moment: datetime) -> datetime:
    """SQLite returns naive datetimes; the database layer stores UTC."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


class ThreatAssessmentService:
    """Scores evidence, runs the state machine, and persists the outcome."""

    def __init__(
        self,
        config: ThreatConfig,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        scorer: ThreatScorer | None = None,
        machine: DefenseStateMachine | None = None,
    ) -> None:
        self._cfg = config
        self._session_factory = session_factory
        self._scorer = scorer or ThreatScorer(config.scoring)
        self._machine = machine or DefenseStateMachine(config.state)
        self._situations = SituationTracker(config.incident_reopen_seconds)
        self._last_persisted_score: float | None = None

    @property
    def state(self) -> DefenseState:
        return self._machine.state

    @property
    def situation_id(self) -> int | None:
        """The security situation in progress, or None while RELAXED."""
        return self._situations.active_id

    async def restore_state(self, now: datetime) -> DefenseState:
        """
        Rebuild in-memory state from the database after a restart. Call once, at
        startup, on a fresh service, with the current time.

        Restores everything a decision depends on:
          * the defense state, from the last persisted transition;
          * the evidence: detection events still inside the TTL are replayed in time
            order, so the score after a restart equals the score before it;
          * the security situation, by replaying recent transitions, so a restart
            neither forgets an open incident nor recommends a second one;
          * the last persisted score, so score history is not duplicated.

        Dwell and cooldown timers restart. A restored raised state therefore descends
        gradually from the first evaluation, never instantly: after an outage the
        service does not assume the threat has passed.
        """
        self.reset()
        since = now - timedelta(seconds=self._cfg.scoring.evidence_ttl_seconds)
        async with self._session_factory() as session:
            changes = await DefenseStateChangeRepository(session).get_all(
                limit=RESTORE_TRANSITION_LIMIT
            )
            score = await ThreatScoreRepository(session).get_latest()
            events = await DetectionEventRepository(session).get_since(
                since, limit=self._cfg.scoring.dedup_window
            )

        ordered = sorted(changes, key=lambda c: (c.changed_at, c.id))
        for change in ordered:
            self._situations.apply(
                transition_id=change.id,
                previous=DefenseState(change.from_state),
                new=DefenseState(change.to_state),
                at=_aware(change.changed_at),
            )
        if ordered:
            last = ordered[-1]
            self._machine.restore(DefenseState(last.to_state), _aware(last.changed_at))
            if self._machine.state is not DefenseState.RELAXED and self.situation_id is None:
                # The opening transition is older than the replayed history window.
                self._situations.adopt(ordered[0].id)

        for event in sorted(events, key=lambda e: (e.detected_at, e.id)):
            self._observe(event, now)
        self._scorer.prune(now)

        if score is not None:
            self._last_persisted_score = score.score
        logger.info(
            "Threat: restored state=%s situation=%s signals=%d",
            self._machine.state.value,
            self.situation_id,
            self._scorer.signal_count,
        )
        return self._machine.state

    async def assess(self, events: Sequence[DetectionEvent], now: datetime) -> Decision:
        """
        Fold `events` into the evidence and decide at `now`.

        Call with an empty sequence to re-evaluate as time passes (decay).
        """
        observed = sum(self._observe(event, now) for event in events)
        self._scorer.prune(now)
        breakdown = self._scorer.score(now)

        snapshot = self._machine.snapshot()
        evaluation = self._machine.evaluate(
            now=now,
            score=breakdown.final_score,
            floor=self._floor(breakdown.active_max_severity),
            severe=breakdown.severe_active,
            corroborated=breakdown.corroborating_categories
            >= self._cfg.state.aggressive_min_categories,
        )

        try:
            score_id, transition_id = await self._persist(breakdown, evaluation)
        except asyncio.CancelledError:
            self._machine.rollback(snapshot)
            raise
        except Exception as exc:
            self._machine.rollback(snapshot)
            logger.error("Threat: failed to persist decision; state rolled back", exc_info=True)
            raise DatabaseError("could not persist threat decision") from exc

        # Update the situation only now that the transition is durable: a failed
        # persist leaves it untouched, so the incident is still recommended, once,
        # when the transition is re-derived and saved.
        update = SituationUpdate(self._situations.active_id)
        if evaluation.changed and transition_id is not None:
            update = self._situations.apply(
                transition_id=transition_id,
                previous=evaluation.previous_state,
                new=evaluation.new_state,
                at=now,
            )
        ended = self._situations.ended(now)

        decision = Decision(
            calculated_at=now,
            threat_score=breakdown.final_score,
            defense_state=evaluation.new_state,
            previous_state=evaluation.previous_state,
            state_changed=evaluation.changed,
            reason_codes=merge_reasons(breakdown.reason_codes, evaluation.reason_codes),
            recommended_actions=recommended_actions_for(
                evaluation.new_state,
                new_evidence=observed > 0,
                record_incident=update.opened,
            ),
            breakdown=breakdown,
            evaluation=evaluation,
            score_record_id=score_id,
            transition_id=transition_id,
            situation_id=update.situation_id,
            new_situation=update.opened,
            ended_situation_id=ended.situation_id if ended else None,
            ended_situation_recovered_at=ended.recovered_at if ended else None,
            ended_situation_reason=ended.reason if ended else None,
        )
        if evaluation.changed:
            logger.info(
                "Threat: state %s -> %s (score %.3f, codes %s)",
                evaluation.previous_state.value,
                evaluation.new_state.value,
                breakdown.final_score,
                [c.value for c in evaluation.reason_codes],
            )
        return decision

    def reset(self) -> None:
        """Forget all evidence and return to RELAXED (for example on a demo reset)."""
        self._scorer.reset()
        self._machine.restore(DefenseState.RELAXED, None)
        self._situations.reset()
        self._last_persisted_score = None

    # ── Internals ──────────────────────────────────────────────────────────

    def _observe(self, event: DetectionEvent, now: datetime) -> bool:
        """Fold one event into the evidence. False if malformed or already seen."""
        try:
            item = EvidenceItem.from_event(
                event, default_confidence=self._cfg.scoring.default_confidence
            )
        except ValueError:
            # A malformed row must not stop scoring of everything else.
            logger.warning("Threat: ignoring malformed detection event id=%s", event.id)
            return False
        return self._scorer.observe(item, now)

    def _floor(self, severity: Severity | None) -> DefenseState:
        if severity is Severity.CRITICAL:
            return self._cfg.state.floor_critical
        if severity is Severity.HIGH:
            return self._cfg.state.floor_high
        return DefenseState.RELAXED

    def _should_persist_score(self, score: float, changed: bool) -> bool:
        if changed or self._last_persisted_score is None:
            return True
        return abs(score - self._last_persisted_score) >= self._cfg.persist_min_delta

    async def _persist(
        self, breakdown: ScoreBreakdown, evaluation: StateEvaluation
    ) -> tuple[int | None, int | None]:
        persist_score = self._should_persist_score(breakdown.final_score, evaluation.changed)
        if not persist_score and not evaluation.changed:
            return None, None

        event_ids = [s.event_id for s in breakdown.signals if s.event_id is not None]
        score_id: int | None = None
        transition_id: int | None = None
        async with self._session_factory() as session, session.begin():
            if persist_score:
                row = await ThreatScoreRepository(session).insert(
                    ThreatScore(
                        calculated_at=breakdown.calculated_at,
                        score=breakdown.final_score,
                        contributing_events=json.dumps(event_ids),
                        defense_state=evaluation.new_state.value,
                        breakdown=json.dumps(breakdown.to_dict(), allow_nan=False, sort_keys=True),
                    )
                )
                score_id = row.id
            if evaluation.changed:
                change = await DefenseStateChangeRepository(session).insert(
                    DefenseStateChange(
                        changed_at=evaluation.evaluated_at,
                        from_state=evaluation.previous_state.value,
                        to_state=evaluation.new_state.value,
                        trigger_score=evaluation.score,
                        trigger_event_ids=json.dumps(event_ids),
                        previous_score=evaluation.previous_score,
                        reason=evaluation.reason_codes[0].value
                        if evaluation.reason_codes
                        else None,
                        evidence=json.dumps(
                            self._transition_evidence(breakdown, evaluation),
                            allow_nan=False,
                            sort_keys=True,
                        ),
                    )
                )
                transition_id = change.id
        if persist_score:
            self._last_persisted_score = breakdown.final_score
        return score_id, transition_id

    @staticmethod
    def _transition_evidence(
        breakdown: ScoreBreakdown, evaluation: StateEvaluation
    ) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "previous_state": evaluation.previous_state.value,
            "new_state": evaluation.new_state.value,
            "previous_score": evaluation.previous_score,
            "new_score": evaluation.score,
            "transition_reason_codes": [c.value for c in evaluation.reason_codes],
            "score_reason_codes": [c.value for c in breakdown.reason_codes],
            "triggering_signals": [s.to_dict() for s in breakdown.signals],
            "breakdown": breakdown.to_dict(),
        }
