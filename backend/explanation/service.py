"""
ExplanationService: observes decisions and explains them in the background.

    Decision ──observe()──> pending (coalesced per situation, bounded)
                                  │  background worker
                                  ▼
        trigger memory (read from ai_explanations) -> trigger policy
        -> context builder (read-only) -> Explainer -> ai_explanations (append-only)

One-way: the security pipeline may hand decisions to observe(); nothing here
returns anything the pipeline uses, and nothing in threat/ or response/ imports
this package. observe() is synchronous and cheap: it never awaits a provider,
never touches the database and never raises, so a slow, failing or disabled AI
cannot slow or change telemetry, detection, scoring, state transitions or
response simulation.

Restart-stable: whether a decision deserves an explanation is decided in the
worker against the persisted explanation records (trigger keys, decision times
and evidence marks), never against process memory. The database also enforces
one record per (incident, trigger key). A recovery to RELAXED, whose decision no
longer carries the situation id, is attributed to its situation by replaying the
persisted state transitions, so it is explained after a restart too.

Bounds:
  * at most one pending entry per situation; newer decisions are coalesced into it;
  * at most `ai_queue_max_incidents` pending entries; further ones are dropped;
  * one provider call at a time (a single worker), each limited by the
    explainer's timeout and attempt cap;
  * a context identical to the incident's last VALID explanation is not sent again.

Every attempt that reaches a provider, or fails to build its context, is
recorded (AS-07). A failed record holds the deterministic fallback text, never
model output; `content` is set only for VALID explanations.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai.explainer import Explainer, ExplanationOutcome
from ai.factory import build_provider, explainer_limits
from ai.protocols import LLMProvider
from core.config import Settings
from database.models import RAW_RESPONSE_MAX_CHARS, AIExplanationRecord
from database.repositories import AIExplanationRepository
from explanation import queries
from explanation.context_builder import ContextLimits, ExplanationContextBuilder, incident_ref
from explanation.fallback import fallback_explanation
from explanation.triggers import (
    CREATED_KEY,
    EvidenceMark,
    ExplanationTriggerPolicy,
    PendingExplanation,
    TriggerMemory,
    TriggerRequest,
)
from models.enums import DefenseState, ExplanationFailure, ExplanationStatus
from threat.decision import Decision
from threat.situation import SituationTracker

logger = logging.getLogger(__name__)

# How many earlier transitions are replayed to attribute a recovery to its situation
# (the same bound the threat service uses when it restores after a restart).
RECOVERY_REPLAY_LIMIT = 200


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class ExplanationStats:
    observed: int = 0
    coalesced: int = 0
    dropped: int = 0
    not_triggered: int = 0
    skipped_duplicate: int = 0
    recorded: int = 0
    record_failed: int = 0


class ExplanationService:
    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        provider: LLMProvider | None = None,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._session_factory = session_factory
        self._policy = ExplanationTriggerPolicy(
            aggressive_refresh_seconds=settings.ai_aggressive_refresh_seconds,
            evidence_score_delta=settings.ai_evidence_score_delta,
        )
        self._builder = ExplanationContextBuilder(
            session_factory, ContextLimits.from_settings(settings)
        )
        self._explainer = Explainer(
            provider or build_provider(settings), explainer_limits(settings), monotonic=monotonic
        )
        self._reopen_seconds = settings.threat_incident_reopen_seconds
        self._clock = clock
        self._max_pending = settings.ai_queue_max_incidents
        # Keyed "s<situation>" or, for a recovery not yet attributed, "r<transition>".
        self._pending: OrderedDict[str, PendingExplanation] = OrderedDict()
        # The situation of the previous decision: a shortcut for attributing a recovery.
        # Only a cache: without it (after a restart) the worker replays the transitions.
        self._current: int | None = None
        self._wake = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self.stats = ExplanationStats()

    @property
    def provider_name(self) -> str:
        return self._explainer.provider_name

    @property
    def pending(self) -> int:
        return len(self._pending)

    # ── Intake (called from the security pipeline; must stay cheap) ────────

    def observe(self, decision: Decision) -> bool:
        """
        Note a decision for possible explanation. True if it was queued. Never blocks,
        never raises, never changes the decision. Whether it is explained is decided
        later, against the persisted explanation records.
        """
        try:
            return self._observe(decision)
        except Exception:
            logger.error("AI: could not queue a decision for explanation", exc_info=True)
            return False

    def _observe(self, decision: Decision) -> bool:
        situation = decision.situation_id
        recovered = decision.state_changed and decision.defense_state is DefenseState.RELAXED
        if situation is None and recovered:
            situation = self._current
        self._current = decision.situation_id
        if situation is None and not recovered:
            return False
        if situation is not None:
            key = f"s{situation}"
        elif decision.transition_id is not None:
            key = f"r{decision.transition_id}"
        else:
            return False  # an unattributable, unpersisted recovery: nothing to explain
        self.stats.observed += 1
        queued = self._pending.get(key)
        if queued is not None:
            queued.absorb(decision)
            self.stats.coalesced += 1
        elif len(self._pending) >= self._max_pending:
            self.stats.dropped += 1
            logger.warning("AI: explanation queue full; decision dropped")
            return False
        else:
            self._pending[key] = PendingExplanation.start(situation, decision)
        self._wake.set()
        return True

    # ── Background worker ─────────────────────────────────────────────────

    def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run(), name="sentinel-ai-explanations")

    async def stop(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
            self._worker = None

    async def _run(self) -> None:
        while True:
            await self._wake.wait()
            self._wake.clear()
            await self.run_pending()

    async def run_pending(self) -> int:
        """Handle everything pending, oldest first. Returns how many entries were handled."""
        handled = 0
        while self._pending:
            _, entry = self._pending.popitem(last=False)
            handled += 1
            try:
                await self._process(entry)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.error("AI: explanation job failed unexpectedly", exc_info=True)
        return handled

    # ── One pending entry ─────────────────────────────────────────────────

    async def _process(self, entry: PendingExplanation) -> None:
        situation = entry.situation_id
        if situation is None:
            situation = await self._recovered_situation(entry.decision)
            if situation is None:
                return
        memory = await self._memory(situation, entry)
        if memory is None:
            return
        request = self._policy.decide(situation, entry, memory)
        if request is None:
            self.stats.not_triggered += 1
            return
        await self._explain(request)

    async def _memory(self, situation: int, entry: PendingExplanation) -> TriggerMemory | None:
        """What is already explained for the situation, from the database (authoritative)."""
        incident_id = incident_ref(situation)
        try:
            async with self._session_factory() as session:
                recorded = await queries.recorded_trigger_keys(session, incident_id, entry.keys())
                latest = await queries.latest_triggered_explanation(session, incident_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Fail closed: without the record of what is explained, explain nothing now.
            logger.warning("AI: could not read the explanation history", exc_info=True)
            return None
        last = (
            EvidenceMark.from_record(latest.decision_at, latest.evidence_state)
            if latest is not None and latest.decision_at is not None
            else None
        )
        return TriggerMemory(
            created=CREATED_KEY in recorded, explained=frozenset(recorded), last=last
        )

    async def _recovered_situation(self, decision: Decision) -> int | None:
        """The situation a recovery to RELAXED ended, by replaying persisted transitions."""
        if decision.transition_id is None:
            return None
        try:
            async with self._session_factory() as session:
                earlier = await queries.transitions_before(
                    session, decision.transition_id, RECOVERY_REPLAY_LIMIT
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("AI: could not attribute a recovery to its situation", exc_info=True)
            return None
        tracker = SituationTracker(self._reopen_seconds)
        for change in earlier:
            moment = change.changed_at
            tracker.apply(
                transition_id=change.id,
                previous=DefenseState(change.from_state),
                new=DefenseState(change.to_state),
                at=moment if moment.tzinfo else moment.replace(tzinfo=UTC),
            )
        situation = tracker.active_id
        if situation is None and earlier and earlier[-1].to_state != DefenseState.RELAXED.value:
            situation = earlier[0].id  # opened before the replayed window
        return situation

    async def _explain(self, request: TriggerRequest) -> None:
        incident_id = incident_ref(request.situation_id)
        try:
            context = await self._builder.build(
                request.trigger, request.decision, request.situation_id
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("AI: no explanation context for %s", incident_id, exc_info=True)
            outcome = ExplanationOutcome(
                status=ExplanationStatus.FAILED,
                provider=self._explainer.provider_name,
                failure=ExplanationFailure.CONTEXT_UNAVAILABLE,
                detail="context_build_failed",
            )
            await self._record(request, outcome, fingerprint=None)
            return

        fingerprint = context.fingerprint()
        if await self._already_explained(incident_id, fingerprint):
            self.stats.skipped_duplicate += 1
            return
        outcome = await self._explainer.explain(context)
        await self._record(request, outcome, fingerprint=fingerprint)

    async def _already_explained(self, incident_id: str, fingerprint: str) -> bool:
        try:
            async with self._session_factory() as session:
                latest = await queries.latest_valid_explanation(session, incident_id)
        except Exception:
            logger.warning("AI: could not check for a duplicate explanation", exc_info=True)
            return False
        return latest is not None and latest.context_fingerprint == fingerprint

    async def _record(
        self, request: TriggerRequest, outcome: ExplanationOutcome, *, fingerprint: str | None
    ) -> None:
        incident_id = incident_ref(request.situation_id)
        output = outcome.output if outcome.status is ExplanationStatus.VALID else None
        text = (
            output.summary
            if output is not None
            else fallback_explanation(
                incident_id,
                request.decision.defense_state.value,
                request.decision.threat_score,
            )
        )
        raw = outcome.raw_response[:RAW_RESPONSE_MAX_CHARS] if outcome.raw_response else None
        record = AIExplanationRecord(
            generated_at=self._clock(),
            incident_id=incident_id,
            provider=outcome.provider,
            explanation=text,
            model=outcome.model,
            prompt_tokens=outcome.prompt_tokens,
            response_tokens=outcome.response_tokens,
            raw_response=raw,  # audit artifact only; never displayed or reused
            situation_id=request.situation_id,
            trigger=request.trigger.value,
            status=outcome.status.value,
            failure_reason=outcome.failure.value if outcome.failure else None,
            failure_detail=outcome.detail,
            latency_ms=outcome.latency_ms,
            attempts=outcome.attempts,
            context_fingerprint=fingerprint,
            content=output.model_dump_json() if output is not None else None,
            trigger_key=request.trigger_key,
            decision_at=request.mark.decision_at,
            evidence_state=request.mark.to_json(),
        )
        try:
            async with self._session_factory() as session, session.begin():
                await AIExplanationRepository(session).insert(record)
        except asyncio.CancelledError:
            raise
        except IntegrityError:
            # Another worker (or a run before a restart) already explained this trigger.
            self.stats.skipped_duplicate += 1
            return
        except Exception:
            # Not retried here: the next decision is judged against what was recorded.
            self.stats.record_failed += 1
            logger.error("AI: could not record the explanation for %s", incident_id, exc_info=True)
            return
        self.stats.recorded += 1
        logger.info(
            "AI: %s explanation for %s (%s, %s, %d ms)",
            outcome.status.value,
            incident_id,
            request.trigger.value,
            outcome.provider,
            outcome.latency_ms,
        )
