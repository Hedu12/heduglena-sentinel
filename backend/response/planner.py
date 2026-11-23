"""
ResponsePlanner: turns a Decision's recommendations into planned actions.

Pure and deterministic: no I/O, no clock (the decision's own timestamp is the
action time), no execution. For each recommended action it decides:

  * the SCOPE that deduplicates it (see POLICIES);
  * scope_key        what cooldown and dedup are measured against;
  * once_key         set for once-per-scope actions (the database allows only one
                     SUCCEEDED row per once_key);
  * idempotency_key  one row per (scope, decision), so handling the same decision
                     twice can never produce a second record.

Deduplication uses the decision's situation_id, so "once" means once per
security situation, not once per evaluation or once per process lifetime.

Actions that must belong to a situation but arrive without one are planned with
a precondition failure and will be recorded as BLOCKED, never executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.enums import ActionType, DefenseState
from response.actions import PlannedAction, Scope
from threat.decision import Decision


@dataclass(frozen=True, slots=True)
class PlanEntry:
    """A planned action and, if it cannot run, why."""

    action: PlannedAction
    precondition_error: str | None = None


# How often each action may run. Protective simulations and incident recording
# happen once per situation; alerts and monitoring changes once per state entered.
POLICIES: dict[ActionType, Scope] = {
    ActionType.GENERATE_ALERT: Scope.PER_SITUATION_STATE,
    ActionType.INCREASE_MONITORING: Scope.PER_SITUATION_STATE,
    ActionType.RECORD_INCIDENT: Scope.PER_SITUATION,
    ActionType.SIMULATE_IP_BLOCK: Scope.PER_SITUATION,
    ActionType.SIMULATE_PROCESS_ISOLATE: Scope.PER_SITUATION,
    ActionType.SIMULATE_QUARANTINE: Scope.PER_SITUATION,
}

# Actions allowed outside a situation (for example evidence while RELAXED); they
# fall back to the COOLDOWN scope. Everything else requires a situation.
ALLOWED_WITHOUT_SITUATION: frozenset[ActionType] = frozenset({ActionType.GENERATE_ALERT})


@dataclass(frozen=True, slots=True)
class ResponsePlanner:
    """Stateless: the same decision always yields the same plan."""

    policies: dict[ActionType, Scope] = field(default_factory=lambda: dict(POLICIES))

    def plan(self, decision: Decision) -> list[PlanEntry]:
        signals = decision.breakdown.signals
        triggering = signals[0].event_id if signals else None
        evidence_ids = tuple(s.event_id for s in signals if s.event_id is not None)
        reasons = tuple(code.value for code in decision.reason_codes)
        entries: list[PlanEntry] = []
        for action in decision.recommended_actions:
            scope, scope_key, once_key, error = self._scope(
                action, decision.situation_id, decision.defense_state
            )
            planned = PlannedAction(
                action_type=action,
                defense_state=decision.defense_state,
                planned_at=decision.calculated_at,
                situation_id=decision.situation_id,
                scope=scope,
                scope_key=scope_key,
                once_key=once_key,
                idempotency_key=f"{scope_key}@{decision.calculated_at.isoformat()}",
                triggering_event_id=triggering,
                threat_score=decision.threat_score,
                reason_codes=reasons,
                evidence_event_ids=evidence_ids,
            )
            entries.append(PlanEntry(planned, error))
        return entries

    def _scope(
        self, action: ActionType, situation_id: int | None, state: DefenseState
    ) -> tuple[Scope, str, str | None, str | None]:
        policy = self.policies.get(action)
        if policy is None:
            key = f"unplanned:{action.value}"
            return Scope.PER_SITUATION, key, None, f"no response policy for {action.value}"
        if situation_id is None:
            key = f"global:{action.value}"
            if action in ALLOWED_WITHOUT_SITUATION:
                return Scope.COOLDOWN, key, None, None
            return policy, key, None, f"{action.value} requires a security situation"
        if policy is Scope.PER_SITUATION_STATE:
            key = f"s{situation_id}:{action.value}:{state.value}"
        else:
            key = f"s{situation_id}:{action.value}"
        return policy, key, key, None
