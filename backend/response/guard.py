"""
Response guard.

The single point of authorization for all response actions.
No action may execute without passing through this guard.
See P-05 (Explicit Simulation Boundary) and SR-01.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from core.config import Settings
from models.enums import ActionClass, ActionType, DefenseState

logger = logging.getLogger(__name__)

# Maps each action type to its class and the minimum state that permits it.
_ACTION_REGISTRY: dict[ActionType, tuple[ActionClass, DefenseState]] = {
    ActionType.GENERATE_ALERT: (ActionClass.INFORMATIONAL, DefenseState.RELAXED),
    ActionType.INCREASE_MONITORING: (ActionClass.MONITORING, DefenseState.ALERT),
    ActionType.RECORD_INCIDENT: (ActionClass.MONITORING, DefenseState.ALERT),
    ActionType.SIMULATE_IP_BLOCK: (ActionClass.SIMULATED_PROTECTIVE, DefenseState.DEFENSIVE),
    ActionType.SIMULATE_PROCESS_ISOLATE: (ActionClass.SIMULATED_PROTECTIVE, DefenseState.DEFENSIVE),
    ActionType.SIMULATE_QUARANTINE: (ActionClass.SIMULATED_PROTECTIVE, DefenseState.AGGRESSIVE),
}

# Ordered list of states for minimum-state comparison.
_STATE_ORDER = [
    DefenseState.RELAXED,
    DefenseState.ALERT,
    DefenseState.DEFENSIVE,
    DefenseState.AGGRESSIVE,
]


@dataclass
class GuardVerdict:
    allowed: bool
    is_simulated: bool
    reason: str
    action_class: ActionClass


@dataclass
class ResponseGuard:
    """
    Authorizes response actions.

    Checks:
        1. Is the action registered?
        2. Is the current defense state sufficient?
        3. For LIVE_PROTECTIVE: is LIVE_ACTIONS=true?
        4. Is the action past its cooldown window?

    Sets is_simulated=True for SIMULATED_PROTECTIVE actions unconditionally.
    """

    settings: Settings
    _last_fired: dict[ActionType, datetime] = field(default_factory=dict, init=False)

    def evaluate(
        self,
        action: ActionType,
        current_state: DefenseState,
        cooldown_seconds: float = 60.0,
    ) -> GuardVerdict:
        """
        Evaluate whether an action may execute.

        Returns a GuardVerdict. Callers should check verdict.allowed before
        executing. Never raises; failures are expressed as denied verdicts.
        """
        if action not in _ACTION_REGISTRY:
            return GuardVerdict(
                allowed=False,
                is_simulated=True,
                reason=f"Unknown action type: {action!r}",
                action_class=ActionClass.INFORMATIONAL,
            )

        action_class, min_state = _ACTION_REGISTRY[action]

        # Check minimum defense state.
        if _STATE_ORDER.index(current_state) < _STATE_ORDER.index(min_state):
            return GuardVerdict(
                allowed=False,
                is_simulated=True,
                reason=(
                    f"{action.value} requires state ≥ {min_state.value}, "
                    f"current state is {current_state.value}"
                ),
                action_class=action_class,
            )

        # Block LIVE_PROTECTIVE unless explicitly enabled.
        if action_class == ActionClass.LIVE_PROTECTIVE and not self.settings.live_actions:
            return GuardVerdict(
                allowed=False,
                is_simulated=True,
                reason="LIVE_ACTIONS=false; live protective actions are disabled",
                action_class=action_class,
            )

        # Cooldown check.
        last = self._last_fired.get(action)
        if last is not None:
            elapsed = (datetime.now(UTC) - last).total_seconds()
            if elapsed < cooldown_seconds:
                return GuardVerdict(
                    allowed=False,
                    is_simulated=action_class != ActionClass.LIVE_PROTECTIVE,
                    reason=(
                        f"{action.value} is in cooldown "
                        f"({cooldown_seconds - elapsed:.1f}s remaining)"
                    ),
                    action_class=action_class,
                )

        is_simulated = action_class in (
            ActionClass.INFORMATIONAL,
            ActionClass.MONITORING,
            ActionClass.SIMULATED_PROTECTIVE,
        )

        return GuardVerdict(
            allowed=True,
            is_simulated=is_simulated,
            reason="Authorized",
            action_class=action_class,
        )

    def record_fired(self, action: ActionType) -> None:
        """Record that an action fired, for cooldown tracking."""
        self._last_fired[action] = datetime.now(UTC)
