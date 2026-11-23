"""
Security tests for ResponseGuard.

Verifies the simulation boundary: simulated actions are always allowed
at the right state level, live actions are blocked when LIVE_ACTIONS=false,
and cooldown windows are enforced.

See P-05, SR-01, and testing-requirements.md §Response guard.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from core.config import Settings
from models.enums import ActionType, DefenseState
from response.guard import ResponseGuard


def _guard(live_actions: bool = False) -> ResponseGuard:
    """Return a ResponseGuard with controlled settings."""
    settings = MagicMock(spec=Settings)
    settings.live_actions = live_actions
    return ResponseGuard(settings=settings)


class TestSimulatedActionsAllowed:
    def test_simulate_ip_block_allowed_at_defensive(self) -> None:
        guard = _guard(live_actions=False)
        verdict = guard.evaluate(ActionType.SIMULATE_IP_BLOCK, DefenseState.DEFENSIVE)
        assert verdict.allowed is True
        assert verdict.is_simulated is True

    def test_simulate_quarantine_allowed_at_aggressive(self) -> None:
        guard = _guard(live_actions=False)
        verdict = guard.evaluate(ActionType.SIMULATE_QUARANTINE, DefenseState.AGGRESSIVE)
        assert verdict.allowed is True
        assert verdict.is_simulated is True

    def test_generate_alert_allowed_at_relaxed(self) -> None:
        guard = _guard()
        verdict = guard.evaluate(ActionType.GENERATE_ALERT, DefenseState.RELAXED)
        assert verdict.allowed is True

    def test_increase_monitoring_allowed_at_alert(self) -> None:
        guard = _guard()
        verdict = guard.evaluate(ActionType.INCREASE_MONITORING, DefenseState.ALERT)
        assert verdict.allowed is True


class TestStateMinimumEnforcement:
    def test_simulate_ip_block_blocked_below_defensive(self) -> None:
        guard = _guard()
        verdict = guard.evaluate(ActionType.SIMULATE_IP_BLOCK, DefenseState.ALERT)
        assert verdict.allowed is False
        assert "DEFENSIVE" in verdict.reason

    def test_simulate_quarantine_blocked_below_aggressive(self) -> None:
        guard = _guard()
        verdict = guard.evaluate(ActionType.SIMULATE_QUARANTINE, DefenseState.DEFENSIVE)
        assert verdict.allowed is False

    def test_increase_monitoring_blocked_at_relaxed(self) -> None:
        guard = _guard()
        verdict = guard.evaluate(ActionType.INCREASE_MONITORING, DefenseState.RELAXED)
        assert verdict.allowed is False


class TestLiveActionsGuard:
    def test_live_actions_false_blocks_live_protective(self) -> None:
        """
        LIVE_PROTECTIVE actions must be blocked when LIVE_ACTIONS=false.
        This is the core security invariant of SR-01.
        """
        # NOTE: LIVE_PROTECTIVE actions are not yet in the registry
        # (they require LIVE_ACTIONS=true hardware integration).
        # This test documents the invariant and will be extended when
        # live action handlers are implemented.
        guard = _guard(live_actions=False)
        # All currently registered actions are SIMULATED_PROTECTIVE or below,
        # so is_simulated must be True for all of them when live_actions=False.
        for action in [
            ActionType.SIMULATE_IP_BLOCK,
            ActionType.SIMULATE_PROCESS_ISOLATE,
            ActionType.SIMULATE_QUARANTINE,
        ]:
            verdict = guard.evaluate(action, DefenseState.AGGRESSIVE)
            assert verdict.is_simulated is True, (
                f"{action.value} must be simulated when LIVE_ACTIONS=false"
            )


class TestCooldown:
    def test_action_blocked_within_cooldown(self) -> None:
        guard = _guard()
        guard.record_fired(ActionType.GENERATE_ALERT)
        # Same action immediately after firing should be blocked by cooldown.
        verdict = guard.evaluate(
            ActionType.GENERATE_ALERT,
            DefenseState.RELAXED,
            cooldown_seconds=60.0,
        )
        assert verdict.allowed is False
        assert "cooldown" in verdict.reason.lower()

    def test_action_allowed_after_cooldown_expires(self) -> None:
        guard = _guard()
        # Simulate that the action fired 120 seconds ago.
        past = datetime.now(UTC) - timedelta(seconds=120)
        guard._last_fired[ActionType.GENERATE_ALERT] = past

        verdict = guard.evaluate(
            ActionType.GENERATE_ALERT,
            DefenseState.RELAXED,
            cooldown_seconds=60.0,
        )
        assert verdict.allowed is True

    def test_cooldown_does_not_affect_different_actions(self) -> None:
        guard = _guard()
        guard.record_fired(ActionType.GENERATE_ALERT)
        # A different action should not be affected by GENERATE_ALERT's cooldown.
        verdict = guard.evaluate(
            ActionType.RECORD_INCIDENT,
            DefenseState.ALERT,
            cooldown_seconds=60.0,
        )
        assert verdict.allowed is True


class TestUnknownAction:
    def test_unknown_action_denied(self) -> None:
        guard = _guard()
        fake_action = MagicMock(spec=ActionType)
        fake_action.__str__ = lambda s: "UNKNOWN_ACTION"
        verdict = guard.evaluate(fake_action, DefenseState.AGGRESSIVE)  # type: ignore[arg-type]
        assert verdict.allowed is False
