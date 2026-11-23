"""
SimulatedActionExecutor: the only thing that "carries out" a response action.

Every handler is a pure function that returns a description of what the
action WOULD do. Nothing here touches the host: no processes, no network, no
files, no firewall. RECORD_INCIDENT is the one handler with an effect, and that
effect is an incident row in Sentinel's own database, written by the response
service in the same transaction as the action record.

Protection against accidental live execution, in layers:

  1. LIVE_EXECUTION_SUPPORTED is False and no live handler exists.
  2. ensure_simulated() refuses any verdict that is not simulated, or that the
     guard classed LIVE_PROTECTIVE, even if ResponseGuard allowed it (for
     example because LIVE_ACTIONS=true). The refusal is recorded as BLOCKED.
  3. The constructor rejects a handler table that does not cover every
     ActionType with a registered simulation, so a new ActionType cannot slip
     through without a reviewed handler.
  4. Static tests forbid process, network and filesystem calls in this package.

Enabling live response requires replacing this module after a security review;
it cannot be switched on by configuration.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from models.enums import ActionClass, ActionType, DefenseState
from response.actions import PlannedAction, incident_id_for
from response.guard import GuardVerdict
from threat.reasons import ReasonCode, reason_text

LIVE_EXECUTION_SUPPORTED = False


class LiveExecutionRefused(RuntimeError):
    """A verdict would have required live (non-simulated) execution."""


@dataclass(frozen=True, slots=True)
class IncidentSpec:
    """The incident row a RECORD_INCIDENT action creates (Sentinel's own data only)."""

    incident_id: str
    defense_state: DefenseState
    threat_score: float
    event_ids: tuple[int, ...]
    summary: str


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """
    What a simulated action would have done. Fails closed: a result that is not
    marked simulated, or that reports any host side effect, cannot be constructed.

    outcome is a fixed machine-readable code (for example WOULD_QUARANTINE);
    target names the kind of thing the real action would affect, never a real
    host identifier.
    """

    result: str
    dry_run_description: str
    outcome: str
    target: str
    incident: IncidentSpec | None = None
    simulated: bool = True
    side_effects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.simulated is not True:
            raise ValueError("a SimulationResult must be simulated")
        if self.side_effects:
            raise ValueError("a simulated action must report no host side effects")


Handler = Callable[[PlannedAction], SimulationResult]


def _situation(p: PlannedAction) -> str:
    return f"situation {p.situation_id}" if p.situation_id is not None else "no situation"


def _alert(p: PlannedAction) -> SimulationResult:
    return SimulationResult(
        result="alert recorded",
        outcome="WOULD_ALERT_OPERATOR",
        target="operator",
        dry_run_description=(
            f"Raise an operator alert: defense state {p.defense_state.value}, "
            f"threat score {p.threat_score:.2f}, {_situation(p)}."
        ),
    )


def _monitoring(p: PlannedAction) -> SimulationResult:
    return SimulationResult(
        result="simulated: monitoring increase recommended",
        outcome="WOULD_INCREASE_MONITORING",
        target="telemetry_collector",
        dry_run_description=(
            f"Halve the telemetry polling interval while in {p.defense_state.value} "
            f"({_situation(p)}). Simulation only: the interval is not changed."
        ),
    )


def _incident(p: PlannedAction) -> SimulationResult:
    if p.situation_id is None:
        raise ValueError("RECORD_INCIDENT requires a situation")
    codes = [ReasonCode(c) for c in p.reason_codes if c in ReasonCode.__members__]
    summary = "; ".join(reason_text(codes)) or "security situation opened"
    incident = IncidentSpec(
        incident_id=incident_id_for(p.situation_id),
        defense_state=p.defense_state,
        threat_score=p.threat_score,
        event_ids=p.evidence_event_ids,
        summary=summary,
    )
    return SimulationResult(
        result=f"incident {incident.incident_id} recorded",
        outcome="INCIDENT_RECORDED",
        target="sentinel_database",
        dry_run_description=f"Open incident {incident.incident_id} for {_situation(p)}.",
        incident=incident,
    )


def _simulated(description: str, outcome: str, target: str) -> Handler:
    def handler(p: PlannedAction) -> SimulationResult:
        return SimulationResult(
            result="simulated: no host change made",
            outcome=outcome,
            target=target,
            dry_run_description=f"{description} for {_situation(p)}. Simulation only.",
        )

    return handler


DEFAULT_HANDLERS: Mapping[ActionType, Handler] = {
    ActionType.GENERATE_ALERT: _alert,
    ActionType.INCREASE_MONITORING: _monitoring,
    ActionType.RECORD_INCIDENT: _incident,
    ActionType.SIMULATE_IP_BLOCK: _simulated(
        "Would block inbound traffic from the source implicated in the evidence",
        "WOULD_BLOCK_SOURCE",
        "network_source",
    ),
    ActionType.SIMULATE_PROCESS_ISOLATE: _simulated(
        "Would suspend and isolate the process implicated in the evidence",
        "WOULD_CONTAIN_PROCESS",
        "process",
    ),
    ActionType.SIMULATE_QUARANTINE: _simulated(
        "Would quarantine the resource implicated in the evidence",
        "WOULD_QUARANTINE",
        "host_resource",
    ),
}


class SimulatedActionExecutor:
    """Runs simulated handlers. Refuses anything that would need live execution."""

    def __init__(self, handlers: Mapping[ActionType, Handler] | None = None) -> None:
        table = dict(DEFAULT_HANDLERS if handlers is None else handlers)
        missing = set(ActionType) - set(table)
        if missing:
            raise ValueError(f"no simulated handler for: {sorted(a.value for a in missing)}")
        if LIVE_EXECUTION_SUPPORTED:  # pragma: no cover - deliberately unreachable
            raise RuntimeError("live execution is not implemented in this phase")
        self._handlers = table

    @staticmethod
    def ensure_simulated(verdict: GuardVerdict) -> None:
        """Raise LiveExecutionRefused unless the verdict describes a simulated action."""
        if verdict.action_class is ActionClass.LIVE_PROTECTIVE or not verdict.is_simulated:
            raise LiveExecutionRefused(
                f"refusing live execution ({verdict.action_class.value}); "
                "only simulated actions are supported"
            )

    def execute(self, planned: PlannedAction, verdict: GuardVerdict) -> SimulationResult:
        """Simulate one authorised action. Pure: returns a description, changes nothing."""
        self.ensure_simulated(verdict)
        return self._handlers[planned.action_type](planned)


def describe_parameters(planned: PlannedAction) -> str:
    """JSON parameters for the audit record."""
    return json.dumps(planned.parameters(), sort_keys=True)
