import type { ReactNode } from "react";

import { SimulatedBadge } from "../../components/Badges";
import { Panel } from "../../components/Panel";
import { useLive } from "../../hooks/live";
import { useActions, useEvents, useStatus, useTelemetry } from "../../hooks/queries";
import { ACTION_LABELS, STATE_COPY, clock, humanize, parseTime, score } from "../../lib/format";
import type { ExplanationState, LiveMessageType } from "../../types/api";

const ACTIVE_FOR_MS = 8_000;

interface Stage {
  key: string;
  verb: string;
  name: string;
  owner: string;
  live: LiveMessageType | null;
  detail: ReactNode;
}

const AVAILABILITY_COPY = {
  AVAILABLE: "Explanation available",
  PENDING: "Explanation pending",
  UNAVAILABLE: "Fallback text shown",
} as const;

export function PipelinePanel({ ai }: { ai: ExplanationState | null }) {
  const live = useLive();
  const telemetry = useTelemetry(live.status);
  const events = useEvents(live.status);
  const status = useStatus(live.status);
  const actions = useActions(live.status);
  const now = Date.now();

  const latestEvent = events.data?.[0];
  const latestAction = actions.data?.[0];
  const stages: Stage[] = [
    {
      key: "telemetry",
      verb: "Sense",
      name: "Telemetry",
      owner: "Host collector",
      live: "telemetry",
      detail: telemetry.data ? `Sample at ${clock(telemetry.data.collected_at)}` : "No sample yet",
    },
    {
      key: "detection",
      verb: "Detect",
      name: "Detection",
      owner: "Rule engine",
      live: "detection_event",
      detail: latestEvent ? `${latestEvent.rule_name} · ${humanize(latestEvent.event_type)}` : "No detections",
    },
    {
      key: "analysis",
      verb: "Analyze",
      name: "Threat analysis",
      owner: "Deterministic scorer",
      live: "threat_score",
      detail: status.data ? `Score ${score(status.data.threat_score)}` : "Awaiting first decision",
    },
    {
      key: "decision",
      verb: "Decide",
      name: "Decision",
      owner: "State machine",
      live: "defense_state_change",
      detail: status.data ? STATE_COPY[status.data.defense_state].label : "—",
    },
    {
      key: "defense",
      verb: "Defend",
      name: "Defense",
      owner: "Planner → Guard → Simulator",
      live: "response_action",
      detail: latestAction ? (
        <>
          {ACTION_LABELS[latestAction.action_type]} <SimulatedBadge />
        </>
      ) : (
        "No responses"
      ),
    },
    {
      key: "explain",
      verb: "Explain",
      name: "AI explanation",
      owner: "Explanation layer (downstream)",
      live: null,
      detail: ai ? AVAILABILITY_COPY[ai.availability] : "No incident to explain",
    },
  ];

  return (
    <Panel id="pipeline" title="Security pipeline" aside={<span className="panel__hint">Detect → Analyze → Decide → Defend → Explain</span>}>
      <ol className="pipeline">
        {stages.map((stage) => {
          const seen = stage.live ? parseTime(live.lastSeen[stage.live]) : null;
          const active = seen !== null && now - seen.getTime() < ACTIVE_FOR_MS;
          return (
            <li key={stage.key} className={`pipeline__stage pipeline__stage--${stage.key} ${active ? "is-active" : ""}`}>
              <span className="pipeline__verb">{stage.verb}</span>
              <span className="pipeline__name">{stage.name}</span>
              <span className="pipeline__owner">{stage.owner}</span>
              <span className="pipeline__detail">{stage.detail}</span>
              {active ? <span className="sr-only">recent activity</span> : null}
            </li>
          );
        })}
      </ol>
      <p className="pipeline__note">
        <strong>AI explains security decisions; it does not make them.</strong> Scoring, the defense
        state and every response are decided by deterministic code before the AI layer sees them.
      </p>
    </Panel>
  );
}
