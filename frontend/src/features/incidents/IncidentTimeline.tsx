/**
 * Incident timeline built only from GET /api/v1/incidents/{id}: evidence,
 * transitions, simulations and the explanation state. Nothing is invented on
 * the frontend; entries are just sorted by their backend timestamps.
 */

import type { ReactNode } from "react";

import { GuardBadge, SimulatedBadge, StateBadge, SyntheticBadge } from "../../components/Badges";
import { Empty } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { ACTION_LABELS, clock, humanize, parseTime, score } from "../../lib/format";
import type { IncidentDetail } from "../../types/api";

const STEPS = [
  "Detection",
  "Threat assessment",
  "State transition",
  "Decision",
  "Planned response",
  "Guard decision",
  "Simulated response",
  "AI explanation",
] as const;

type Step = (typeof STEPS)[number];
type Kind = "detect" | "decide" | "defend" | "explain";

interface Entry {
  at: string;
  kind: Kind;
  steps: Step[];
  body: ReactNode;
}

const MAX_ENTRIES = 40;

export function buildTimeline(detail: IncidentDetail): Entry[] {
  const entries: Entry[] = [];
  for (const e of detail.evidence) {
    entries.push({
      at: e.detected_at,
      kind: "detect",
      steps: ["Detection"],
      body: (
        <>
          <strong>{e.rule_name}</strong> detected {humanize(e.event_type)} ({e.severity}){" "}
          {e.is_synthetic ? <SyntheticBadge /> : null}
        </>
      ),
    });
  }
  for (const t of detail.transitions) {
    entries.push({
      at: t.changed_at,
      kind: "decide",
      steps: ["Threat assessment", "State transition", "Decision"],
      body: (
        <>
          Score <span className="mono">{score(t.trigger_score)}</span>: <StateBadge state={t.from_state} /> →{" "}
          <StateBadge state={t.to_state} />
          {t.reason ? <span className="timeline__reason">{t.reason.description}</span> : null}
        </>
      ),
    });
  }
  for (const s of detail.simulations) {
    entries.push({
      at: s.executed_at,
      kind: "defend",
      steps: ["Planned response", "Guard decision", "Simulated response"],
      body: (
        <>
          {ACTION_LABELS[s.action_type]} <GuardBadge verdict={s.guard_verdict} /> <SimulatedBadge />
          {s.simulation_outcome ? <span className="timeline__reason">{humanize(s.simulation_outcome)}</span> : null}
        </>
      ),
    });
  }
  const ai = detail.ai.explanation ?? detail.ai.latest_attempt;
  if (ai) {
    entries.push({
      at: ai.generated_at,
      kind: "explain",
      steps: ["AI explanation"],
      body: (
        <>
          {ai.status === "VALID" ? "Explanation recorded" : `Explanation attempt: ${humanize(ai.status)}`}
          {ai.trigger ? ` (${humanize(ai.trigger)})` : ""} — after the decision, never part of it
        </>
      ),
    });
  }
  const time = (iso: string) => parseTime(iso)?.getTime() ?? 0;
  return entries.sort((a, b) => time(a.at) - time(b.at)).slice(-MAX_ENTRIES);
}

export function IncidentTimeline({ detail }: { detail: IncidentDetail | null }) {
  return (
    <Panel
      id="timeline"
      title={detail ? `Incident ${detail.incident.incident_id} timeline` : "Incident timeline"}
      aside={detail ? <span className="chip">{humanize(detail.incident.status)}</span> : null}
    >
      {detail === null ? (
        <Empty>No incident recorded. Incidents open when Sentinel leaves RELAXED.</Empty>
      ) : (
        <>
          <ol className="timeline-legend" aria-label="Incident stages">
            {STEPS.map((step, i) => (
              <li key={step}>
                <span className="mono">{i + 1}</span> {step}
              </li>
            ))}
          </ol>
          <ol className="timeline">
            {buildTimeline(detail).map((entry, i) => (
              <li key={`${entry.at}-${i}`} className={`timeline__entry timeline__entry--${entry.kind}`}>
                <span className="timeline__time mono">{clock(entry.at)}</span>
                <span className="timeline__steps">
                  {entry.steps.map((s) => (
                    <span key={s} className="chip chip--step">
                      {STEPS.indexOf(s) + 1}. {s}
                    </span>
                  ))}
                </span>
                <span className="timeline__body">{entry.body}</span>
              </li>
            ))}
          </ol>
        </>
      )}
    </Panel>
  );
}
