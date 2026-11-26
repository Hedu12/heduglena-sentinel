/**
 * Badges always carry their meaning in text; color only reinforces it.
 */

import { STATE_COPY } from "../lib/format";
import type { DefenseState, GuardVerdict } from "../types/api";

export function StateBadge({ state, size = "md" }: { state: DefenseState; size?: "md" | "lg" }) {
  return (
    <span className={`badge badge--state state--${state.toLowerCase()} badge--${size}`}>
      <span className="badge__glyph" aria-hidden="true" />
      {STATE_COPY[state].label.toUpperCase()}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const level = severity.toLowerCase();
  return <span className={`badge badge--severity severity--${level}`}>{severity.toUpperCase()}</span>;
}

export function SimulatedBadge() {
  return (
    <span className="badge badge--simulated" title="Recorded by Sentinel; no host change was made">
      SIMULATED
    </span>
  );
}

export function SyntheticBadge() {
  return (
    <span className="badge badge--synthetic" title="Injected by the demo controls, not a real attack">
      SYNTHETIC · DEMO
    </span>
  );
}

export function RealBadge() {
  return (
    <span className="badge badge--real" title="Measured on this host">
      REAL HOST
    </span>
  );
}

const VERDICT_COPY: Record<GuardVerdict, string> = {
  AUTHORIZED: "Guard: authorized",
  DENIED: "Guard: denied",
  NOT_EVALUATED: "Guard: not evaluated",
};

export function GuardBadge({ verdict }: { verdict: GuardVerdict }) {
  return <span className={`badge badge--guard guard--${verdict.toLowerCase()}`}>{VERDICT_COPY[verdict]}</span>;
}

export function AiBadge() {
  return <span className="badge badge--ai">AI EXPLANATION</span>;
}
