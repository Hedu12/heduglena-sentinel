/**
 * DEMO MODE controls. Scenarios start only when a person presses a button;
 * nothing here runs on page load. The backend injects synthetic security events
 * through the same detection pipeline as real telemetry. The dashboard cannot
 * set the defense state; the reset (ResetControl) asks the backend to start a new
 * session, whose state the backend establishes itself.
 */

import { SimulatedBadge, StateBadge, SyntheticBadge } from "../../components/Badges";
import { describeError } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useLive } from "../../hooks/live";
import { useRuntime, useScenarios, useStartScenario, useStatus } from "../../hooks/queries";
import { isApiError } from "../../services/http";
import { clock, humanize } from "../../lib/format";
import type { ScenarioName } from "../../types/api";
import { ResetControl } from "./ResetControl";

const ORDER: { name: ScenarioName; label: string; expect: string }[] = [
  { name: "normal", label: "Normal", expect: "Stays RELAXED; no synthetic events" },
  {
    name: "suspicious",
    label: "Suspicious",
    expect: "Failed logins → ALERT or DEFENSIVE (AGGRESSIVE if a real host signal corroborates)",
  },
  { name: "critical", label: "Critical", expect: "Corroborated attack → AGGRESSIVE" },
];

function startError(error: unknown): string {
  if (isApiError(error, "conflict")) return "A scenario is already running. Wait for it to finish.";
  if (isApiError(error, "rate_limited")) return "Demo rate limit reached. Try again in a minute.";
  if (isApiError(error, "forbidden")) return "Demo mode is disabled on the backend (DEMO_MODE=false).";
  if (isApiError(error, "not_found")) return "The backend does not know this scenario.";
  if (isApiError(error, "unavailable")) return "The runtime is not running yet.";
  return describeError(error);
}

export function DemoPanel({ simulatedCount }: { simulatedCount: number }) {
  const live = useLive();
  const scenarios = useScenarios();
  const runtime = useRuntime(live.status);
  const status = useStatus(live.status);
  const start = useStartScenario();

  const disabled = isApiError(scenarios.error, "forbidden");
  const offline = isApiError(scenarios.error, "offline");
  const running = runtime.data?.demo_running ?? null;
  const last = runtime.data?.last_demo_run ?? null;
  const busy = start.isPending || running !== null;
  const descriptions = new Map(scenarios.data?.map((s) => [s.name, s.description]));

  let progress = "No scenario run yet.";
  if (running) progress = `Scenario ${humanize(running)} is running…`;
  else if (start.isPending) progress = "Starting scenario…";
  else if (last) {
    progress = `Scenario ${humanize(last.name)} ${last.status} at ${clock(last.finished_at ?? last.started_at)}: ${last.events_injected} synthetic events, ${last.detections} detections.`;
  }

  return (
    <Panel id="demo" title="DEMO MODE" className="panel--demo" aside={<SyntheticBadge />}>
      <p className="demo__note">
        Demo scenarios inject <strong>synthetic</strong> security events into the real pipeline. No
        attack is performed and every response stays simulated.
      </p>
      {disabled ? (
        <p className="data-state data-state--empty">Demo mode is disabled on the backend (DEMO_MODE=false).</p>
      ) : offline ? (
        <p className="data-state data-state--error" role="alert">
          Backend offline — demo controls unavailable.
        </p>
      ) : (
        <div className="demo__buttons" role="group" aria-label="Demo scenarios">
          {ORDER.map((s) => (
            <button
              key={s.name}
              type="button"
              className={`button button--scenario button--${s.name}`}
              disabled={busy || scenarios.data === undefined}
              onClick={() => start.mutate(s.name)}
              title={descriptions.get(s.name) ?? s.expect}
            >
              <span className="button__label">{s.label}</span>
              <span className="button__hint">{s.expect}</span>
            </button>
          ))}
        </div>
      )}
      <div className="demo__status" role="status" aria-live="polite">
        <p>{progress}</p>
        {start.isSuccess && !running && !last ? <p>Scenario {humanize(start.data.scenario)} started.</p> : null}
        {start.error ? <p className="data-state--error">{startError(start.error)}</p> : null}
      </div>
      <dl className="demo__result">
        <div>
          <dt>Resulting defense state</dt>
          <dd>{status.data ? <StateBadge state={status.data.defense_state} /> : "—"}</dd>
        </div>
        <div>
          <dt>Simulated responses (current incident)</dt>
          <dd>
            {simulatedCount} <SimulatedBadge />
          </dd>
        </div>
      </dl>
      {disabled || offline ? null : <ResetControl disabled={start.isPending} />}
      <p className="panel__footnote">
        The dashboard cannot set the defense state. Without a reset, Sentinel returns to RELAXED
        on its own as the evidence decays, as decided by its state machine.
      </p>
    </Panel>
  );
}
