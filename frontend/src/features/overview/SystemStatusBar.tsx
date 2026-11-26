import { describeError } from "../../components/DataState";
import { useLive } from "../../hooks/live";
import { useHealth, useRuntime, useTelemetry } from "../../hooks/queries";
import { ago, clock, parseTime } from "../../lib/format";

type Level = "ok" | "warn" | "bad" | "unknown";

function Indicator({ label, value, level }: { label: string; value: string; level: Level }) {
  return (
    <li className={`indicator indicator--${level}`}>
      <span className="indicator__dot" aria-hidden="true" />
      <span className="indicator__label">{label}</span>
      <span className="indicator__value">{value}</span>
    </li>
  );
}

const LIVE_COPY = {
  open: ["Connected", "ok"],
  stale: ["Stale", "warn"],
  connecting: ["Connecting", "warn"],
  closed: ["Disconnected", "bad"],
} as const;

export function SystemStatusBar() {
  const live = useLive();
  const health = useHealth();
  const runtime = useRuntime(live.status);
  const telemetry = useTelemetry(live.status);

  let sentinel: [string, Level] = ["Loading", "unknown"];
  if (health.error) sentinel = ["Offline", "bad"];
  else if (health.data) sentinel = health.data.status === "ok" ? ["Online", "ok"] : ["Degraded", "warn"];

  const rt = runtime.data;
  const offline = sentinel[0] === "Offline";
  let monitoring: [string, Level] = ["Unknown", "unknown"];
  if (rt && !offline) {
    monitoring = rt.monitoring
      ? rt.healthy
        ? ["Running", "ok"]
        : [`Failing (${rt.consecutive_failures} cycles)`, "bad"]
      : ["Stopped", "bad"];
  } else if (runtime.error && !offline) {
    monitoring = [describeError(runtime.error), "warn"];
  }

  let telemetryState: [string, Level] = ["No data", "unknown"];
  const collected = parseTime(telemetry.data?.collected_at);
  if (collected && rt && !offline) {
    const age = (Date.now() - collected.getTime()) / 1000;
    telemetryState = age <= rt.poll_interval_seconds * 3 ? ["Fresh", "ok"] : [`Delayed (${ago(telemetry.data?.collected_at)})`, "warn"];
  }

  const [liveLabel, liveLevel] = LIVE_COPY[live.status];

  return (
    <div className="status-bar">
      <p className="sr-only" role="status" aria-live="polite">
        Sentinel {sentinel[0]}. Monitoring {monitoring[0]}.
      </p>
      <ul className="status-bar__list" aria-label="System status">
        <Indicator label="Sentinel" value={sentinel[0]} level={sentinel[1]} />
        <Indicator label="Monitoring" value={monitoring[0]} level={monitoring[1]} />
        <Indicator label="Telemetry" value={telemetryState[0]} level={telemetryState[1]} />
        <Indicator label="Live stream" value={offline ? "Unavailable" : liveLabel} level={offline ? "bad" : liveLevel} />
        <Indicator
          label="Last cycle"
          value={rt && !offline ? clock(rt.last_cycle_at) : "—"}
          level={rt && !offline ? "ok" : "unknown"}
        />
      </ul>
    </div>
  );
}
