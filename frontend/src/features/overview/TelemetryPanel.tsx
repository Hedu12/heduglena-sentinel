import { RealBadge } from "../../components/Badges";
import { QueryView } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useLive } from "../../hooks/live";
import { useRuntime, useTelemetry } from "../../hooks/queries";
import { clock, duration, percent, rate } from "../../lib/format";

function Metric({ label, value, meter }: { label: string; value: string; meter?: number | null }) {
  return (
    <div className="metric">
      <dt className="metric__label">{label}</dt>
      <dd className="metric__value">
        {value}
        {meter !== undefined && meter !== null ? (
          <meter className="metric__meter" min={0} max={100} low={70} high={90} optimum={10} value={meter} aria-label={`${label} ${value}`} />
        ) : null}
      </dd>
    </div>
  );
}

export function TelemetryPanel() {
  const live = useLive();
  const telemetry = useTelemetry(live.status);
  const runtime = useRuntime(live.status);

  return (
    <Panel id="telemetry" title="Host telemetry" stage="Sense" aside={<RealBadge />}>
      <QueryView label="telemetry" query={telemetry}>
        {(t) => (
          <>
            <dl className="metrics">
              <Metric label="CPU" value={percent(t.cpu_percent, 1)} meter={t.cpu_percent} />
              <Metric label="Memory" value={percent(t.memory_percent, 1)} meter={t.memory_percent} />
              <Metric label="Network out" value={rate(t.net_bytes_sent)} />
              <Metric label="Network in" value={rate(t.net_bytes_recv)} />
              <Metric label="Disk read" value={rate(t.disk_read_rate)} />
              <Metric label="Disk write" value={rate(t.disk_write_rate)} />
              <Metric label="Processes" value={t.process_count === null ? "—" : String(t.process_count)} />
              <Metric label="Sentinel uptime" value={duration(runtime.data?.started_at)} />
            </dl>
            <p className="panel__footnote">
              Sampled {clock(t.collected_at)}. These are real measurements of this host. Demo
              events never appear here; they are listed under Detections as SYNTHETIC.
            </p>
          </>
        )}
      </QueryView>
    </Panel>
  );
}
