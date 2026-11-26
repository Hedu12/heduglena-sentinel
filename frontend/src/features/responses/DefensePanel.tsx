import { GuardBadge, SimulatedBadge, StateBadge } from "../../components/Badges";
import { Empty, QueryView } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useLive } from "../../hooks/live";
import { useActions } from "../../hooks/queries";
import { ACTION_LABELS, clock, humanize } from "../../lib/format";
import type { ResponseSimulation } from "../../types/api";

function Simulated({ isSimulated }: { isSimulated: boolean }) {
  // Every action is simulated by design; anything else would be a backend fault to surface.
  return isSimulated ? <SimulatedBadge /> : <span className="badge badge--warning">NOT SIMULATED — REVIEW</span>;
}

function IncidentResponses({ simulations }: { simulations: ResponseSimulation[] }) {
  return (
    <ul className="responses">
      {simulations.map((s, i) => (
        <li key={`${s.executed_at}-${s.action_type}-${i}`} className="response">
          <div className="response__head">
            <span className="response__action">{ACTION_LABELS[s.action_type]}</span>
            <Simulated isSimulated={s.is_simulated} />
          </div>
          <div className="response__meta">
            <StateBadge state={s.defense_state} />
            <GuardBadge verdict={s.guard_verdict} />
            <span className="mono">{clock(s.executed_at)}</span>
            <span>Status: {humanize(s.status)}</span>
          </div>
          <p className="response__dry-run">
            <span className="response__dry-run-label">Would have:</span> {s.dry_run_description}
          </p>
          {s.simulation_outcome ? <p className="response__outcome">Outcome: {humanize(s.simulation_outcome)}</p> : null}
          {s.guard_reason ? <p className="response__outcome">Guard: {s.guard_reason}</p> : null}
        </li>
      ))}
    </ul>
  );
}

export function DefensePanel({ simulations }: { simulations: ResponseSimulation[] | null }) {
  const live = useLive();
  const actions = useActions(live.status);
  return (
    <Panel id="defense" title="Guarded responses" stage="Defend" aside={<SimulatedBadge />}>
      <p className="defense-note">
        Every response is planned by the ResponsePlanner, authorized by the ResponseGuard and carried
        out by the simulator. <strong>No firewall, process or file on this host is changed.</strong>
      </p>
      {simulations && simulations.length > 0 ? (
        <IncidentResponses simulations={[...simulations].reverse()} />
      ) : (
        <QueryView
          label="responses"
          query={actions}
          empty={(rows) => (rows.length === 0 ? <Empty>No responses yet.</Empty> : null)}
        >
          {(rows) => (
            <ul className="responses">
              {rows.map((a) => (
                <li key={a.id} className="response">
                  <div className="response__head">
                    <span className="response__action">{ACTION_LABELS[a.action_type]}</span>
                    <Simulated isSimulated={a.is_simulated} />
                  </div>
                  <div className="response__meta">
                    <StateBadge state={a.defense_state} />
                    <span className="mono">{clock(a.executed_at)}</span>
                    {a.incident_id ? <span>{a.incident_id}</span> : null}
                  </div>
                  <p className="response__dry-run">
                    <span className="response__dry-run-label">Would have:</span> {a.dry_run_description}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </QueryView>
      )}
    </Panel>
  );
}
