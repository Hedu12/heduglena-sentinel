import { RealBadge, SeverityBadge, SyntheticBadge } from "../../components/Badges";
import { Empty, QueryView } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useLive } from "../../hooks/live";
import { useEvents } from "../../hooks/queries";
import { clock, fraction, humanize } from "../../lib/format";

export function DetectionsPanel() {
  const live = useLive();
  const events = useEvents(live.status);

  return (
    <Panel id="detections" title="Recent detections" stage="Detect">
      <QueryView
        label="detections"
        query={events}
        empty={(rows) => (rows.length === 0 ? <Empty>No detections yet. Sentinel is watching.</Empty> : null)}
      >
        {(rows) => (
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Detections table">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Detection</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Classification</th>
                  <th scope="col">Source</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{clock(e.detected_at)}</td>
                    <td>
                      <span className="cell__primary">{e.rule_name}</span>
                      <span className="cell__secondary">{humanize(e.event_type)}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={e.severity} />
                    </td>
                    <td>{fraction(e.confidence)}</td>
                    <td>{humanize(e.classification)}</td>
                    <td>{e.is_synthetic ? <SyntheticBadge /> : <RealBadge />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
    </Panel>
  );
}
