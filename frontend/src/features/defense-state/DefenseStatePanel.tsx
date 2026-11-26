import { StateBadge } from "../../components/Badges";
import { Failure, Loading } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useLive, type TrendPoint } from "../../hooks/live";
import { useStatus } from "../../hooks/queries";
import { STATES, STATE_COPY, clock, score, stateIndex } from "../../lib/format";
import type { IncidentTransition } from "../../types/api";

function Trend({ points }: { points: TrendPoint[] }) {
  if (points.length < 2) {
    return <p className="trend__empty">The trend fills in while the live stream is connected.</p>;
  }
  const width = 240;
  const height = 56;
  const step = width / (points.length - 1);
  const path = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(height - p.score * height).toFixed(1)}`)
    .join(" ");
  const first = points[0];
  const last = points[points.length - 1];
  return (
    <figure className="trend">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Threat score trend from ${score(first?.score)} to ${score(last?.score)}`}
      >
        {[0.25, 0.55, 0.8].map((t) => (
          <line key={t} className="trend__threshold" x1="0" x2={width} y1={height - t * height} y2={height - t * height} />
        ))}
        <path className="trend__line" d={path} />
      </svg>
      <figcaption>Threat score this session (backend-reported values, {points.length} readings)</figcaption>
    </figure>
  );
}

export function DefenseStatePanel({ lastTransition }: { lastTransition: IncidentTransition | null }) {
  const live = useLive();
  const status = useStatus(live.status);

  let body;
  if (status.data === undefined) {
    body = status.error ? <Failure error={status.error} /> : <Loading label="defense state" />;
  } else {
    const current = status.data.defense_state;
    const level = stateIndex(current);
    body = (
      <div className={`defense state--${current.toLowerCase()}`}>
        <p className="sr-only" role="status" aria-live="polite">
          Defense state {STATE_COPY[current].label}
        </p>
        <div className="defense__headline">
          <div>
            <p className="defense__caption">Current defense state</p>
            <StateBadge state={current} size="lg" />
            <p className="defense__meaning">{STATE_COPY[current].meaning}</p>
          </div>
          <div className="defense__score">
            <p className="defense__caption">Threat score</p>
            <p className="defense__score-value">{score(status.data.threat_score)}</p>
            <p className="defense__score-scale">of 1.00 · decided {clock(status.data.timestamp)}</p>
          </div>
        </div>
        <ol className="ladder" aria-label="Defense states, lowest to highest">
          {STATES.map((state, i) => (
            <li
              key={state}
              className={`ladder__step state--${state.toLowerCase()} ${i === level ? "is-current" : ""} ${i < level ? "is-passed" : ""}`}
              aria-current={i === level ? "step" : undefined}
            >
              <span className="ladder__name">{STATE_COPY[state].label}</span>
              <span className="ladder__meaning">{STATE_COPY[state].meaning}</span>
            </li>
          ))}
        </ol>
        {lastTransition ? (
          <p className="defense__transition">
            Last transition: <StateBadge state={lastTransition.from_state} /> →{" "}
            <StateBadge state={lastTransition.to_state} /> at {clock(lastTransition.changed_at)} (score{" "}
            {score(lastTransition.trigger_score)})
          </p>
        ) : (
          <p className="defense__transition">No state transition recorded for the current incident.</p>
        )}
        <Trend points={live.trend} />
      </div>
    );
  }

  return (
    <Panel id="defense-state" title="Defense posture" stage="Decide" className="panel--hero">
      {body}
    </Panel>
  );
}
