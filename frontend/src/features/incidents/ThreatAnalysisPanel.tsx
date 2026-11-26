import { StateBadge } from "../../components/Badges";
import { Empty } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { clock, humanize, score } from "../../lib/format";
import type { ScoreBreakdown } from "../../types/api";

const FACTORS: { key: keyof ScoreBreakdown; label: string; hint: string }[] = [
  { key: "severity", label: "Severity", hint: "How serious the strongest evidence is" },
  { key: "confidence", label: "Confidence", hint: "How certain the detections are" },
  { key: "repetition", label: "Repetition", hint: "The same signal recurring" },
  { key: "escalation", label: "Escalation", hint: "Signals getting worse" },
  { key: "correlation", label: "Correlation", hint: "Several signals together" },
  { key: "cross_domain", label: "Cross-domain", hint: "Evidence from independent categories" },
  { key: "decay", label: "Decay", hint: "Weight lost as evidence ages" },
];

function Factor({ label, hint, value }: { label: string; hint: string; value: number }) {
  // Width is presentation only: the value shown is the backend's, unchanged.
  const width = `${Math.max(0, Math.min(1, value)) * 100}%`;
  return (
    <li className="factor">
      <span className="factor__label">
        {label}
        <span className="factor__hint">{hint}</span>
      </span>
      <span className="factor__bar" aria-hidden="true">
        <span className="factor__fill" style={{ width }} />
      </span>
      <span className="factor__value mono">{score(value)}</span>
    </li>
  );
}

export function ThreatAnalysisPanel({ breakdown }: { breakdown: ScoreBreakdown | null }) {
  return (
    <Panel id="analysis" title="Why this threat score" stage="Analyze">
      {breakdown === null ? (
        <Empty>
          No active incident. The score breakdown is reported by the backend for an open incident.
        </Empty>
      ) : (
        <>
          <p className="analysis__summary">
            Score <strong className="mono">{score(breakdown.score)}</strong>
            {breakdown.defense_state ? (
              <>
                {" "}
                → <StateBadge state={breakdown.defense_state} />
              </>
            ) : null}{" "}
            at {clock(breakdown.calculated_at)}
          </p>
          <ul className="factors" aria-label="Score contributions reported by the backend">
            {FACTORS.map((f) => (
              <Factor key={f.key} label={f.label} hint={f.hint} value={breakdown[f.key] as number} />
            ))}
          </ul>
          {breakdown.active_categories.length > 0 ? (
            <p className="analysis__categories">
              Active signal categories:{" "}
              {breakdown.active_categories.map((c) => (
                <span key={c} className="chip">
                  {humanize(c)}
                </span>
              ))}
            </p>
          ) : null}
          {breakdown.reasons.length > 0 ? (
            <ul className="reasons" aria-label="Reasons">
              {breakdown.reasons.map((r) => (
                <li key={r.code}>{r.description}</li>
              ))}
            </ul>
          ) : null}
          <p className="panel__footnote">Computed by Sentinel's deterministic scorer and shown as reported.</p>
        </>
      )}
    </Panel>
  );
}
