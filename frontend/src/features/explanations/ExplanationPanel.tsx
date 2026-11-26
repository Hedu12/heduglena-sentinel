import { AiBadge } from "../../components/Badges";
import { Empty } from "../../components/DataState";
import { Panel } from "../../components/Panel";
import { useAiStatus } from "../../hooks/queries";
import { clock, humanize } from "../../lib/format";
import type { ExplanationState } from "../../types/api";

function ProviderNote() {
  const status = useAiStatus();
  if (!status.data) return null;
  return (
    <p className="panel__footnote">
      Provider: {status.data.language_model_configured ? status.data.provider : "deterministic template (no language model)"}
    </p>
  );
}

export function ExplanationPanel({ ai }: { ai: ExplanationState | null }) {
  let body;
  if (ai === null) {
    body = <Empty>No incident to explain yet.</Empty>;
  } else if (ai.availability === "AVAILABLE" && ai.explanation?.content) {
    const { content } = ai.explanation;
    body = (
      <article className="explanation" aria-label={`Explanation for ${ai.incident_id}`}>
        <p className="explanation__summary">{content.summary}</p>
        <dl className="explanation__fields">
          <dt>What happened</dt>
          <dd>{content.what_happened}</dd>
          <dt>Why it matters</dt>
          <dd>{content.why_it_matters}</dd>
          <dt>Current state</dt>
          <dd>{content.current_state}</dd>
          <dt>Recommended human attention</dt>
          <dd>{content.recommended_human_attention}</dd>
        </dl>
        {content.evidence.length > 0 ? (
          <>
            <h3 className="explanation__subhead">Evidence cited</h3>
            <ul className="explanation__evidence">
              {content.evidence.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
            </ul>
          </>
        ) : null}
        <p className="panel__footnote">
          Status: validated · confidence {humanize(content.confidence)} · generated {clock(ai.explanation.generated_at)}
          {ai.explanation.trigger ? ` · trigger ${humanize(ai.explanation.trigger)}` : ""}
        </p>
      </article>
    );
  } else if (ai.availability === "PENDING") {
    body = (
      <div className="explanation">
        <p className="explanation__pending" role="status">Explanation pending</p>
        <p className="explanation__fallback">{ai.fallback_text}</p>
      </div>
    );
  } else {
    body = (
      <div className="explanation">
        <p className="explanation__pending">
          No validated explanation{ai.latest_attempt?.failure_reason ? ` (${humanize(ai.latest_attempt.failure_reason)})` : ""}.
          Deterministic summary, not AI:
        </p>
        <p className="explanation__fallback">{ai.fallback_text}</p>
      </div>
    );
  }

  return (
    <Panel id="explanation" title="Incident explanation" stage="Explain" aside={<AiBadge />}>
      <p className="ai-note">
        The AI explanation layer is downstream of the security decision and cannot modify threat
        scoring, defense state, or response actions.
      </p>
      {body}
      <ProviderNote />
    </Panel>
  );
}
