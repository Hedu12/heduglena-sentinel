/**
 * Demo reset: a deliberate, two-step request to the backend. The dashboard never
 * changes any displayed state itself; after the backend answers, every panel is
 * re-read from the backend. The request carries no data.
 */

import { useState } from "react";

import { StateBadge } from "../../components/Badges";
import { describeError } from "../../components/DataState";
import { useLive } from "../../hooks/live";
import { useResetDemo } from "../../hooks/queries";
import { isApiError } from "../../services/http";

function resetError(error: unknown): string {
  if (isApiError(error, "conflict")) return "Reset not possible right now (409). See the backend log.";
  if (isApiError(error, "rate_limited")) return "Demo rate limit reached. Try again in a minute.";
  if (isApiError(error, "forbidden")) return "Demo mode is disabled on the backend (DEMO_MODE=false).";
  if (isApiError(error, "unavailable")) return "The runtime is not running yet.";
  return describeError(error);
}

export function ResetControl({ disabled }: { disabled: boolean }) {
  const [confirming, setConfirming] = useState(false);
  const live = useLive();
  const reset = useResetDemo();

  const confirm = () => {
    setConfirming(false);
    reset.mutate(undefined, { onSuccess: () => live.clearSession() });
  };

  return (
    <div className="reset">
      <p className="reset__explain">
        Reset archives this demo session intact and starts a clean one. The new state is
        decided by Sentinel&apos;s own startup restore from an empty history, never by this
        console.
      </p>
      {confirming ? (
        <div className="reset__confirm" role="group" aria-label="Confirm demo reset">
          <button type="button" className="button button--danger" onClick={confirm}>
            Confirm reset
          </button>
          <button type="button" className="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="button button--reset"
          disabled={disabled || reset.isPending}
          onClick={() => setConfirming(true)}
        >
          {reset.isPending ? "Resetting…" : "Reset demo session"}
        </button>
      )}
      <div role="status" aria-live="polite" className="reset__status">
        {reset.isSuccess ? (
          <p>
            New demo session started; previous session archived as{" "}
            <span className="mono">{reset.data.archived_session}</span>. Backend reports{" "}
            <StateBadge state={reset.data.defense_state} />.
          </p>
        ) : null}
        {reset.error ? <p className="data-state--error">{resetError(reset.error)}</p> : null}
      </div>
    </div>
  );
}
