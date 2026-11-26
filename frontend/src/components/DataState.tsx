/**
 * Loading / empty / error states. An error never falls back to stale or
 * invented values: it says what is known and what is not.
 */

import type { ReactNode } from "react";

import { isApiError } from "../services/http";

export function Loading({ label }: { label: string }) {
  return (
    <p className="data-state data-state--loading" role="status">
      Loading {label}…
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="data-state data-state--empty">{children}</p>;
}

export function describeError(error: unknown): string {
  if (isApiError(error, "offline")) return "Backend offline — no data can be shown.";
  if (isApiError(error, "unavailable")) return "Runtime not ready yet (503).";
  if (isApiError(error, "not_found")) return "No data yet (404).";
  if (isApiError(error, "rate_limited")) return "Too many requests (429). Wait a moment.";
  if (isApiError(error, "forbidden")) return "Not allowed by the backend (403).";
  if (isApiError(error, "conflict")) return "Busy: an operation is already in progress (409).";
  return "The backend returned an error.";
}

export function Failure({ error }: { error: unknown }) {
  return (
    <p className="data-state data-state--error" role="alert">
      {describeError(error)}
    </p>
  );
}

interface QueryViewProps<T> {
  label: string;
  query: { data: T | undefined; error: unknown; isPending: boolean };
  empty?: (data: T) => ReactNode | null;
  children: (data: T) => ReactNode;
}

/** Render a query's data, or its loading / error / empty state. */
export function QueryView<T>({ label, query, empty, children }: QueryViewProps<T>) {
  if (query.data === undefined) {
    if (query.error) return <Failure error={query.error} />;
    return <Loading label={label} />;
  }
  const emptyView = empty?.(query.data);
  return (
    <>
      {query.error ? (
        <p className="data-state data-state--stale" role="status">
          Showing last known data. Latest refresh failed: {describeError(query.error)}
        </p>
      ) : null}
      {emptyView ?? children(query.data)}
    </>
  );
}
