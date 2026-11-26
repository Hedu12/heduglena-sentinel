/**
 * Server-state hooks (React Query). All are reads, except useStartScenario,
 * which a person triggers deliberately.
 *
 * Polling is bounded and adapts to the live stream: while the WebSocket is open,
 * lists refresh when a live event says they changed, plus a slow safety
 * refresh; while it is down, they poll at a modest fixed interval. Health is
 * always polled, because it is what tells the dashboard the backend is offline.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { isApiError } from "../services/http";
import { api } from "../services/api";
import type { LiveStatus } from "../services/live";
import type { IncidentSummary, ScenarioName } from "../types/api";

export const keys = {
  health: ["health"],
  status: ["status"],
  runtime: ["runtime"],
  state: ["state"],
  telemetry: ["telemetry"],
  events: ["events"],
  actions: ["actions"],
  incidents: ["incidents"],
  incidentRoot: ["incident"],
  incident: (id: string) => ["incident", id],
  aiStatus: ["ai-status"],
  scenarios: ["scenarios"],
} as const;

const LIVE_SAFETY_MS = 30_000;
// AC-F07-1: data refreshes at ≤ 2 s. Used only while the live stream is down.
const FALLBACK_MS = 2_000;

export const pollFor = (live: LiveStatus): number => (live === "open" ? LIVE_SAFETY_MS : FALLBACK_MS);

// Missing data (404/503) is a state to display, not an error worth retrying.
const retry = (count: number, error: unknown): boolean =>
  count < 1 && !isApiError(error, "not_found") && !isApiError(error, "unavailable");

export const useHealth = () =>
  useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: 10_000, retry: false });

export const useRuntime = (live: LiveStatus) =>
  useQuery({ queryKey: keys.runtime, queryFn: api.runtime, refetchInterval: pollFor(live), retry });

export const useStatus = (live: LiveStatus) =>
  useQuery({ queryKey: keys.status, queryFn: api.status, refetchInterval: pollFor(live), retry });

export const useDefenseState = (live: LiveStatus) =>
  useQuery({ queryKey: keys.state, queryFn: api.state, refetchInterval: pollFor(live), retry });

export const useTelemetry = (live: LiveStatus) =>
  useQuery({
    queryKey: keys.telemetry,
    queryFn: api.telemetry,
    refetchInterval: pollFor(live),
    retry,
  });

export const useEvents = (live: LiveStatus) =>
  useQuery({ queryKey: keys.events, queryFn: () => api.events(25), refetchInterval: pollFor(live), retry });

export const useActions = (live: LiveStatus) =>
  useQuery({ queryKey: keys.actions, queryFn: () => api.actions(25), refetchInterval: pollFor(live), retry });

export const useIncidents = (live: LiveStatus) =>
  useQuery({ queryKey: keys.incidents, queryFn: () => api.incidents(20), refetchInterval: pollFor(live), retry });

export const useIncident = (id: string | null, live: LiveStatus) =>
  useQuery({
    queryKey: keys.incident(id ?? "none"),
    queryFn: () => api.incident(id as string),
    enabled: id !== null,
    refetchInterval: pollFor(live),
    retry,
  });

export const useAiStatus = () =>
  useQuery({ queryKey: keys.aiStatus, queryFn: api.aiStatus, staleTime: 60_000, retry });

export const useScenarios = () =>
  useQuery({ queryKey: keys.scenarios, queryFn: api.scenarios, staleTime: 60_000, retry: false });

/** The deliberate demo reset. Afterwards everything is re-read from the backend. */
export function useResetDemo() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api.resetDemo(),
    onSettled: () => {
      void client.invalidateQueries();
    },
  });
}

export function useStartScenario() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (name: ScenarioName) => api.startScenario(name),
    onSettled: () => {
      void client.invalidateQueries({ queryKey: keys.runtime });
    },
  });
}

/** The incident the dashboard focuses on: the newest open one, else the newest. */
export function currentIncident(incidents: IncidentSummary[] | undefined): IncidentSummary | null {
  if (!incidents || incidents.length === 0) return null;
  return incidents.find((i) => i.status !== "resolved") ?? incidents[0] ?? null;
}
