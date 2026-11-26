/**
 * The backend endpoints the dashboard uses. Read-only GETs, plus the two
 * deliberate demo POSTs (a scenario start and a synthetic injection). Nothing
 * here can send a security decision to the backend: there is no such endpoint.
 */

import type {
  ActionRecord,
  AIStatus,
  DefenseStateReading,
  DetectionEvent,
  ExplanationState,
  HealthResponse,
  IncidentDetail,
  IncidentSummary,
  ResetResponse,
  RuntimeStatus,
  ScenarioInfo,
  ScenarioName,
  ScenarioResponse,
  SystemStatusResponse,
  TelemetrySnapshot,
  ThreatScoreReading,
} from "../types/api";
import { request } from "./http";

const INCIDENT_ID = /^SIT-\d{1,12}$/;

function incidentPath(id: string): string {
  // Only the public SIT-n identifier is ever placed in a URL.
  if (!INCIDENT_ID.test(id)) throw new Error("invalid incident id");
  return encodeURIComponent(id);
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  status: () => request<SystemStatusResponse>("/api/v1/status"),
  runtime: () => request<RuntimeStatus>("/api/v1/runtime"),
  state: () => request<DefenseStateReading>("/api/v1/state/current"),
  score: () => request<ThreatScoreReading>("/api/v1/score/current"),
  telemetry: () => request<TelemetrySnapshot>("/api/v1/telemetry/latest"),
  events: (limit = 25) => request<DetectionEvent[]>(`/api/v1/events?limit=${limit}`),
  actions: (limit = 25) => request<ActionRecord[]>(`/api/v1/actions?limit=${limit}`),
  incidents: (limit = 20) => request<IncidentSummary[]>(`/api/v1/incidents?limit=${limit}`),
  incident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${incidentPath(id)}`),
  explanation: (id: string) =>
    request<ExplanationState>(`/api/v1/ai/explain/${incidentPath(id)}`),
  aiStatus: () => request<AIStatus>("/api/v1/ai/status"),
  scenarios: () => request<ScenarioInfo[]>("/api/v1/demo/scenarios"),
  startScenario: (name: ScenarioName) =>
    request<ScenarioResponse>(`/api/v1/demo/scenario/${name}`, { method: "POST" }),
  // No body, no parameters: the client cannot choose a state, a score or an incident.
  resetDemo: () => request<ResetResponse>("/api/v1/demo/reset", { method: "POST" }),
};
