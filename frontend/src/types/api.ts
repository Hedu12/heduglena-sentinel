/**
 * API contract types.
 *
 * These interfaces mirror the Pydantic response schemas defined in
 * backend/models/. When a backend schema changes, this file must be
 * updated in the same commit. See P-08 (Frontend/Backend Contract).
 *
 * No business logic lives here — only shape declarations.
 */

// ── Enumerations ─────────────────────────────────────────────────────────────

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type DefenseState = "RELAXED" | "ALERT" | "DEFENSIVE" | "AGGRESSIVE";

export type ActionType =
  | "GENERATE_ALERT"
  | "INCREASE_MONITORING"
  | "RECORD_INCIDENT"
  | "SIMULATE_IP_BLOCK"
  | "SIMULATE_PROCESS_ISOLATE"
  | "SIMULATE_QUARANTINE";

export type SyntheticEventType =
  | "cpu_spike"
  | "memory_pressure"
  | "auth_failure"
  | "suspicious_process"
  | "network_surge"
  | "disk_io_spike"
  | "access_denied"
  | "connection_burst";

export type Classification = "INFORMATIONAL" | "SUSPICIOUS" | "HIGH_CONFIDENCE";

// ── Health ────────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: "ok" | "degraded";
  service: string;
  version: string;
}

// ── System Status ─────────────────────────────────────────────────────────────

export interface SystemStatusResponse {
  defense_state: DefenseState;
  threat_score: number; // 0.0–1.0
  timestamp: string;    // ISO 8601
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

export interface TelemetrySnapshot {
  id: number;
  collected_at: string;
  cpu_percent: number | null;
  memory_percent: number | null;
  disk_read_rate: number | null;
  disk_write_rate: number | null;
  net_bytes_sent: number | null;
  net_bytes_recv: number | null;
  process_count: number | null;
}

// ── Detection Events ──────────────────────────────────────────────────────────

export interface DetectionEvent {
  id: number;
  detected_at: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  metric_key: string;
  metric_value: number | null;
  threshold_value: number | null;
  is_synthetic: boolean;
  event_type: string;
  classification: Classification;
  confidence: number | null; // 0.0-1.0; null = not assessed
  status: string;
}

// ── Threat Score ──────────────────────────────────────────────────────────────

export interface ThreatScoreReading {
  id: number;
  calculated_at: string;
  score: number;
}

// ── Defense State ─────────────────────────────────────────────────────────────

export interface DefenseStateReading {
  current_state: DefenseState;
  since: string | null; // null: no transition recorded yet (RELAXED since install)
  threat_score_at_transition: number | null;
}

export interface DefenseStateChange {
  id: number;
  changed_at: string;
  previous_state: DefenseState;
  new_state: DefenseState;
  trigger_score: number;
}

// ── Response Actions ──────────────────────────────────────────────────────────

export interface ActionRecord {
  id: number;
  executed_at: string;
  action_type: ActionType;
  is_simulated: boolean;
  defense_state: DefenseState;
  result: string | null;
  dry_run_description: string;
  // The public incident identifier ("SIT-n"); internal ids are not exposed.
  incident_id: string | null;
  status: ActionStatus | null;
  action_class: ActionClass | null;
  guard_reason: string | null;
}

// Terminal lifecycle statuses (only these are ever persisted).
export type ActionStatus = "SUCCEEDED" | "FAILED" | "BLOCKED";

export type ActionClass =
  | "INFORMATIONAL"
  | "MONITORING"
  | "SIMULATED_PROTECTIVE"
  | "LIVE_PROTECTIVE";

// ── Detection Rules ───────────────────────────────────────────────────────────

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  metric: string;
  severity: Severity;
  enabled: boolean;
  last_fired: string | null;
  cooldown_seconds: number;
}

// ── Incidents (Phase 6, read-only) ────────────────────────────────────────────
// Mirrors backend/explanation/views.py. None of these endpoints accepts input
// that could reach the security pipeline: they are all GET.

export type IncidentStatus = "open" | "investigating" | "resolved";

export interface Reason {
  code: string;
  description: string;
}

// GET /api/v1/incidents
export interface IncidentSummary {
  incident_id: string; // "SIT-n"
  status: IncidentStatus;
  created_at: string;
  defense_state_at_creation: DefenseState;
  threat_score_at_creation: number;
  recovered_at: string | null;
  resolved_at: string | null;
  resolution: string | null; // e.g. "QUIET_FOR_REOPEN_WINDOW"
  summary: string | null;
}

export interface ScoreBreakdown {
  calculated_at: string;
  score: number;
  defense_state: DefenseState | null;
  severity: number;
  confidence: number;
  repetition: number;
  escalation: number;
  correlation: number;
  cross_domain: number;
  decay: number;
  active_categories: string[];
  reasons: Reason[];
}

export interface IncidentEvidence {
  detected_at: string;
  rule_name: string;
  event_type: string;
  classification: string;
  severity: string;
  confidence: number | null;
  metric_key: string;
  metric_value: number | null;
  threshold_value: number | null;
  is_synthetic: boolean;
}

export interface IncidentTransition {
  changed_at: string;
  from_state: DefenseState;
  to_state: DefenseState;
  trigger_score: number;
  reason: Reason | null;
}

export type GuardVerdict = "AUTHORIZED" | "DENIED" | "NOT_EVALUATED";

export interface ResponseSimulation {
  executed_at: string;
  action_type: ActionType;
  defense_state: DefenseState;
  status: string;
  guard_verdict: GuardVerdict;
  guard_reason: string | null;
  simulation_outcome: string | null; // e.g. "WOULD_QUARANTINE"
  dry_run_description: string;
  is_simulated: boolean;
}

// ── AI Explanation (explanation-only; display text) ───────────────────────────

export type ExplanationTrigger =
  | "INCIDENT_CREATED"
  | "STATE_TRANSITION"
  | "NEW_EVIDENCE"
  | "AGGRESSIVE_REFRESH";

export type ExplanationStatus = "VALID" | "REJECTED" | "FAILED";

export type ExplanationFailure =
  | "TIMEOUT"
  | "PROVIDER_ERROR"
  | "EMPTY_RESPONSE"
  | "OVERSIZED_OUTPUT"
  | "MALFORMED_JSON"
  | "SCHEMA_VIOLATION"
  | "UNSAFE_CONTENT"
  | "VALIDATOR_REDACTED"
  | "CONTEXT_UNAVAILABLE";

export type ExplanationConfidence = "LOW" | "MEDIUM" | "HIGH";

export interface ExplanationContent {
  summary: string;
  what_happened: string;
  why_it_matters: string;
  evidence: string[];
  current_state: string;
  recommended_human_attention: string;
  confidence: ExplanationConfidence;
}

export interface Explanation {
  generated_at: string;
  trigger: ExplanationTrigger | null;
  provider: string;
  model: string | null;
  status: ExplanationStatus | null;
  failure_reason: ExplanationFailure | null;
  latency_ms: number | null;
  content: ExplanationContent | null; // only for VALID explanations
}

// AVAILABLE: a validated explanation exists. PENDING: none attempted yet
// (show the neutral "Explanation pending" label). UNAVAILABLE: attempts failed.
export type ExplanationAvailability = "AVAILABLE" | "PENDING" | "UNAVAILABLE";

// GET /api/v1/ai/explain/{incident_id}
export interface ExplanationState {
  incident_id: string;
  availability: ExplanationAvailability;
  explanation: Explanation | null;
  latest_attempt: Explanation | null;
  fallback_text: string; // deterministic, non-AI
}

// GET /api/v1/incidents/{incident_id}
export interface IncidentDetail {
  incident: IncidentSummary;
  current_score: ScoreBreakdown | null;
  evidence: IncidentEvidence[];
  transitions: IncidentTransition[];
  simulations: ResponseSimulation[];
  ai: ExplanationState;
}

// GET /api/v1/ai/status
export interface AIStatus {
  provider: string;
  language_model_configured: boolean;
  explanation_only: true;
}

// ── Demo Endpoints ────────────────────────────────────────────────────────────

// Demo routes answer 403 when DEMO_MODE=false and 429 when rate-limited.
// Only security synthetic types can be injected (others are refused with 422).
export type SecuritySyntheticEventType =
  | "auth_failure"
  | "access_denied"
  | "connection_burst"
  | "suspicious_process";

export interface InjectEventRequest {
  event_type: SecuritySyntheticEventType;
  count?: number; // 1-20, default 1
}

export interface InjectEventResponse {
  injected: number;
  event_ids: number[]; // detection events produced (thresholds may need several injections)
}

export type ScenarioName = "normal" | "suspicious" | "critical";

export interface ScenarioInfo {
  name: ScenarioName;
  description: string;
  synthetic_events: number;
}

// POST /api/v1/demo/scenario/{name}: 202, 404 unknown, 409 one already running.
export interface ScenarioResponse {
  scenario: ScenarioName;
  status: "started";
  message: string;
}

// POST /api/v1/demo/reset (DEMO OPERATION): takes no input of any kind (a body or
// query string is refused with 422). It archives the current demo session intact and
// starts a new one from empty history; `defense_state` is what the new session's own
// runtime restored, never a value chosen by the client. 409 when unavailable or busy.
export interface ResetResponse {
  status: "reset";
  archived_session: string; // a label, never a filesystem path
  defense_state: DefenseState;
  message: string;
}

// ── Runtime (GET /api/v1/runtime) ─────────────────────────────────────────────

export interface DemoRun {
  name: ScenarioName;
  status: "running" | "completed" | "failed" | "cancelled";
  started_at: string;
  finished_at: string | null;
  events_injected: number;
  detections: number;
}

export interface RuntimeStatus {
  monitoring: boolean;
  healthy: boolean;
  started_at: string | null;
  poll_interval_seconds: number;
  defense_state: DefenseState;
  threat_score: number | null;
  last_decision_at: string | null;
  cycles: number;
  failed_cycles: number;
  consecutive_failures: number;
  telemetry_failures: number;
  last_cycle_at: string | null;
  last_cycle_ms: number | null;
  max_cycle_ms: number | null;
  last_telemetry_ms: number | null;
  last_detection_ms: number | null;
  last_decision_ms: number | null;
  detections: number;
  decisions: number;
  actions_recorded: number;
  synthetic_events: number;
  events_per_minute: number | null;
  last_error: string | null; // exception class name only
  explanations_pending: number;
  live_subscribers: number;
  live_messages_dropped: number;
  demo_running: ScenarioName | null;
  last_demo_run: DemoRun | null;
}

// ── WebSocket live stream message ─────────────────────────────────────────────

export type LiveMessageType =
  | "telemetry"
  | "detection_event"
  | "threat_score"
  | "defense_state_change"
  | "response_action";

// WS /ws/live is receive-only; client messages are ignored. Payloads by type:
//   telemetry            -> TelemetrySnapshot
//   detection_event      -> DetectionEvent
//   threat_score         -> LiveThreatScore
//   defense_state_change -> LiveStateChange
//   response_action      -> LiveResponseAction (fetch /api/v1/actions for the full record)
export interface LiveMessage {
  type: LiveMessageType;
  timestamp: string;
  payload: unknown; // narrow by checking `type`
}

export interface LiveThreatScore {
  calculated_at: string;
  score: number;
  defense_state: DefenseState;
}

export interface LiveStateChange {
  changed_at: string;
  previous_state: DefenseState;
  new_state: DefenseState;
  trigger_score: number;
}

export interface LiveResponseAction {
  id: number;
  action_type: ActionType;
  status: ActionStatus | null;
  incident_id: string | null;
}
