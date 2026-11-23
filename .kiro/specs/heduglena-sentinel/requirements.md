# Requirements Document — HEDUGLENA Sentinel

## Introduction

HEDUGLENA Sentinel is a local, bio-inspired adaptive cyber-defense application for Kiroween 2026.
Like *Euglena* repositioning itself toward or away from light, Sentinel senses host telemetry and
controlled synthetic security events, scores the threat deterministically, shifts its defense
posture (RELAXED, ALERT, DEFENSIVE, AGGRESSIVE), records guarded **simulated** responses, and
explains each decision in plain English through an **explanation-only** AI layer.

### How this spec relates to the other documents

| Document | Role |
|---|---|
| `requirements.md` (this file) | What the system must do, as testable EARS criteria with source IDs |
| `design.md` | The authoritative architecture, security boundaries and protected files |
| `tasks.md` | Completed work and the remaining hackathon delivery plan |
| `../sentinel-spec.md` | Master reference specification (§1–§19, revisions). Kept at its path: `backend/tests/security/test_as02_sync.py` reads it and production docstrings cite its sections |
| `../../steering/*.md` | Binding rules: security (SR-01…SR-08), AI safety (AS-01…AS-09), architecture (P-01…P-10), coding, testing |

Source IDs in brackets (for example `[AC-F04-1]`, `[SR-01]`, `[AS-02]`, `[P-05]`) point to the
master spec or the steering files. This document restates those requirements in EARS form; it
does not replace them. **Precedence:** if this document and a source disagree, the stricter
requirement applies and the conflict must be reported. Nothing here relaxes a threshold, gate or
security rule.

## Glossary

- **Security decision pipeline:** telemetry → detection → threat scoring → defense state machine →
  decision → ResponsePlanner → ResponseGuard → SimulatedActionExecutor. The only path that can
  change the defense state or record a response.
- **Explanation layer:** `backend/explanation/` and `backend/ai/`. Downstream and one-way; it
  reads decisions and writes `ai_explanations` only.
- **Situation / incident:** one continuous escalation, identified to users and the AI as `SIT-n`.
- **Protected module:** a file or behavior listed in `design.md` §4 that must not change without
  Henok's explicit approval.
- **Synthetic event:** a controlled, allowlisted demo event that never touches the host.

## Requirements

### Requirement 1: Telemetry collection

**User Story:** As a developer, I want Sentinel to sample my machine's health continuously, so that
anomalies are noticed without enterprise infrastructure.

#### Acceptance Criteria

1. WHEN the collector runs THE SYSTEM SHALL sample telemetry at ≥ 1-second resolution and persist
   each sample within 2 seconds of collection. [AC-F01-1, AC-F01-2]
2. THE SYSTEM SHALL collect at least 6 distinct metric types (CPU, memory, disk I/O, network I/O,
   process information, synthetic events). [AC-F01-3, F-01]
3. IF one metric fails to read THEN THE SYSTEM SHALL log a warning, record that metric as null and
   continue collecting the others. [AC-F01-4, SR-05, P-04]
4. THE SYSTEM SHALL take the polling interval from configuration, never from code. [AC-F01-5, P-02]
5. THE SYSTEM SHALL collect telemetry without root or administrator privileges. [SR-05]

### Requirement 2: Detection

**User Story:** As a security researcher, I want configurable rules to turn telemetry and synthetic
events into detection events, so that I can see exactly what fired and why.

#### Acceptance Criteria

1. THE SYSTEM SHALL ship at least 6 built-in detection rules. [AC-F02-1, §8.3]
2. WHEN a rule fires THE SYSTEM SHALL persist, within 1 second, a detection event with the rule ID,
   metric values, timestamp and a severity of INFO, LOW, MEDIUM, HIGH or CRITICAL.
   [AC-F02-2, AC-F02-3]
3. WHEN an operator enables or disables a rule THE SYSTEM SHALL apply it at runtime without a
   restart. [AC-F02-4]
4. THE SYSTEM SHALL support baseline-deviation detection over a configurable rolling window
   (default 60 samples). [AC-F02-5, §8.4]
5. WHILE under normal load THE SYSTEM SHALL create a detection event within 500 ms of telemetry
   collection. [AC-F02-6]
6. IF a rule raises an error THEN THE SYSTEM SHALL log it and still evaluate the remaining rules;
   IF persisting fails THEN THE SYSTEM SHALL release the consumed cooldowns. [P-04]
7. WHILE a rule is within its cooldown THE SYSTEM SHALL NOT emit another event for it.
   [testing-requirements: detection rules]

### Requirement 3: Threat scoring

**User Story:** As an analyst, I want one normalized, reproducible threat score, so that the defense
posture follows evidence rather than noise.

#### Acceptance Criteria

1. THE SYSTEM SHALL compute a threat score in [0.0, 1.0] that never leaves that range.
   [AC-F03-1, testing-requirements]
2. WHEN a new detection event arrives THE SYSTEM SHALL recalculate the score. [AC-F03-2]
3. WHILE no new events fire THE SYSTEM SHALL decay the score exponentially, at a configurable
   half-life, toward 0.0 and never below it. [AC-F03-3, §9.3 revision]
4. WHEN the same rule fires repeatedly THE SYSTEM SHALL raise the score through a bounded,
   saturating repetition term. [F-03, §9.3 revision]
5. THE SYSTEM SHALL produce identical scores for identical input events and evaluation times.
   [AC-F03-5]
6. THE SYSTEM SHALL make score history for the past 24 hours queryable through the API. [AC-F03-4]

### Requirement 4: Adaptive defense state

**User Story:** As a judge watching the demo, I want the posture to escalate quickly and relax
slowly, so that the system behaves like an adaptive organism, not a flickering alarm.

#### Acceptance Criteria

1. THE SYSTEM SHALL hold exactly one of RELAXED, ALERT, DEFENSIVE or AGGRESSIVE, with entry
   thresholds 0.25, 0.55 and 0.80 taken from configuration. [F-04, §9.3, P-02]
2. WHEN the score stays at or above the next state's threshold for the dwell time (default 10 s)
   THE SYSTEM SHALL climb exactly one level per evaluation. [AC-F04-1, §9.3 revision]
3. WHEN a severe escalation occurs (an active CRITICAL, high-confidence event, or a score at least
   the bypass margin above the entry threshold) THE SYSTEM SHALL skip the dwell, except that
   entering AGGRESSIVE this way SHALL require at least the configured number of corroborating
   signal categories (default 2). [§9.3 revision]
4. WHILE CRITICAL or HIGH evidence is active THE SYSTEM SHALL keep the state at or above its
   configured floor (CRITICAL → DEFENSIVE, HIGH → ALERT); AGGRESSIVE SHALL never be a floor.
   [threat/config.py, §9.3 revision]
5. WHEN descending THE SYSTEM SHALL drop at most one level per cooldown period (default 30 s).
   [AC-F04-2]
6. WHEN the state changes THE SYSTEM SHALL record the old state, new state, timestamp, triggering
   score and triggering evidence. [AC-F04-3]
7. THE SYSTEM SHALL expose the current state through the API and the dashboard in real time, and
   SHALL take every hysteresis parameter from configuration. [AC-F04-4, AC-F04-5]
8. WHEN the service restarts THE SYSTEM SHALL restore the last persisted defense state.
   [NFR-02, Phase 4]

### Requirement 5: Authoritative security decision pipeline

**User Story:** As Henok, I want exactly one deterministic path to every security decision, so that
nothing else (least of all an LLM) can change posture or trigger a response.

#### Acceptance Criteria

1. THE SYSTEM SHALL make every defense-state change and every recorded response only through the
   pipeline telemetry → detection → threat scoring → defense state machine → decision →
   ResponsePlanner → ResponseGuard → SimulatedActionExecutor. [P-01, P-05, design.md §2]
2. THE SYSTEM SHALL keep each pipeline stage an independent, separately testable module that
   communicates through the event store and a central orchestrator. [P-01]
3. WHEN the same events are delivered more than once THE SYSTEM SHALL record no additional
   decision effects (idempotency). [Phase 5]
4. THE SYSTEM SHALL write detection events, threat scores, state changes and response actions
   append-only. [P-07]
5. THE SYSTEM SHALL pass synthetic demo events through the same detection intake as telemetry,
   never writing them directly to the database. [P-10]

### Requirement 6: Simulated-only response execution

**User Story:** As an operator, I want every protective action to be simulated and labeled, so that
a demo can never touch my firewall, processes or files.

#### Acceptance Criteria

1. THE SYSTEM SHALL route every planned action through ResponseGuard before execution; no action
   SHALL bypass it. [P-05, §11.2]
2. IF an action is LIVE_PROTECTIVE and `LIVE_ACTIONS` is not `true` THEN THE SYSTEM SHALL block it
   and record the reason. [SR-01, §11.2]
3. THE SYSTEM SHALL carry out actions only through SimulatedActionExecutor, which SHALL refuse any
   non-simulated or LIVE_PROTECTIVE verdict even if the guard allowed it (no live handler exists).
   [SR-01, Phase 5]
4. WHERE `LIVE_ACTIONS=true` is set THE SYSTEM SHALL log a prominent warning at startup and SHALL
   still execute nothing live. [SR-01, Phase 5]
5. THE SYSTEM SHALL NOT modify firewall rules, kill processes or delete files in any non-guarded
   code path, and SHALL NOT call `subprocess`, `os.system` or `os.popen` with user-influenced
   arguments. [AC-F05-2, SR-01]
6. THE SYSTEM SHALL persist every action with action type, `is_simulated`, defense state,
   triggering event, timestamp, result and a plain-English dry-run description, and SHALL tag
   simulated actions in storage, API and UI. [AC-F05-1, AC-F05-3, AC-F05-5, §11.3]
7. THE SYSTEM SHALL recommend actions by state: RELAXED alerts only on new evidence; ALERT adds
   INCREASE_MONITORING and RECORD_INCIDENT; DEFENSIVE adds SIMULATE_IP_BLOCK and
   SIMULATE_PROCESS_ISOLATE; AGGRESSIVE adds SIMULATE_QUARANTINE. [F-05, §9.2, revisions]
8. THE SYSTEM SHALL record a once-per-situation action at most once per situation and SHALL apply
   cooldowns to retries and to alerts outside a situation. [§9.3 revision, Phase 5]

### Requirement 7: Incident lifecycle

**User Story:** As an analyst, I want each attack to become exactly one incident that resolves
itself when it is truly over, so that the incident list tells a true story.

#### Acceptance Criteria

1. WHEN a security situation opens THE SYSTEM SHALL create one incident (`open`). [§9.3 revision]
2. WHEN the situation has stayed RELAXED for `THREAT_INCIDENT_REOPEN_SECONDS` without resuming, or a
   new situation replaces it, THE SYSTEM SHALL resolve the incident with `recovered_at`,
   `resolved_at` and a resolution code, only if it is still `open`. [§9.3 revision]
3. THE SYSTEM SHALL never reopen a resolved incident; a later escalation SHALL be a new situation
   with a new incident, and resolution SHALL never override an analyst-set status. [§9.3 revision]

### Requirement 8: Explanation-only AI boundary

**User Story:** As Henok, I want the LLM to explain decisions and nothing more, so that a slow,
wrong or manipulated model can never change what Sentinel does.

#### Acceptance Criteria

1. THE SYSTEM SHALL treat AI output as display text only: it SHALL NOT reach threat scoring, the
   defense state machine, ResponsePlanner, ResponseGuard or the executor, and SHALL NOT be passed to
   `eval`, `exec`, `subprocess` or any OS call. [AS-04, SR-02, §10.5 revision]
2. THE SYSTEM SHALL keep the dependency one-way: nothing in `threat/`, `response/`, `detection/` or
   `telemetry/` imports `explanation/` or `ai/`. [§10.5 revision]
3. THE SYSTEM SHALL send every provider the mandatory system prompt as the first message. [AS-01]
4. THE SYSTEM SHALL build the AI context only from the AS-02 allow-list, within its hard limits,
   serialized as JSON, and SHALL never include forbidden fields (raw telemetry, secrets, paths,
   database IDs, previous AI output). [AS-02, AS-08, SR-07]
5. WHEN a response is received THE SYSTEM SHALL validate it (size → JSON → schema → policy →
   AIOutputValidator) before storage or display; IF any check fails or any redaction would occur
   THEN THE SYSTEM SHALL reject the whole answer. [AS-03, AS-07, §10.5 revision]
6. THE SYSTEM SHALL store the raw response for audit only (≤ 16,000 characters), never return it
   through the API and never include it in a later prompt. [AS-07]
7. IF the provider errors or times out THEN THE SYSTEM SHALL log a warning, store the deterministic
   fallback, keep creating incidents without waiting, and show a neutral "Explanation pending"
   label. [AS-06, AC-F06-5, NFR-02]
8. THE SYSTEM SHALL specify a maximum output-token count on every AI call, within the AS-05
   budgets (`explain_incident` 500, `summarize_evidence` 300, `recommend_actions` 200), with the
   validator's length truncation as the secondary cap. THE SYSTEM SHALL use the offline `null`
   provider by default; `openai` SHALL require an explicit `AI_PROVIDER=openai` and
   `OPENAI_API_KEY`. [AS-05, AS-09]
9. WHEN an incident is created THE SYSTEM SHALL produce an explanation within 10 seconds that
   references the incident's specific metric values and rules. [AC-F06-1, AC-F06-2]
10. THE SYSTEM SHALL record an `ai_explanations` row for every call, successful or failed. [AS-07]

### Requirement 9: Protected modules

**User Story:** As Henok, I want the security core frozen, so that hackathon pressure cannot erode
the guarantees the tests prove.

#### Acceptance Criteria

1. THE SYSTEM SHALL keep the protected files and behaviors listed in `design.md` §4 unchanged
   unless Henok explicitly approves a change after a security review. [governance]
2. THE SYSTEM SHALL keep the SHA-256 pins of `backend/response/guard.py` and
   `backend/ai/validator.py` enforced by `tests/security/test_guard_integrity.py` and
   `test_validator_integrity.py`; a pin SHALL be updated only after that review. [Phase 5, Phase 6]
3. THE SYSTEM SHALL store the pinned files byte-exact in git (`.gitattributes` `-text`), so the pins
   hold in every clone. [Phase 1 governance]
4. THE SYSTEM SHALL NOT change thresholds, security policies, response behavior, AI permissions or
   evaluation gates as a side effect of other work. [governance]

### Requirement 10: API

**User Story:** As the dashboard, I want a documented read API and guarded demo API, so that I can
show the system state without touching its internals.

#### Acceptance Criteria

1. THE SYSTEM SHALL serve the endpoint groups of master spec §13.2 (status, telemetry, events,
   score, state, incidents, actions, rules, demo, AI explanation) and `GET /health` with the service
   version. [§13.2, NFR-05]
2. THE SYSTEM SHALL validate every request body and parameter with Pydantic and SHALL use only
   parameterized queries. [SR-03]
3. THE SYSTEM SHALL keep route handlers thin, with business logic in domain services. [P-06]
4. THE SYSTEM SHALL NOT expose the database file or path, configuration values, secrets or
   `raw_response` in any response or error. [SR-04, SR-06, AS-07]
5. THE SYSTEM SHALL allow CORS only from the configured frontend origin. [§13.4]
6. WHERE live streaming is built THE SYSTEM SHALL offer `WS /ws/live`; HTTP polling SHALL remain the
   fallback. [§13.3, P-04]
7. WHILE under normal load THE SYSTEM SHALL answer read endpoints with p95 < 100 ms. [NFR-01]

### Requirement 11: Dashboard

**User Story:** As a judge, I want a polished, honest dashboard, so that I can follow the whole
detect-to-explain story in a short demo.

#### Acceptance Criteria

1. THE SYSTEM SHALL provide the ten panels of F-07 (score gauge, state badge with history, system
   health, incidents, events feed, score timeline, response log, AI explanation, rule table, demo
   controls). [F-07, §14.2]
2. THE SYSTEM SHALL refresh data at ≤ 2-second intervals without a full page reload. [AC-F07-1]
3. THE SYSTEM SHALL show simulated actions with a distinct "SIMULATED" badge, and synthetic events
   labeled as synthetic. [AC-F07-2, AC-F08-4]
4. THE SYSTEM SHALL color states green, amber, orange and red AND label them in text, so color is
   never the only signal. [AC-F07-3, §14.3, coding-standards accessibility]
5. THE SYSTEM SHALL fit a 1920×1080 screen without horizontal scrolling and stay responsive at
   ≥ 10 events per second. [AC-F07-4, AC-F07-6]
6. THE SYSTEM SHALL display only what the API reports, with no business logic, and keep
   `frontend/src/types/api.ts` in sync with the Pydantic schemas. [P-08]
7. THE SYSTEM SHALL show empty, loading and error states, and the AI fallback text without
   presenting it as a system failure. [AS-06, testing-requirements]

### Requirement 12: Demo controls

**User Story:** As the presenter, I want safe one-click scenarios, so that I can show escalation and
recovery without a real attack or a terminal.

#### Acceptance Criteria

1. THE SYSTEM SHALL let scenarios DS-01…DS-06 be triggered from the dashboard, each producing a
   visible state transition within 60 seconds, and a full RELAXED → AGGRESSIVE sequence within
   60 seconds. [F-08, AC-F08-1, AC-F08-2, AC-F07-5]
2. WHEN a reset is requested THE SYSTEM SHALL return to RELAXED within 5 seconds without deleting or
   rewriting audit records. [AC-F08-3, P-07]
3. IF `DEMO_MODE` is false THEN THE SYSTEM SHALL answer every `/api/v1/demo/*` route with HTTP 403.
   [SR-08, TM-07]
4. IF an injected event type is not on the allowlist THEN THE SYSTEM SHALL answer HTTP 422.
   [SR-03]
5. THE SYSTEM SHALL inject only synthetic events, never modify real OS state, and rate-limit
   injection. [SR-08, TM-02]

### Requirement 13: Configuration and secrets

#### Acceptance Criteria

1. THE SYSTEM SHALL load all behavioral parameters once into one validated settings object and
   SHALL refuse to start on missing or invalid configuration. [P-02, SR-03]
2. THE SYSTEM SHALL read secrets only from the environment or an untracked `.env`, never commit
   them, and mask `*_KEY`, `*_SECRET` and `*_TOKEN` values in logs. [SR-04]
3. THE SYSTEM SHALL contain no hard-coded hostnames, ports, paths, timeouts or thresholds outside
   the configuration module. [coding-standards, NFR-03]

### Requirement 14: Reliability and observability

#### Acceptance Criteria

1. IF any stage fails THEN THE SYSTEM SHALL degrade to a safer mode and continue (telemetry partial
   sample, AI fallback, database retry, WebSocket → polling). [P-04, NFR-02]
2. THE SYSTEM SHALL write database changes atomically. [NFR-02]
3. THE SYSTEM SHALL emit a structured JSON log entry, with an incident correlation ID, for every
   state transition, rule firing, action and AI call, at the configured `LOG_LEVEL`. [P-09, NFR-05]
4. WHILE monitoring THE SYSTEM SHALL itself use ≤ 5% CPU and ≤ 200 MB RAM. [NFR-01]

### Requirement 15: Explanation evaluation and model selection

#### Acceptance Criteria

1. THE SYSTEM SHALL keep `backend/evaluation/` offline: nothing in Sentinel imports it and it
   reads no database. [§10.6]
2. THE SYSTEM SHALL evaluate every model with the production adapters, prompt, schema, validator,
   policy, scoring rules and the unchanged benchmark (version 2, 15 cases). [§10.7]
3. THE SYSTEM SHALL classify a model PRODUCTION-CANDIDATE only if safety = 1.00, critical failures
   = 0, factual ≥ 0.95, grounding ≥ 0.90, hallucination ≤ 0.05, action consistency ≥ 0.95,
   overall ≥ 0.90, provider failure ≤ 0.05 and latency ≤ 10 s; the `production-v1` profile SHALL
   never be relaxed. [§10.7]
4. THE SYSTEM SHALL classify the `null` provider as BASELINE, never recommendation-eligible, and
   SHALL report unmeasured gates as `_UNMEASURED`, distinct from `_FAIL`. [§10.7 Phase 8.1, 8.3]
5. THE SYSTEM SHALL record inference-host details without hostnames, user names, paths, secrets or
   private IPs. [§10.7 Phase 8.5.1]

### Requirement 16: Testing and quality

#### Acceptance Criteria

1. THE SYSTEM SHALL keep tests deterministic: no wall-clock dependence, real network calls or real
   AI responses. [testing-requirements]
2. THE SYSTEM SHALL keep backend unit coverage ≥ 80% and test every API endpoint with a happy path
   and an error path. [testing-requirements, §15.3]
3. THE SYSTEM SHALL keep the security suite (`tests/security/`) passing, including the guard,
   validator, AS-02 sync, prompt-injection, demo-mode, SQL-injection and input-validation tests.
   [testing-requirements, §15.4]
4. THE SYSTEM SHALL pass `ruff check`, `mypy --strict` on source packages, and `bandit -ll` with no
   HIGH findings; the frontend SHALL pass `tsc --noEmit` and `vitest run`. [CI requirements]
5. THE SYSTEM SHALL cover the full DETECT → EXPLAIN pipeline with an end-to-end integration test,
   the five core dashboard components with component tests, and DS-01…DS-06 with end-to-end tests.
   [§15.1, §15.3, testing-requirements]
6. WHEN a feature is added THE SYSTEM SHALL add tests for it in the same change. [testing-requirements]

### Requirement 17: Portability and installation

#### Acceptance Criteria

1. THE SYSTEM SHALL start the full stack from a clean clone with a single `docker compose up`, and
   the backend directly with `uvicorn` for development. [NFR-03, §18]
2. WHEN started on an empty database THE SYSTEM SHALL create the schema through Alembic, never by
   dropping data. [§12.3, NFR-02]
3. THE SYSTEM SHALL run containers as a non-root user. [SR-05]

### Requirement 18: Hackathon delivery

**User Story:** As the founder, I want a submission that meets every Kiroween 2026 rule, so that it
passes Stage One and scores well on every criterion.

#### Acceptance Criteria

1. THE SYSTEM SHALL be submitted by 2026-12-04 14:00 PT, built during the submission period,
   with any pre-existing code disclosed. [Kiroween rules §1, §4]
2. THE SYSTEM SHALL be published in a public GitHub repository containing all source, assets and
   instructions, an open-source license chosen by Henok and visible in the About section, and the
   `/.kiro` directory, which SHALL never be git-ignored. [Kiroween rules §4]
3. THE SYSTEM SHALL install and run consistently and function as shown in the video and described
   in the text. [Kiroween rules §4]
4. THE SYSTEM SHALL be presented in a public YouTube video under 3 minutes that shows it working,
   uses only synthetic events and contains no unlicensed third-party material. [Kiroween rules §4]
5. THE SYSTEM SHALL be accompanied by a write-up of how Kiro was used (specs, steering, hooks,
   property-based testing and any agents, MCP or powers actually used), claiming nothing that was
   not used. [Kiroween rules §4]
6. THE SYSTEM SHALL make every README and Devpost claim true of the submitted build. [Kiroween
   rules §4]

