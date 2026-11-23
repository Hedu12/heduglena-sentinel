# HEDUGLENA Sentinel — Kiroween 2026 Readiness Audit

**Audit date:** 2026-11-20 (machine clock, UTC)
**Submission deadline:** 2026-12-04 14:00 PT = 2026-12-05 01:00 EAT. 14 calendar days remain.
**Scope:** read-only audit. This report is the only file created. No other file was changed.
**Auditor:** Kiro (IDE agent), at Henok's request.

Evidence tags used below:

- **VERIFIED**: confirmed by reading code or files, or by running a command during this audit.
- **ASSUMED**: an inference that this audit did not test.
- **UNKNOWN**: cannot be confirmed from the available evidence; it needs Henok or the organizers.

---

## 1. Executive summary

**Overall readiness: 3.5 / 10.**

The security domain of Sentinel is strong. Telemetry, detection, threat scoring, the defense state machine, response planning, `ResponseGuard`, the simulated executor, incident lifecycle and the explanation-only AI layer are implemented as separate modules. All 2,011 backend tests pass. Bandit reports 0 issues, and mypy strict is clean on all 88 source files.

The product that judges would see does not exist yet:

1. **The pipeline never runs in the application.** `app/main.py` creates a database engine and mounts four read-only GET routes. No production code creates a `TelemetryCollector`, `DetectionEngine`, `ThreatAssessmentService`, `ResponseService` or `ExplanationService`. The DETECT → EXPLAIN loop runs only inside the test suite.
2. **There is no dashboard.** `frontend/` holds configuration files, an empty directory skeleton and one types file (`src/types/api.ts`). There is no `index.html`, no `main.tsx` and no React component.
3. **There is no demo control.** The `/api/v1/demo/*` endpoints, the status, telemetry, events, score, state, actions and rules endpoints, and the WebSocket in spec §13 are not implemented. 5 of the 20 planned HTTP routes exist.
4. **The submission prerequisites are missing.** The folder is not a git repository. There is no GitHub repository, no open-source LICENSE, no video, and no Kiro usage write-up.
5. **The Kiro configuration is only partly valid.** The steering files work: this audit received them as injected rules. The 5 hook files do not use the documented Kiro hook schema, so Kiro will not run them. The spec is one 48 KB file, not the per-feature `requirements.md` / `design.md` / `tasks.md` layout Kiro shows in its Specs panel.

The remaining work is mostly integration and presentation, not new security logic. The tested services already compose end to end in `tests/integration/test_response_pipeline.py` and `tests/threat_scenario.py`. Sentinel can reach a credible submission by 4 December if the work follows this order: version control first, then the runtime orchestrator, the API and the dashboard, then the video and the write-up. The protected modules need no changes for any of these steps.

---

## 2. Current project architecture (as implemented)

```
                         ┌────────────────────── NOT WIRED IN THE APP ──────────────────────┐
psutil / Fake provider → TelemetryCollector → DetectionEngine → ThreatAssessmentService
                         (telemetry/)         (detection/)      (threat/: scorer + state_machine
                                                                 + decision + situation)
                                                    │ Decision
                                                    ▼
                                ResponseService → ResponsePlanner → ResponseGuard → SimulatedActionExecutor
                                (response/)                          (guard.py)      (executor.py)
                                                    │ Decision (observe only, one-way)
                                                    ▼
                                ExplanationService → ContextBuilder → Explainer → AIOutputValidator
                                (explanation/)        (IncidentContext)  (ai/)      (validator.py)
                         └──────────────────────────────────────────────────────────────────┘
SQLite (SQLAlchemy 2 async, Alembic head f8b5d2c30008)  ← all stages write append-only rows

FastAPI app (app/main.py): /health, GET /api/v1/incidents, /incidents/{id},
                           /ai/explain/{id}, /ai/status            ← read-only, VERIFIED
Frontend: types only (frontend/src/types/api.ts)                   ← no UI, VERIFIED
Evaluation harness: backend/evaluation (Phase 7–8.5.1), offline CLI, not part of the app
```

| Layer | Modules | Lines (Bandit count) | State |
|---|---|---|---|
| Backend source | 12 packages, 88 files | 11,450 | Implemented, type-clean |
| Tests | 32 unit, 19 integration, 14 security and 0 performance test files | n/a | 2,011 pass |
| Frontend | `package.json`, `vite.config.ts`, `tsconfig*.json`, `Dockerfile`, `src/types/api.ts`, `tests/setup.ts` | ~10 KB types | No application |
| Kiro | 1 spec, 5 steering files, 5 hook files | n/a | Steering valid; hooks and spec format not recognized (see §7) |

---

## 3. Verified implemented features

All items are VERIFIED by code reading, and the 2,011-test run on 2026-11-20 confirms their behavior.

### A. Telemetry (`backend/telemetry/`)
- **Providers behind a protocol.** `TelemetrySource` has two implementations, `PsutilTelemetryProvider` and `FakeTelemetryProvider` (P-03).
- **Validation and sanitization** live in `telemetry/validation.py`. `collector.py` derives rate metrics and persists each sample.
- **Graceful degradation.** A metric that fails to read logs a warning and becomes `None` (`psutil_provider.py:40–51`, SR-05).
- **Polling loop.** `TelemetryCollector.run_until_cancelled()` exists, but nothing in the app calls it.

### B. Detection (`backend/detection/`)
- **Rule engine.** `DetectionEngine` isolates rule failures and releases cooldowns when a write fails. It has `process_sample()` and `process_synthetic()`.
- **Rules.**
  - Resource: CPU and memory, each with a threshold and a consecutive-sample count.
  - Process: process-count increase over a baseline.
  - Network: throughput and connection burst.
  - Synthetic security events.
- **Synthetic allowlist.** `models/enums.py:SyntheticEventType` has 8 types: `cpu_spike`, `memory_pressure`, `auth_failure`, `suspicious_process`, `network_surge`, `disk_io_spike`, `access_denied`, `connection_burst`. Free text is sanitized and capped (`detection/synthetic.py`).
- **Rule state.** `list_rules()`, `set_rule_enabled()` and `reset()` exist for the planned rules API.

### C. Threat scoring and state (`backend/threat/`)
- **Deterministic scorer.** The score combines severity, confidence, repetition, escalation, correlation and cross-domain weights, with half-life decay (`THREAT_HALF_LIFE_SECONDS=60`).
- **Four-state machine with hysteresis.**
  - Thresholds: 0.25, 0.55 and 0.80.
  - Timing: 10 s dwell to climb, 30 s cooldown to descend.
  - The state climbs one level per evaluation.
  - Severity floors: CRITICAL keeps the state at least DEFENSIVE, and HIGH keeps it at least ALERT.
  - Entering AGGRESSIVE by bypassing the dwell needs at least 2 corroborating signal categories.
- **Clock-free service.** `ThreatAssessmentService` takes `now` from the caller, so the same events always produce the same result. It persists the score and any transition in one transaction and restores state after a restart.
- **Property-based tests.** `tests/unit/test_threat_properties.py` uses Hypothesis.

### D. Defense (`backend/response/`)
- **Planner.** `ResponsePlanner` is pure and recommends actions per state (`threat/decision.py`):
  - **ALERT:** alert, increase monitoring, record incident.
  - **DEFENSIVE:** adds simulated IP block and simulated process isolation.
  - **AGGRESSIVE:** adds simulated quarantine.
- **Service.** `ResponseService` provides idempotency keys, once-per-situation deduplication, cooldowns and one transaction per action.
- **Guard.** `ResponseGuard` blocks `LIVE_PROTECTIVE` unless `LIVE_ACTIONS=true`.
- **Executor.** `SimulatedActionExecutor` has no live handler, and `ensure_simulated()` refuses live verdicts even when the guard allows them.
- **Incident lifecycle.** Incidents open, stay open, resolve after the reopen window, and a second attack opens a new incident. The `test_response_pipeline.py` tests cover this.
- **Startup warning.** `response/service.py:112` logs a warning when `LIVE_ACTIONS=true`, as SR-01 requires.

### E. AI explanation (`backend/ai/`, `backend/explanation/`)
- **Provider protocol.** `NullProvider` is the default and makes no network calls. `OpenAICompatibleProvider` serves both Ollama (`/v1`) and OpenAI. Settings refuse `openai` without a key (AS-09).
- **Context.** `IncidentContext` is the AS-02 allow-list model. `tests/security/test_as02_sync.py` fails if the code and the steering document drift apart.
- **Output validation.** `AIOutputValidator` runs before storage. Any redaction rejects the whole answer. `raw_response` is an audit artifact and is never returned by the API.
- **One-way, non-blocking explanations.** `ExplanationService.observe()` is synchronous and never raises. A worker builds explanations in the background with timeouts and limited retries.
- **Prompt-injection resistance** is covered by `tests/security/test_ai_prompt_injection.py` and `test_ai_boundary.py`.

### F. API (`backend/api/v1/incidents.py`)
- **Routes:** `GET /api/v1/incidents`, `/incidents/{id}`, `/ai/explain/{id}` and `/ai/status`. Path IDs are pattern-checked (`^SIT-\d{1,12}$`) and the limit is bounded (1–100). The handlers stay thin (P-06).

### G. Evaluation (`backend/evaluation/`)
- **Benchmark harness.** An offline benchmark has 15 cases and quality gates. Saved results are in `reports/phase8.2–8.5`. Both local models are NOT READY on CPU (100% timeouts). GPU benchmarking is postponed.

### H. Hackathon-relevant engineering evidence
| Check (run 2026-11-20) | Result |
|---|---|
| `pytest` full suite | **2,011 passed**, 0 failed, 536.8 s |
| `mypy --strict` source packages | **0 issues in 88 files** |
| `mypy --strict .` including tests | 125 errors in 25 test files (tests only) |
| `bandit -r` source (11,450 lines) | **0 Low / 0 Medium / 0 High** |
| `ruff check .` | 9 findings, all pre-existing (Phase 1 alembic files plus one test F841) |
| Secret scan over 229 text files | 0 secret-like literals, 0 personal paths |
| `guard.py` / `validator.py` SHA-256 | Unchanged (see §13) |

---

## 4. Incomplete or disconnected features

| # | Gap | Evidence | Impact |
|---|---|---|---|
| G1 | **No runtime orchestrator.** Nothing starts the collector loop or connects detection → threat → response → explanation. | `app/main.py` (36 lines) mounts only `incidents_router`. No service is instantiated outside `tests/`. | The running app records nothing. Every list endpoint returns empty forever. |
| G2 | **No frontend application.** | `frontend/src/{components,hooks,pages,services}` are empty. There is no `index.html` or `main.tsx`, no `package-lock.json`, and no `node_modules`. | The Design criterion cannot be met, and the video has nothing to show. |
| G3 | **No demo API.** `inject`, `scenario/{name}` and `reset` are missing. | No `demo` route anywhere. | The README demo panel and spec §16 cannot run. |
| G4 | **15 of 20 planned HTTP routes and the WebSocket are missing.** | Spec §13.2 lists 20 routes; the app serves 5, including `/health`. | `api.ts` declares types (`SystemStatusResponse`, `LiveMessage`, ...) for endpoints that do not exist. |
| G5 | **No schema bootstrap.** | `lifespan` does not run Alembic or `create_all`. The README never says to run `alembic upgrade head`, and the Dockerfile doesn't either. | ASSUMED: a fresh install answers `GET /api/v1/incidents` with HTTP 500 because the tables don't exist. |
| G6 | **No CORS middleware.** | No `CORSMiddleware`. `frontend_origin` is configured but never read. | In Docker the browser at :3000 calls :8000 cross-origin, so requests would be blocked. |
| G7 | **No logging configuration.** There is no structured JSON logging, correlation IDs or secret-masking formatter. | No `logging.basicConfig`, `dictConfig` or `structlog.configure`. `structlog` is a dependency but unused. | P-09 and SR-04 (formatter masking) are only partly met. Secrets are protected by `SecretStr`. |
| G8 | **Docker quick start is broken.** | The compose healthcheck uses `curl`, which `python:3.11-slim` doesn't include, and the frontend depends on `service_healthy`. The frontend image needs a lock file and an app. Compose needs `.env`. | Both README quick starts fail on a clean clone. |
| G9 | **Testing-steering items are missing.** | `tests/performance/` holds only `__init__.py`. The fixtures directory lacks `normal_telemetry.json`, `cpu_spike_telemetry.json`, `auth_failure_sequence.json` and `full_escalation_sequence.json`. There are no Playwright or Vitest tests. | The project's own testing steering is not met. Judges rarely check this. |
| G10 | **Python 3.11 is the target but untested.** | Dockerfile and pyproject target 3.11. All runs used 3.14.2. | UNKNOWN whether the suite passes on 3.11. |

**README statements that are currently false.** These matter because the rules require the project to "function as depicted in the video and/or expressed in the text description":

- "docker compose up --build … open http://localhost:3000"
- "The Demo Control Panel (bottom-right of the dashboard)" and the scenarios DS-01–DS-06
- "npm run test", "npx playwright test"
- "core/ … orchestrator"
- "demo injection endpoint returns HTTP 403"

---

## 5. Security and reliability findings

**Security posture: strong at the domain layer. No CRITICAL security finding.**

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| S1 | — (positive) | The guard and executor protect live actions in two layers, and `LIVE_ACTIONS` defaults to `false`. | `guard.py:99`, `executor.py`, `test_no_live_response.py`, `test_live_actions_true_changes_nothing_about_the_response` |
| S2 | — (positive) | The AI is explanation-only and imports nothing from `threat/` or `response/`. Redaction rejects the whole answer. | `explanation/service.py` docstring, `test_ai_boundary.py`, `test_raw_response_audit.py` |
| S3 | MEDIUM | The demo-mode 403 guard (SR-08) cannot be verified because the demo endpoints don't exist. It must ship with the new endpoints, together with `test_demo_mode_guard.py`. | No demo routes |
| S4 | MEDIUM | There is no log-masking formatter (SR-04). The risk is low today because keys are `SecretStr` and the DB URL is masked (`engine.py:143`). | `core/config.py:56–57` |
| S5 | MEDIUM | The new orchestrator and demo API will be the first code that drives the protected modules at runtime. They need security review and must not bypass `ResponseService` or `ResponseGuard`. | Architecture P-05, P-10 |
| S6 | LOW | `reports/phase8.*/debug/` holds raw local-model outputs. They contain no secrets or paths (scan: 0 hits). Decide whether to publish them. | Directory listing |
| S7 | LOW | Do not add `--host 0.0.0.0` to the local run instructions. The Docker CMD uses `0.0.0.0`, which is expected inside a container. | `backend/Dockerfile` |
| R1 | HIGH | No runtime loop exists, so restart and recovery are proven only in tests (`test_explanation_restart.py`, `test_restarting_the_response_service_mid_attack_changes_nothing`). | G1 |
| R2 | MEDIUM | The full suite takes 537 s. The steering target for the unit suite is under 30 s, and this audit did not measure the unit suite on its own. | Test run |
| R3 | LOW | There are 12 DeprecationWarning types, all from FastAPI and pytest-asyncio on Python 3.14. They are not caused by project code. | Test output |
| R4 | LOW | The 9 ruff findings are in Phase 1 alembic files plus one test. 125 mypy errors are in test files only. | Lint run |

---

## 6. Dashboard readiness

**Score: 1 / 10. VERIFIED: no UI exists.**

| Spec §14 requirement | Status |
|---|---|
| React 18 + TS + Vite + Tailwind + React Query + Recharts | Declared in `package.json`. Not installed; no lock file. Tailwind config is missing. |
| Header with state badge and score gauge | Missing |
| Threat score timeline, state history, system sparklines | Missing (no backend endpoints either) |
| Detection events feed | Missing |
| Response actions log with SIMULATED badge | Missing |
| AI explanation panel ("Explanation pending" neutral label, AS-06) | Missing. The backend `ExplanationState` (AVAILABLE / PENDING / UNAVAILABLE) is ready to drive it. |
| Demo control panel | Missing |
| Color system plus a text label (accessibility: color is not the only signal) | Missing |
| WebSocket with polling fallback | Missing. Polling-only is acceptable for the MVP (P-04). |
| Error and empty states, responsive layout | Missing |

Reusable assets:

- **Types.** `src/types/api.ts` (about 40 exported types) already mirrors the incident and explanation schemas. Re-check it against the Pydantic models when the API is built (P-08).
- **Kiroween theme.** The Kiroween theme is Halloween ("Build something wicked"). The Design and Presentation criteria reward a polished, intentional look. A dark "bioluminescent Euglena" visual identity would fit the theme without changing any security semantics.

---

## 7. Kiro integration assessment

The rules state: *"Insufficient use of Kiro will result in disqualification at the Judges' sole discretion."* Technological Implementation (20%) is judged on how well and how variously the project uses Kiro.

| Kiro feature | Evidence in repo | Valid per kiro.dev docs? | Assessment |
|---|---|---|---|
| **Steering** | 5 files in `.kiro/steering/`: architecture, coding, security, testing, AI safety | **Yes.** `.kiro/steering/*.md` with no front matter is included by default. This audit received all five as injected rules. | Strongest Kiro evidence. `ai-safety-requirements.md` is enforced by a test (`test_as02_sync.py`), which makes a good story for the write-up. |
| **Specs** | One file, `.kiro/specs/sentinel-spec.md` (48 KB, 19 sections, acceptance criteria F-01…F-08) | **Not in Kiro's spec format.** Kiro expects `.kiro/specs/<feature>/requirements.md` (EARS), `design.md` and `tasks.md` (https://kiro.dev/docs/specs.md). | The content is rich, but Kiro's Specs panel probably won't show it (the docs don't say). The work happened in phases (1–8.5.1) driven by chat, not by Kiro task lists. |
| **Hooks** | 5 JSON files in `.kiro/hooks/` | **No.** They use `{"hook":{"event":"file_save","steps":[{"type":"shell"}]}}`. Kiro documents `{"version":"v1","hooks":[{"name","trigger","matcher","action":{"type":"command"\|"agent"}}]}` (https://kiro.dev/docs/hooks.md). `pre_commit` is not a documented trigger. | Kiro does not run them. Some commands also use wrong paths: `pytest tests/unit/` and `mypy backend/` from the workspace root, but the tests live in `backend/tests`. |
| **Custom agents** | None (no `.kiro/agents/`) | n/a | Missing |
| **MCP** | None (no `.kiro/settings/mcp.json`) | n/a | Missing. Optional. |
| **Property-based testing** | Hypothesis in `test_threat_properties.py` | n/a | A real but small example. Worth one paragraph in the write-up. |
| **Powers** | None used for the project | n/a | Optional |
| **Kiro clients used** | Kiro IDE: 6 local session directories exist under the user profile; their content was not read. | n/a | Evidence exists, but it isn't in the repository. |

**Honest narrative available for the write-up.** Every point below is backed by the repository:

- **Steering first.** Steering-first development: five steering documents encode security invariants (SR-01…SR-08, AS-01…AS-09). Kiro applied them across 8+ phases.
- **Invariants turned into tests.** Steering requirements became executable tests: `test_as02_sync.py` syncs the steering text with the code, and `test_guard_integrity.py` / `test_validator_integrity.py` pin the protected files.
- **Spec-led phases.** The spec defines F-01…F-08 acceptance criteria. Phases were delivered against them with test counts recorded (1,239 → 1,601 → 1,823 → 2,011).
- **Agent-assisted model evaluation.** The evaluation framework shows experimentation: real-model benchmarking, UNMEASURED vs FAIL semantics, and a hardware feasibility plan.

**Gaps to close, using Kiro for real and never backfilling fake history:**

1. **Fix the hooks.** Rewrite them in the documented schema and correct their paths. Then actually use them and capture screenshots.
2. **Spec the remaining work in Kiro's format.** Create per-feature spec folders for the work still to do (runtime orchestrator, read and demo API, dashboard) and execute their `tasks.md` with Kiro. This is genuine, demonstrable spec-driven development.
3. **Optionally add one custom agent and use it.** A good candidate is a read-only security reviewer agent for changes touching `response/` or `ai/`. Document its use.
4. **Document the Kiro story.** Write `docs/hackathon/KIRO_USAGE.md`: how steering, spec, hooks, PBT and agents were used, with dates and screenshots.

---

## 8. Official hackathon compliance checklist

Source: https://kiroween.devpost.com/rules, fetched 2026-11-20. Dates there: submissions run 2026-10-30 09:00 PT – **2026-12-04 14:00 PT**, judging runs 2026-12-16 – 2027-01-29, and Kiro credit requests close **2026-12-01 12:00 PT**.

| # | Requirement (quoted or paraphrased from rules) | Status | Evidence / action |
|---|---|---|---|
| 1 | Working software application built with Kiro | **FAIL** | The backend runs, but there is no pipeline and no UI (G1, G2). |
| 2 | "capable of being successfully installed and running consistently … function as depicted in the video and/or text description" | **FAIL** | Docker is broken (G8), there is no schema bootstrap (G5), and the README overclaims (§4). |
| 3 | Newly created during the Submission Period (after 2026-10-30) | **LIKELY PASS** | All 230 project files were created 2026-11-17 to 2026-11-20 (file timestamps). There is no git history to prove it, so start git now. Disclose any pre-existing code (none known). |
| 4 | Submit in one category (Resurrection / Frankenstein / Skeleton Crew / Costume Contest) | **UNDECIDED** | See §14 recommendation. |
| 5 | URL to functional application; credentials if needed | **UNKNOWN / FAIL** | The rules allow "a link to a website, functioning demo, or a test build". There is no hosted instance yet. Needs a decision (§14). |
| 6 | Text description of features and functionality | **MISSING** | Devpost draft not started (ASSUMED; Henok to confirm). |
| 7 | Demo video < 3 minutes, public on YouTube, shows the project working on its device, no copyrighted music or third-party marks | **MISSING** | Depends on G1–G3. |
| 8 | Public GitHub repo with all source, assets and instructions | **FAIL** | Not a git repository (`git status` → "not a git repository"). |
| 9 | Open-source license file, detectable in the GitHub About section | **FAIL** | No `LICENSE*` file. License choice needs Henok's approval. |
| 10 | `/.kiro` directory at repo root, not in `.gitignore` | **PASS (local)** | `.kiro/` exists at the root, and `.gitignore` does not exclude it (VERIFIED). |
| 11 | Write-up on how Kiro was used (IDE, CLI, Web, Crew, agents, hooks, specs, steering, MCP, PBT, powers) | **MISSING** | See §7. |
| 12 | English materials | **PASS (so far)** | All docs are in English. |
| 13 | Third-party integrations authorized | **PASS (ASSUMED)** | Ollama and model licenses must be respected if shown. The default `null` provider has no third-party dependency. |
| 14 | Optional bonuses: Blog, Social Blitz (#KiroweenHackathon26 at the start of the post), Best Demo, Ghost of Kiroween Past (registered for 2025), Student or Startup | **OPTIONAL** | Blog and Social Blitz are cheap if time allows. Eligibility for the other bonuses is UNKNOWN; Henok to confirm. |
| 15 | Registered on Devpost; Kiro credits requested by 2026-12-01 12:00 PT | **UNKNOWN** | Henok to confirm. |
| 16 | Eligibility (age, country) | **UNKNOWN** | Ethiopia is not on the exclusion list quoted in the rules. Henok must confirm personal eligibility. |

**Judging:**

- **Stage 1** is pass/fail on theme fit and use of the required tools.
- **Stage 2** scores five equally weighted criteria: Potential Impact, Technological Implementation (Kiro use), Design, Innovation, Presentation.

---

## 9. Demonstration scenario readiness

**Today none of the three scenarios can be shown in the application.** All three are already proven deterministically in the integration tests, driven by `tests/threat_scenario.py`:

```
NORMAL → CPU ANOMALY → NETWORK ANOMALY → quiet → AUTH FAILURE BURST
       → REPEATED AUTH FAILURES → CRITICAL ESCALATION → RECOVERY
```

That makes the job one of exposing an existing, proven sequence through the orchestrator and demo API, not inventing behavior. Thresholds below are the `.env.example` defaults. Exact score values per step were not re-derived in this audit (ASSUMED ranges; the tests assert the states).

### Scenario 1: Normal activity, RELAXED
| Item | Detail |
|---|---|
| Setup | Fresh database, `DEMO_MODE=true`, `LIVE_ACTIONS=false`, `AI_PROVIDER=null`, then demo reset. |
| Telemetry | Real psutil samples every 2 s. On the demo laptop, idle CPU and RAM are well under the 90% thresholds. |
| Detection | None. |
| Score / state | About 0.0, RELAXED. |
| Response | None. RELAXED alerts only on new evidence (`decision.py`). |
| Dashboard | Green state badge with the "RELAXED" text, live sparklines, "No events" empty state. |
| Proof today | `test_recovery_produces_no_alerts`, `test_decaying_evidence_after_recovery_never_alerts_periodically`, and the NORMAL phase in `threat_scenario.py`. **Not runnable in the app (G1, G2).** |
| Caution | The audit laptop measured 93–98% CPU/RAM under model load in Phase 8.4. Close Ollama and other heavy apps during recording, or real telemetry could fire CPU or memory rules and spoil the RELAXED shot. |

### Scenario 2: Suspicious activity, ALERT then DEFENSIVE
| Item | Detail |
|---|---|
| Setup | Start from Scenario 1. Trigger `cpu_spike`, then an `auth_failure` burst (5 or more in 60 s) from the demo panel. These are synthetic events only. Do not load the real CPU. |
| Detection | Resource rule event, then an authentication-failure rule event with repetition. |
| Score / state | The score crosses 0.25 and holds for 10 s, giving ALERT. With repetition and correlation it crosses 0.55, giving DEFENSIVE. The HIGH floor keeps the state at least ALERT. |
| Response | ALERT: `GENERATE_ALERT`, `INCREASE_MONITORING`, `RECORD_INCIDENT` (the incident opens once). DEFENSIVE adds `SIMULATE_IP_BLOCK` and `SIMULATE_PROCESS_ISOLATE`. All carry guard verdict AUTHORIZED and are simulated. |
| Dashboard | Amber, then orange badge with text and an up-arrow. Events feed. Action log with blue SIMULATED badges. Incident `SIT-n` opened. |
| Proof today | `test_alerts_follow_the_state_path_without_repeating`, `test_the_guard_authorizes_every_action_before_it_is_simulated`, `test_threat_pipeline.py`. |

### Scenario 3: High-severity simulated attack, AGGRESSIVE, audit and AI, then recovery
| Item | Detail |
|---|---|
| Setup | Continue Scenario 2. Inject `suspicious_process` (CRITICAL, label "simulated-malware") while the authentication evidence is active. |
| Detection | CRITICAL synthetic-security event. There are now at least 2 corroborating categories. |
| Score / state | The CRITICAL floor enforces at least DEFENSIVE. The score at or above 0.80 with corroboration gives AGGRESSIVE, one level per evaluation, so every level stays in the audit trail. |
| Response | Adds `SIMULATE_QUARANTINE`, once per situation. Re-delivered decisions create nothing new (idempotency). |
| AI | The explanation worker builds an `IncidentContext` (AS-02 fields only), and `NullProvider` returns deterministic text, which passes the validator and is stored as `VALID`. The dashboard shows "Explanation pending", then the text. Optional: Ollama on capable hardware. CPU-only Ollama timed out in Phase 8.2/8.4, so do not use it live on this laptop. |
| Recovery | Stop injections. The 60 s half-life decay and 30 s cooldown per level take the state down AGGRESSIVE → DEFENSIVE → ALERT → RELAXED. The incident resolves after the reopen window. Roughly 2–4 minutes (ASSUMED). Speed up the video with an on-screen note, or lower the demo timing values through configuration (approval needed). |
| Proof today | `test_the_attack_produces_one_incident_and_each_protective_action_once`, `test_each_attack_is_one_stable_situation_closed_by_recovery`, `test_the_incident_is_resolved_once_the_reopen_window_passes`, `test_explanation_service.py`, `test_incident_api.py`. |

**Video timing risk.** The rules cap the video at 3 minutes, and the spec §16 script runs 5–8 minutes. The demo must be cut to about 2:30, using a speed-up or a "scenario" endpoint that runs the deterministic sequence quickly. Any speed-up must be disclosed on screen.

---

## 10. GitHub and release readiness

| Item | Status | Evidence |
|---|---|---|
| Git repository | **Missing** | `git status` → "fatal: not a git repository" |
| Branches / commit history | **None** | No proof of build history inside the submission period. `coding-standards.md` asks for feature branches and imperative commits. |
| Remote / GitHub | **None** | No remote |
| `.gitignore` | **Good** | Ignores `.env`, `*.db`, caches, `.coverage`, `node_modules`, `dist`, `*.egg-info`. Keeps `.env.example`. Does **not** ignore `.kiro/`. Note: `*.xml` is ignored globally (harmless today). |
| Secrets exposure | **Clean** | Scan of 229 text files: 0 key or token patterns and 0 personal paths. No `.env` exists. `.env.example` has no secret values. |
| Files that should not be committed | Ignored correctly | `backend/.coverage`, `.hypothesis/`, `.mypy_cache/`, `heduglena_sentinel.egg-info/` are all covered by `.gitignore`. Verify with `git status` after `git init`. |
| LICENSE | **Missing** | Required by the rules. Recommend MIT or Apache-2.0 (Henok to choose). |
| README | **Misleading** | Describes a Docker stack, dashboard, demo panel, Playwright and an orchestrator that don't exist. The placeholder `git clone <repo-url>` needs a real URL. |
| Dependency files | Partial | `backend/pyproject.toml` has lower bounds only and no lock file. `frontend/package.json` has no lock file, and `npm ci` in the Dockerfile requires one. |
| Environment config | Good | `.env.example` documents about 80 variables. Settings validate at startup (`core/config.py` validators). |
| Install reproducibility | **Unverified / failing** | Python 3.11 untested. Docker fails (G8). There is no migration step (G5). |
| CI | **Missing** | No `.github/workflows`. `testing-requirements.md` requires 8 CI steps. |

---

## 11. Readiness scores with evidence

| Area | Score | Evidence |
|---|---|---|
| Product completeness | **3 / 10** | All domain stages exist and pass tests. The running app executes none of them (G1). There is no UI (G2) and no demo control (G3). 5 of 20 routes exist. |
| Technological implementation (engineering) | **7 / 10** | Clean ports-and-adapters design, deterministic clock-free services, idempotent append-only audit, layered live-action refusal, AS-02 allow-list context, restart recovery. Points are lost because nothing is integrated. |
| Security | **8 / 10** | Bandit 0 issues. Guard plus executor give two-layer live refusal. The validator rejects whole answers. `SecretStr` keys, 0 secrets in files, 15 security test files, pinned hashes. Gaps: no demo 403 guard yet (no endpoints), no log-masking formatter. |
| Reliability | **5 / 10** | 2,011 tests pass, and restart and idempotency are tested. But there is no runtime loop, no schema bootstrap, broken Docker, Python 3.11 untested, a 9-minute suite, and empty performance tests. |
| Dashboard / UI | **1 / 10** | Types file only. |
| Kiro integration | **4 / 10** | Steering is real and active, and the spec is detailed. The hooks are not in Kiro's schema, the spec is not in Kiro's format, there are no agents or MCP, PBT is limited to one file, and there is no write-up. |
| Documentation | **4 / 10** | The spec, steering and Phase 8.5 plan are strong. The README overclaims. There is no LICENSE, no install guide that works, and no Kiro write-up. |
| Demonstration readiness | **2 / 10** | All scenarios are proven in tests and none can be shown. There is no video plan that fits 3 minutes. |
| Submission readiness | **2 / 10** | No git, GitHub, license, video, Devpost text or app URL. `.kiro/` is present. Timing eligibility is likely fine. |
| **Overall** | **3.5 / 10** | Unweighted mean of the nine scores (3.6), rounded down: completeness, demo and submission readiness dominate what judges see. |

Projected score if the roadmap in §12 is completed: **about 7.5–8 / 10** (ASSUMED).

---

## 12. Prioritized remediation roadmap

Protected modules (`threat/scorer.py`, `threat/state_machine.py`, `response/planner.py`, `response/guard.py`, `response/executor.py`, `ai/validator.py`, and the AI safety boundaries) **must not change** in any item below. Each item adds code *around* them.

### CRITICAL: blocks a safe, working submission

| ID | Improvement | Benefit | Files / modules likely involved | Risk | Effort | Depends on | Approval needed |
|---|---|---|---|---|---|---|---|
| C1 | `git init`, a feature-branch workflow, an open-source **LICENSE**, and a GitHub repository (private until release, then public) | Meets the rules (#8, #9). Starts provable build history now. | `LICENSE` (new), `.git/` | Low. Run `git status` before the first commit to confirm ignored files stay out. | 0.5 h | Henok chooses the license and the repo name | **Yes** (license, visibility, commits) |
| C2 | **Runtime orchestrator** in the app lifespan: collector loop → `DetectionEngine` → `ThreatAssessmentService.assess(now)` → `ResponseService.handle()` → `ExplanationService.observe()`. Restore state at startup. Shut down cleanly. Fail-safe per stage (P-04). Correlation-ID logging. | The application actually runs. Prerequisite for everything visible. | New `backend/core/orchestrator.py` (or `backend/runtime/`), `app/main.py`, tests in `tests/integration/test_orchestrator.py` | **Medium.** First runtime driver of the protected modules. A single SQLite writer, the event loop and the shutdown order need care. Reuse the `threat_scenario.py` wiring. | 1.5–2 d | — | **Yes** (security review: touches the order in which the response and AI paths are called) |
| C3 | **Schema bootstrap.** Run `alembic upgrade head` at startup or as an entrypoint, and document it. | A fresh clone works. | `app/main.py` or `backend/entrypoint` script, README | Low–Medium. Must never auto-drop data. Back up the database before running a migration. | 2–3 h | C2 | **Yes** (migration behavior) |
| C4 | **Read API** per spec §13.2: status, telemetry latest/history, events, score current/history, state current/history, actions, rules. Bounded queries, Pydantic responses, read services in the domain (P-06). Plus **CORS** from `FRONTEND_ORIGIN`. | Gives the dashboard its data. Meets the integration-test steering. | `backend/api/v1/{status,telemetry,events,threat,actions,rules}.py`, read services, `app/main.py`, tests | Low. Read-only. Must not leak DB paths or config (SR-06). | 1–1.5 d | C2 | Yes (scope). Rule enable/disable `PUT` optional, see M8. |
| C5 | **Demo API**: `POST /demo/inject` (allowlist → 422), `/demo/scenario/{name}` (DS-01…DS-06 or the 3 key scenarios), `/demo/reset`. Return 403 when `DEMO_MODE=false`. Events enter through `DetectionEngine.process_synthetic()` (P-10). | Makes the demo possible without terminal access. | `backend/api/v1/demo.py`, new `backend/demo/scenarios.py` (reusing the `threat_scenario.py` logic), `tests/security/test_demo_mode_guard.py` | **Medium.** It must remain synthetic only. Reset must touch only in-memory state and never delete audit rows (P-07), or be explicitly designed and approved. | 1 d | C2 | **Yes** (security-sensitive; reset semantics) |
| C6 | **Dashboard MVP**: header badge plus gauge, score timeline, state history, events feed, action log (SIMULATED badge), incident list and detail, AI panel (pending, available or fallback), demo panel, empty and error states. React Query polling every 2 s. | Covers the Design and Presentation criteria and the video. | `frontend/index.html`, `src/main.tsx`, `src/pages/Dashboard.tsx`, `src/components/dashboard/*`, `src/hooks/*`, `src/services/api.ts`, `tailwind.config.js`, `package-lock.json`, Vitest tests for the 5 core components | Medium (time). No security risk if it only displays API data (P-08). | 3–4 d | C4, C5 | Yes (dependency install, design direction) |
| C7 | **Submission package**: demo video under 3 minutes (YouTube, public), Devpost description, Kiro usage write-up, category choice | Required by the rules (#6, #7, #11) | `docs/hackathon/KIRO_USAGE.md`, `docs/hackathon/DEMO_SCRIPT.md`, Devpost | Low | 1–1.5 d | C2–C6 | Yes (publishing) |

### HIGH: substantially weakens the submission

| ID | Improvement | Benefit | Files | Risk | Effort | Depends on | Approval |
|---|---|---|---|---|---|---|---|
| H1 | Rewrite the hooks in the documented v1 schema (`version`, `hooks[]`, `trigger`, `matcher`, `action`), with correct `backend/` paths. Use them during C2–C6 and capture evidence. | Real Kiro hook usage for Technological Implementation | `.kiro/hooks/*.json` | Low. Hooks run commands, so keep them read-only (lint, type-check, test). | 2–3 h | — | **Yes** (configuration change) |
| H2 | Kiro-format specs for the remaining work: `.kiro/specs/runtime-orchestrator/`, `api-and-demo/`, `dashboard/`, each with `requirements.md` (EARS), `design.md`, `tasks.md`. Execute the tasks through Kiro. Keep `sentinel-spec.md` as the master spec. | Genuine spec-driven evidence that Kiro's Specs panel shows | `.kiro/specs/*/` | Low | 0.5 d (alongside C2–C6) | — | Yes |
| H3 | Rewrite the README to match reality: a working quick start, the migration step, demo steps, architecture diagram, the safety model, links to the Kiro write-up. Remove unbuilt claims (Playwright, unbuilt scenarios). | Meets the rule that the project function as described | `README.md` | Low | 3–4 h | C2–C6 | Yes |
| H4 | Fix Docker: a Python-based healthcheck in compose, the frontend lock file and app, a non-root user (already done), the migration entrypoint. Verify `docker compose up --build` from a clean clone. | Judges can install it (rule #2) | `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile` | Low–Medium | 0.5 d | C3, C6 | Yes |
| H5 | A clean-clone install test on **Python 3.11 or 3.12** in a venv (pyproject targets 3.11, and only 3.14 was tested) | Confirms the code runs on the versions it claims | none (verification) | Low | 1–2 h | C1 | Yes (venv and dependency install) |
| H6 | A Kiroween visual theme (dark, bioluminescent Euglena motif, spooky but readable, color plus text labels) | Design and Innovation scores; fits the theme | `frontend/src/**`, `tailwind.config.js` | Low | 0.5–1 d | C6 | Yes |

### MEDIUM: should be improved before submission

| ID | Improvement | Benefit | Files | Risk | Effort | Approval |
|---|---|---|---|---|---|---|
| M1 | Structured logging config (`structlog` or stdlib JSON) with a formatter that masks `*_KEY`, `*_SECRET` and `*_TOKEN` (SR-04, P-09) | Steering compliance; logs read well in the video | `backend/core/logging.py`, `app/main.py` | Low | 3–4 h | Yes |
| M2 | GitHub Actions CI covering the 8 steps in `testing-requirements.md` (ruff, mypy, pytest unit/integration/security, bandit, tsc, vitest) | A visible quality signal | `.github/workflows/ci.yml` | Low | 2–3 h | Yes |
| M3 | Optional WebSocket `/ws/live` (spec §13.3); polling already satisfies the MVP | More "live" feel | `backend/api/ws.py`, `src/hooks/useLive.ts` | Medium (concurrency) | 0.5–1 d | Yes |
| M4 | One custom Kiro agent used for real, for example a read-only `security-reviewer` that runs on every PR touching `response/` or `ai/` | Kiro feature variety | `.kiro/agents/security-reviewer.md` | Low | 1–2 h | Yes |
| M5 | Missing test fixtures and the performance tests listed in the testing steering | Steering compliance | `tests/fixtures/*.json`, `tests/performance/*` | Low | 0.5 d | Yes |
| M6 | Demo timing profile: a documented `.env.demo` with shorter dwell, cooldown and half-life so recovery fits the video. It must not change code or production defaults. | Recovery fits in 3 minutes | `.env.demo.example` (new) | Low. It is a demo profile, clearly labeled. | 1 h | **Yes** (threshold values are security parameters) |
| M7 | Decide whether `reports/phase8.*/debug/` raw model output is published | Avoids publishing confusing artifacts | `reports/` | Low | 15 min | Yes |
| M8 | Rules enable/disable `PUT` (spec §13.2). It changes detection behavior at runtime, so treat it as security-sensitive. Defer or protect it with `DEMO_MODE`. | Spec completeness | `api/v1/rules.py` | Medium | 2–3 h | **Yes** |

### LOW: optional polish

| ID | Improvement | Effort |
|---|---|---|
| L1 | Fix the 9 Phase 1 ruff findings (alembic files plus one test F841). Never run `ruff format` or `--fix` on `guard.py`. | 15 min |
| L2 | Clean up the 125 mypy-strict errors in test files | 2–3 h |
| L3 | Pin upper bounds or add a lock file for the backend (`uv lock` or `pip-tools`) | 1 h |
| L4 | Blog post and #KiroweenHackathon26 social post (bonus prizes) | 1–2 h |
| L5 | Demo-video polish (captions, narration, no copyrighted music) | 2 h |

---

## 13. Suggested daily schedule through 4 December

Times are EAT (UTC+3). The deadline is **Sat 5 Dec 01:00 EAT** (Fri 4 Dec 14:00 PT). The target is to submit by **Thu 3 Dec**, leaving a full day of buffer.

| Date | Focus | Exit criterion |
|---|---|---|
| Fri 20 Nov | Review this audit. Approve or reject items. Choose the license and category. C1: git init, first commit, private GitHub repo. | Repo exists. `git status` is clean, with ignored files absent. |
| Sat 21 Nov | H1 (fix hooks), H2 (Kiro specs for orchestrator, API and dashboard). Start C2. | Hooks run in Kiro. `requirements.md`, `design.md` and `tasks.md` exist for C2. |
| Sun 22 Nov | C2 orchestrator plus tests. C3 schema bootstrap. | The app runs the pipeline on real telemetry. Incidents appear via the existing API. Full suite green, hashes unchanged. |
| Mon 23 Nov | C4 read API plus CORS plus tests. | All read endpoints return data. Integration tests cover happy and error paths. |
| Tue 24 Nov | C5 demo API plus security tests (403, 422, synthetic-only). M6 demo profile (if approved). | All 3 scenarios run end to end via HTTP, and you can watch them in the API. |
| Wed 25 Nov | C6 dashboard scaffold: Vite app, layout, React Query, API client, header, events feed, action log. | The dashboard shows live data. |
| Thu 26 Nov | C6: state and score timeline, incident and AI panel, demo panel, empty and error states. | Scenarios 1–3 can be driven from the UI. |
| Fri 27 Nov | H6 Kiroween theme. Vitest component tests. Accessibility pass (color plus text). | Polished UI. `tsc --noEmit` and `vitest run` green. |
| Sat 28 Nov | H4 Docker, H5 clean-clone install on Python 3.11/3.12. M1 logging. | `docker compose up --build` works from a fresh clone. |
| Sun 29 Nov | **Feature freeze.** Full rehearsal of the 3 scenarios, ×3 runs, deterministic. Bug fixes only. M2 CI. | 3 clean rehearsals. CI green. |
| Mon 30 Nov | H3 README rewrite. `docs/hackathon/KIRO_USAGE.md`. Demo script under 2:45. | Docs match reality. |
| **Tue 1 Dec** | **Kiro credit request deadline: 1 Dec 12:00 PT (23:00 EAT).** Record the video (several takes). | Final cut under 3:00. |
| Wed 2 Dec | Upload the video to YouTube (public). Draft Devpost: description, category, Kiro write-up, links. Make the repo public; confirm the license shows in the About section. | Devpost draft complete. |
| **Thu 3 Dec** | Final clean-clone test from the public URL. **Submit on Devpost.** Optional: blog and social post. | Submitted. |
| Fri 4 Dec | Buffer only. Read-only checks of the links. No code changes. | Submission period closes 14:00 PT (Sat 01:00 EAT). |

---

## 14. Recommended final submission strategy

1. **Category: Frankenstein** (recommendation; Henok decides). Sentinel stitches together elements that rarely meet: a biological adaptation model (Euglena posture switching), a deterministic security state machine, guarded simulated response, and a strictly downstream LLM narrator. Choose Costume Contest only if the UI becomes outstanding. With no UI today, that is the riskier bet.
2. **Pitch: "an immune system that explains itself, and can't be talked into acting."** Lead with the problem: small teams and individual users cannot read raw alerts. Show the posture adapting, then the AI explaining. Then show the safety story: AI output can't reach execution, live actions are refused in two layers, and every action is labeled SIMULATED. That third point sets Sentinel apart from typical "AI security agent" entries.
3. **Demo honesty.** Use synthetic events only and say so on screen. Show the SIMULATED badges. Use the deterministic `null` provider in the video unless a GPU-backed model has passed the Phase 8 gates. Present Phase 8 as evidence of rigor: "we measured local models and refused to ship one that failed our gates".
4. **Application URL.** The rules accept "a link to a website, functioning demo, or a test build". The lowest-risk option is the public GitHub repo with a one-command Docker or venv run plus the video. A hosted demo (demo mode, `null` AI, rate limits) would help judges, but it adds exposure and needs a deployment decision. UNKNOWN whether a hosted URL is effectively required. Ask the Devpost hackathon manager.
5. **Kiro story.** Show steering as the source of the security invariants, tests that keep steering and code in sync, Kiro-format specs and tasks for the final phases, working hooks, PBT, and an optional custom agent. Every claim must point to a file in the repo.
6. **Scope discipline.** WebSocket, rule toggling, performance tests and GPU benchmarking are not needed to win. Cut them before risking the freeze date.
7. **Security invariants.** Re-check the `guard.py` and `validator.py` hashes and run the security suite at every phase gate and immediately before submission.

---

## Appendix A: Files and commands inspected

**Read in full or in part:**

- **Root:** `README.md`, `.gitignore`, `.env.example` (key names only), `docker-compose.yml`
- **Backend build and app:**
  - `backend/pyproject.toml`, `backend/Dockerfile`, `backend/alembic.ini`
  - `backend/app/main.py`, `backend/api/v1/incidents.py`, `backend/core/config.py`
  - `backend/database/engine.py`, `backend/models/enums.py`
- **Backend pipeline stages:**
  - `backend/telemetry/collector.py`, `backend/telemetry/providers/psutil_provider.py`
  - `backend/detection/engine.py`, `backend/detection/synthetic.py`
  - `backend/threat/service.py`, `backend/threat/state_machine.py`, `backend/threat/decision.py`, `backend/threat/config.py`
  - `backend/response/service.py`, `backend/response/planner.py`, `backend/response/executor.py`, `backend/response/actions.py`
  - `backend/explanation/service.py`, `backend/ai/factory.py`, `backend/ai/explainer.py`
- **Tests:** `backend/tests/integration/test_response_pipeline.py` (header and test names), `backend/tests/threat_scenario.py` (header)
- **Frontend:** `frontend/package.json`, `vite.config.ts`, `tsconfig.json`, `Dockerfile`, `tests/setup.ts`, `src/types/api.ts` (exports)
- **Kiro:** `.kiro/hooks/*.json` (all 5), `.kiro/specs/sentinel-spec.md` (headings and §13, §14, §16–18). The 5 steering files were injected as rules.
- **External:** https://kiroween.devpost.com/rules, plus kiro.dev documentation via the Kiro docs agent (hooks, specs, steering, agents, MCP)

**Read-only commands:**

- **Listings:** directory and file listings, file timestamps, encoding check
- **Searches:** grep over the source for routers, loops, service instantiation, CORS and logging
- **Scans:** secret and personal-path scan (Python, read-only)
- **Integrity:** SHA-256 of the protected files
- **Not run, by design:** `git status` / `branch` / `remote` all reported that the folder is not a repository

## Appendix B: Tests and checks run

| Command (from `backend/`) | Result |
|---|---|
| `python -m pytest -q -p no:cacheprovider -o addopts=""` | 2,011 passed, 0 failed, 4,626 warnings (12 DeprecationWarning types from FastAPI and pytest-asyncio on Python 3.14), 536.8 s |
| `python -m mypy --strict <12 source packages>` (temp cache dir) | Success: 0 issues in 88 source files |
| `python -m mypy --strict .` (temp cache dir) | 125 errors in 25 files, all under `tests/` |
| `python -m bandit -r . -x ./tests,./.hypothesis,./.mypy_cache` | 0 Low / 0 Medium / 0 High, 11,450 LOC |
| `python -m ruff check . --no-cache` | 9 pre-existing findings (no fixes applied) |

No benchmark, model call, migration, install, `ruff --fix` or `ruff format` was run. The pytest run uses in-memory or temporary SQLite and fake providers. Hypothesis may have refreshed its local example cache in `backend/.hypothesis/`, which is gitignored.

## Appendix C: Integrity confirmation

| File | SHA-256 before and after audit |
|---|---|
| `backend/response/guard.py` | `F91996F1D4651CAA42135D13ABA37B3173CFE367EFA9A0F360BB7A680F04A14F` |
| `backend/ai/validator.py` | `BC4A601CC1C700C4A754A0EAD7A07ADE300221DDDE1C1377E356FDE9EC0EA0E5` |

The only file created is `docs/hackathon/KIROWEEN_READINESS_AUDIT.md`. No other project file was modified.

