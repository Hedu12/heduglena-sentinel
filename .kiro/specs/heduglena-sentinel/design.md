# Design Document — HEDUGLENA Sentinel

This is the authoritative statement of Sentinel's architecture, security boundaries and protected
files. Detailed algorithms, schemas and parameters are not repeated here; each section points to
the master reference (`../sentinel-spec.md`, cited as §n) or the steering file that defines them.

Status markers: **BUILT** = implemented and covered by passing tests (verified 2026-11-20);
**PLANNED** = specified, not yet implemented.

## 1. Overview

```
            ┌──────────────── Security decision pipeline (deterministic, authoritative) ───────────────┐
 psutil /   │                                                                                           │
 synthetic ─┼─► TelemetryCollector ─► DetectionEngine ─► ThreatAssessmentService ─► Decision           │
 events     │   telemetry/            detection/         threat/ (scorer + state_machine)   │           │
            │                                                                               ▼           │
            │                    ResponseService ─► ResponsePlanner ─► ResponseGuard ─► SimulatedActionExecutor
            │                    response/                             guard.py          executor.py    │
            └───────────────────────────────────────────────┬───────────────────────────────────────────┘
                                                            │ Decision (observe only; one-way)
                                                            ▼
            ExplanationService ─► ContextBuilder (AS-02 allow-list) ─► Explainer ─► AIOutputValidator
            explanation/                                               ai/          validator.py
                                                            │
                         SQLite (SQLAlchemy 2 async, Alembic; append-only audit tables)
                                                            │
            FastAPI read + demo API  ─►  React dashboard  (display only, P-08)
```

| Component | Package | Status |
|---|---|---|
| Telemetry collection, validation, graceful degradation | `backend/telemetry/` | BUILT |
| Detection engine, rules, synthetic events | `backend/detection/` | BUILT |
| Threat scoring, defense state machine, decision, situations | `backend/threat/` | BUILT |
| Response planning, guard, simulated execution, incidents | `backend/response/` | BUILT |
| Explanation service, context builder, AI adapters, validator | `backend/explanation/`, `backend/ai/` | BUILT |
| Persistence and migrations (head `f8b5d2c30008`) | `backend/database/`, `backend/alembic/` | BUILT |
| Offline evaluation harness | `backend/evaluation/` | BUILT |
| Incident and explanation read API | `backend/api/v1/incidents.py` | BUILT |
| Runtime orchestrator (composition root), lifespan, fresh-schema bootstrap | `backend/app/runtime.py`, `backend/app/main.py`, `backend/database/bootstrap.py` | BUILT (Phase 2) |
| Current-state read API (status, runtime, state, score, telemetry, events, actions), CORS | `backend/api/v1/runtime.py` | BUILT (Phase 2) |
| History endpoints, rules API | `backend/api/v1/` | PLANNED |
| Demo API (inject, scenarios); reset pending a decision | `backend/api/v1/demo.py`, `backend/core/demo.py` | BUILT (Phase 2) |
| Live stream `WS /ws/live` | `backend/api/v1/live.py`, `backend/core/live.py` | BUILT (Phase 2) |
| Dashboard (React 18 + TypeScript + Vite, React Query, observation-only WebSocket) | `frontend/src/` | BUILT (Phase 3) |

## 2. Authoritative security decision pipeline

The pipeline in §1 is the **only** path that can change the defense state or record a response
(Requirement 5). Its invariants:

1. **Order.** telemetry → detection → threat scoring → defense state machine → decision →
   ResponsePlanner → ResponseGuard → SimulatedActionExecutor. No stage calls past its successor;
   the orchestrator connects them (P-01). Synthetic events enter at `DetectionEngine.process_synthetic()`
   (P-10).
2. **Determinism.** `ThreatAssessmentService.assess(events, now)` reads no clock; the caller passes
   `now`. The same events produce the same decisions (AC-F03-5). Scoring: §8, §9.3 and their
   revisions; parameters: `backend/threat/config.py` and `.env.example`.
3. **Hysteresis.** Fast, one-level-per-evaluation climb after the dwell; severity floors; corroborated
   bypass into AGGRESSIVE; slow, cooldown-gated descent (§9.1, §9.3, Requirement 4).
4. **Idempotency and append-only audit.** Each planned action has a scope, a once-key and an
   idempotency key; each action is its own transaction; audit tables are never updated in place
   (P-07; Phase 5).
5. **Restart stability.** State is restored from persisted transitions; explanation triggers are
   decided from persisted `ai_explanations` rows, not process memory (Phase 4, Phase 6.1).

## 3. Security boundaries

### 3.1 Simulated-only response execution
- `ResponseGuard` (`backend/response/guard.py`) is the single authorization point (P-05). It blocks
  `LIVE_PROTECTIVE` unless `LIVE_ACTIONS=true`, which defaults to `false` (SR-01, §11.2).
- `SimulatedActionExecutor` (`backend/response/executor.py`) has no live handler
  (`LIVE_EXECUTION_SUPPORTED` is false) and `ensure_simulated()` refuses any live verdict even if the
  guard allowed it. Setting `LIVE_ACTIONS=true` logs a warning and still executes nothing live.
- Every action record carries `is_simulated` and a dry-run description (§11.3).

### 3.2 Explanation-only LLM boundary
- **One-way dependency:** security domain → `explanation/` → `ai/`. Nothing in `threat/`,
  `response/`, `detection/` or `telemetry/` imports either (§10.5 revision).
- `ExplanationService.observe()` is synchronous, never awaits a provider and never raises, so a
  slow or failing AI cannot delay or alter scoring, state or responses.
- **Context:** only the AS-02 allow-list (`backend/ai/context.py`), JSON-serialized (AS-08).
  `tests/security/test_as02_sync.py` fails if the code and `ai-safety-requirements.md` drift apart.
- **Output:** size → JSON → strict schema → explanation-only policy → `AIOutputValidator`
  (`backend/ai/validator.py`). Any failure or any redaction rejects the whole answer. `raw_response`
  is an audit artifact only (AS-07).
- **Provider:** `null` by default (offline, deterministic); `ollama` and `openai` through the same
  OpenAI-compatible adapter; `openai` requires an explicit opt-in and key (AS-09).

### 3.3 Input, secrets and data isolation
Pydantic validation and parameterized queries (SR-03); secrets only from the environment as
`SecretStr` (SR-04); no database path, configuration or secret in API responses (SR-06); demo
routes return 403 when `DEMO_MODE=false`, before any input is read (SR-08); the live
WebSocket refuses foreign browser origins.

## 4. Protected modules and files

These must not change without Henok's explicit approval after a security review (Requirement 9).
Hashes recorded 2026-11-20 at the Phase 1 baseline commit `469f953`.

| Protected item | File | SHA-256 | Enforced by |
|---|---|---|---|
| ResponseGuard | `backend/response/guard.py` | `F91996F1D4651CAA42135D13ABA37B3173CFE367EFA9A0F360BB7A680F04A14F` | `test_guard_integrity.py` (pinned) |
| AIOutputValidator | `backend/ai/validator.py` | `BC4A601CC1C700C4A754A0EAD7A07ADE300221DDDE1C1377E356FDE9EC0EA0E5` | `test_validator_integrity.py` (pinned) |
| Threat scoring | `backend/threat/scorer.py` | `69828D896473D169C588A06F09FA6C1849F6C86B61F87D11B359D693F181C575` | threat unit, property and safety tests |
| Defense state machine | `backend/threat/state_machine.py` | `02E05FAAA2F0E6AD034C502A8AF07E71CBEF45C0178E98E04B8DF36E597647C4` | `test_threat_state_machine.py` |
| ResponsePlanner | `backend/response/planner.py` | `399E181E3538DD90EBB5AA1BEA3843B59F68B856AE5C30195A0D2E27A8587CD4` | `test_response_planner.py` |
| SimulatedActionExecutor | `backend/response/executor.py` | `D27044DC8E5908BD79EB8CB3F464BD381B5AE823481C6AF7BBEFB1B96A5A996B` | `test_no_live_response.py`, `test_response_executor.py` |
| Evaluation scoring | `backend/evaluation/metrics.py` | `D30B6EE5C47EEA8488C9E091D5B7A13DF1F0C1BE07BD97DCCAC1F3D694E71155` | `test_eval_metrics.py` |
| Evaluation gates and selection | `backend/evaluation/selection.py` | `7E100842DDE0CFE84B796256BF90F725532212DC9093BF7F2151556A22F41FBB` | `test_eval_selection.py` |

Also protected as **behavior**: AI safety boundaries (§3.2), thresholds and hysteresis parameters,
the `production-v1` evaluation profile, and the AS-01 system prompt. The two pinned files are stored
byte-exact in git (`.gitattributes` `-text`). Only the first two have hash-pinning tests; changes
to the other files are caught by their behavior tests and by the `security-boundary-review` hook.
Never run `ruff format` or `ruff --fix` on `guard.py`.

## 5. Data model and API

- **Database:** §12 plus migrations in `backend/alembic/versions/` (authoritative for the current
  schema). Database CHECK constraints enforce enum values, the `content`-only-when-VALID rule and the
  `raw_response` cap.
- **API:** §13. Built today: `GET /health`, `GET /api/v1/incidents`, `/incidents/{id}`,
  `/ai/explain/{id}`, `/ai/status`, all read-only with validated path and query parameters.
  The remaining §13.2 groups, CORS (§13.4) and the optional WebSocket (§13.3) are PLANNED.
- **Frontend contract:** `frontend/src/types/api.ts` mirrors the Pydantic schemas (P-08).

## 6. Runtime integration (Phase 2, BUILT)

- **Orchestrator** (`app/runtime.py`): the composition root, in `app/` because it wires the
  security domain to the explanation layer and `core/` is part of the security domain, which must
  never import `ai/` or `explanation/` (`tests/security/test_ai_boundary.py`). Started and stopped
  by the FastAPI lifespan. Each
  monitoring cycle and each synthetic event runs, under one `asyncio.Lock`, through detection →
  `assess(now)` → `ResponseService.handle()` → `ExplanationService.observe()`, then publishes
  sanitized read models to the live hub. It restores state at startup, logs and counts a failing
  cycle and keeps monitoring (P-04), and contains no detection, scoring, state, response or AI logic.
  Background tasks (monitor, explanation worker, one demo scenario) are cancelled and awaited on
  shutdown.
- **Schema bootstrap** (`database/bootstrap.py`): an empty database is created by the Alembic
  migrations on the application's connection; a database at head is used as is; anything else
  refuses to start. Nothing is migrated, altered or dropped automatically.
- **Demo API**: security synthetic types only (422 otherwise), 403 when `DEMO_MODE=false`,
  rate-limited (TM-02), one scenario at a time.
- **Demo reset** (Phase 3.1, `app/demo_reset.py`): *session rotation*, not state manipulation.
  It (1) refuses unless `DEMO_MODE=true` and the database is a local SQLite file, and accepts no
  input (422 for any body or query); (2) stops the session through `app/lifecycle.stop_session`;
  (3) archives the database file intact into `<name>-demo-sessions/session-<UTC>/` (rename, never
  delete; a file still held open is retried, and on failure the old session is resumed);
  (4) starts a new session through `start_session`, the same path as application startup.
  It **may clear** only the active session: it replaces the session database (preserved in the
  archive) and the in-memory runtime (new detection, threat, response, explanation and live
  instances). It **does not bypass the state machine**: it never calls the scorer, the state
  machine, the planner, the guard or the executor, and writes no state, score, transition or
  response; the new state is produced by `ThreatAssessmentService.restore_state()` from an empty
  history, so it is whatever the authoritative pipeline derives (RELAXED). Restoring an archived
  session with the same code yields its escalated state again (tested). The demo rate limiter
  carries over. While no runtime is attached the read endpoints answer 503; live clients are
  closed with 1012 and reconnect to the new runtime.
- **Production CSP** (Phase 3.1, `frontend/config/csp.ts`): `default-src 'none'`, `'self'` for
  scripts, styles, images, fonts and `connect-src` (API and same-origin `/ws/live`), plus explicit
  origins only when configured; no `unsafe-eval` or `unsafe-inline`. Delivered as a build-time meta
  tag, as `dist/serve.json` headers for `serve -s dist`, and as `vite preview` headers; any other
  host must set the response header itself (README).
- **Live stream**: `WS /ws/live`, receive-only, bounded drop-oldest queues per client, origin check,
  subscriber limit.
- **Dashboard** (Phase 3, BUILT): `services/` (typed REST client, observation-only `LiveClient`
  that validates, de-duplicates and reconnects), `hooks/` (one `LiveProvider`; React Query reads
  that refresh on live events and poll at a bounded rate only while the stream is down),
  `features/` (one folder per pipeline stage), `components/` (panels, text-carrying badges,
  loading, empty and error states). It computes no score and decides no state (P-08); the only
  writes are the deliberate demo POSTs. State colors are always paired with text; responses are
  always labeled SIMULATED and demo events SYNTHETIC.

## 7. Error handling

P-04 fail-safe defaults: telemetry failure → partial sample; rule failure → isolated and counted;
database write failure → cooldowns released, retry; AI failure → deterministic fallback, incident
creation never blocked (AS-06).

## 8. Testing strategy

Authoritative: `.kiro/steering/testing-requirements.md` and §15. Current evidence (2026-11-20):
2,011 backend tests pass (32 unit, 19 integration and 14 security test files); `mypy --strict` clean on 88
source files; Bandit 0 findings; property-based tests in `tests/unit/test_threat_properties.py`.
Known gaps are tracked in `tasks.md`.

**Automated checks (Kiro hooks, `.kiro/hooks/`, all read-only):** ruff check and mypy on every
backend Python file the agent saves; bandit plus an agent boundary review on the security-sensitive
packages; ESLint on frontend files (only when installed locally); a spec and steering impact
review; and an opt-in full quality gate when the agent finishes a turn. Hook logic is in
`scripts/hooks/check.py`, which never fixes, formats, installs or downloads anything.
