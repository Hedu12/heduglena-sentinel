# Implementation Plan — HEDUGLENA Sentinel

Checked tasks are complete and verified: all 2,011 backend tests passed on 2026-11-20, and the
code was inspected in the readiness audit (`docs/hackathon/KIROWEEN_READINESS_AUDIT.md`).
Unchecked tasks are open. Every task must keep the protected files in `design.md` §4 unchanged,
unless Henok explicitly approves a change after a security review. Tasks marked **(approval)**
need Henok's go-ahead before they start.

## Completed foundation (development phases 1–8.5.1)

- [x] 1. Database foundation: SQLAlchemy 2 async models, repositories, Alembic migrations
  - _Requirements: 5.4, 14.2, 17.2_
- [x] 2. Telemetry collection with validation, rate metrics and graceful degradation
  - psutil and fake providers behind a protocol; failing metrics become null with a warning
  - _Requirements: 1.3, 1.4, 1.5_
- [x] 3. Detection engine with resource, process, network and synthetic rules
  - Failure isolation, cooldowns, cooldown release on failed persistence, synthetic allowlist
  - _Requirements: 2.2, 2.6, 2.7, 5.5_
- [x] 4. Threat scoring, defense state machine, decisions and situations
  - Deterministic, clock-free scoring; dwell, floors, corroborated bypass, cooldown descent;
    restart restore; property-based tests (`tests/unit/test_threat_properties.py`)
  - _Requirements: 3.1–3.5, 4.1–4.6, 4.8_
- [x] 5. Guarded simulated response: planner, ResponseGuard, SimulatedActionExecutor
  - Idempotency, once-per-situation dedup, cooldowns, `LIVE_ACTIONS` refusal in two layers
  - _Requirements: 5.3, 6.1–6.8_
- [x] 6. Incident lifecycle: open, automatic resolution, no reopening
  - _Requirements: 7.1–7.3_
- [x] 7. Explanation-only AI layer
  - AS-02 context, fixed system prompt, strict output schema, whole-answer rejection on any
    redaction, raw response for audit only, background worker, restart-stable triggers
  - _Requirements: 8.1–8.7, 8.10_
- [x] 8. Read-only incident and explanation API (`/api/v1/incidents`, `/ai/explain/{id}`, `/ai/status`)
  - _Requirements: 10.2, 10.3, 10.4 (for these routes)_
- [x] 9. Offline evaluation framework, benchmark v2 and model selection
  - BASELINE class for `null`, UNMEASURED distinct from FAIL, inference-environment metadata.
    Both local CPU models are NOT READY (100% timeouts); GPU benchmarking is postponed.
  - _Requirements: 15.1–15.5_

## Phase 1 — Project foundation and Kiro governance

- [x] 10. Initialize local git with a safe `.gitignore` and `.gitattributes`, and commit the baseline
  - Baseline commit `469f953` on `main`. The pinned files are stored byte-exact.
  - _Requirements: 9.3, 13.2, 18.2_
- [x] 11. Rewrite the five Kiro hooks in the documented v1 schema, with a read-only helper
  - `.kiro/hooks/*.json` call `scripts/hooks/check.py`. Validated against the kiro.dev schema
    and observed firing in Kiro IDE 1.5.11.
  - _Requirements: 9.1, 16.4_
- [x] 12. Restructure the specification into Kiro format (`requirements.md`, `design.md`, `tasks.md`)
  - `../sentinel-spec.md` is kept unchanged as the master reference
- [ ] 13. Choose and add an open-source LICENSE **(approval: Henok chooses the license)**
  - _Requirements: 18.2_
- [ ] 14. Create the GitHub repository and push **(approval: visibility and timing)**
  - _Requirements: 18.2_

## Phase 2 — Runtime integration

- [x] 15. Build the runtime orchestrator (`backend/app/runtime.py`, the composition root)
  - Started and stopped by the FastAPI lifespan; collector → detection → `assess(now)` →
    `ResponseService.handle()` → `ExplanationService.observe()`, under one lock
  - Restores state at startup; one failing cycle is logged, counted and survived
  - Tests: `tests/integration/test_runtime_orchestrator.py`, `test_runtime_api.py`,
    `tests/security/test_runtime_safety.py`, `tests/unit/test_runtime_components.py`
  - Correlation IDs in logs remain open under task 17
  - _Requirements: 5.1, 5.2, 14.1_
- [x] 16. Create the schema on an empty database at startup, with the Alembic migrations
  (`backend/database/bootstrap.py`). Any other mismatch refuses to start; nothing is
  migrated or dropped automatically.
  - _Requirements: 17.2_
- [ ] 17. Add structured JSON logging with secret masking
  - _Requirements: 13.2, 14.3_

## Phase 3 — API and demo controls

- [x] 18. Build the current-state read API and CORS (`backend/api/v1/runtime.py`)
  - Built: `/api/v1/status`, `/runtime`, `/state/current`, `/score/current`,
    `/telemetry/latest`, `/events`, `/actions`; CORS from `FRONTEND_ORIGIN`
  - _Requirements: 4.7, 10.2–10.5_
- [ ] 18a. Add the history endpoints (`/score/history`, `/state/history`,
  `/telemetry/history`), `/events/{id}` and `/rules`, and measure p95 latency
  - _Requirements: 3.6, 10.1, 10.7_
- [x] 19. Build the demo API (`backend/api/v1/demo.py`, `backend/core/demo.py`)
  - `inject`, `scenarios`, `scenario/{name}` (normal, suspicious, critical); security
    synthetic types only (422 otherwise); `DEMO_MODE=false` → 403 before input is read;
    rate limit (429); one scenario at a time (409); synthetic intake only
  - _Requirements: 5.5, 12.3, 12.4, 12.5_
- [x] 19a. Safe demo reset (Phase 3.1): `POST /api/v1/demo/reset`, `app/demo_reset.py`,
  `app/lifecycle.py`; dashboard **Reset demo session** with confirmation
  - Session rotation: the session's SQLite file is archived intact (renamed, never deleted)
    and a new session starts as application startup does; the state comes from the state
    machine's own restore of an empty history. No state, score, transition or response is
    written; no input is accepted (422); `DEMO_MODE=false` → 403; local SQLite file only
  - Reads answer 503 while no runtime is attached, so nothing reads a half-built database
  - Tests: `tests/integration/test_demo_reset.py` (22), `frontend/tests/app/dashboard.test.tsx`
  - _Requirements: 12.2 (reset to a clean demo start; P-07 preserved: nothing deleted)_
- [x] 19b. Build `WS /ws/live` (`backend/api/v1/live.py`, `backend/core/live.py`)
  - Receive-only, sanitized read models, bounded per-client queues, origin check,
    subscriber limit, reconnect-safe
  - _Requirements: 10.6_
- [ ] 20. Decide whether to build runtime rule enable/disable (`PUT /rules/{id}/...`) **(approval)**
  - _Requirements: 2.3_

## Phase 4 — Dashboard

- [x] 21. Scaffold the Vite + React + TypeScript app, typed API client, observation-only
  WebSocket client and React Query (dependencies approved by Henok, Phase 3)
  - **Spec revision (approved):** plain CSS with design tokens and an inline SVG trend
    replace Tailwind CSS and Recharts (§14.1), to avoid heavy UI dependencies
  - _Requirements: 11.2, 11.6_
- [x] 22. Build the dashboard panels: system status, defense posture (four-state ladder, score,
  trend), pipeline, host telemetry, detections, threat analysis, guarded responses, incident
  timeline, AI explanation, DEMO MODE controls
  - Rule table panel not built: the backend has no rules endpoint yet (task 18a)
  - _Requirements: 11.1, 11.3, 11.4, 11.5, 11.7_
- [x] 23. Frontend tests (Vitest + Testing Library): 47 tests, including a contract test
  against responses recorded from the real backend (`frontend/tests/fixtures/contract.json`,
  checked for drift by `backend/tests/integration/test_dashboard_contract.py`)
  - _Requirements: 16.4, 16.5_
- [ ] 23a. Upgrade the dev tooling flagged by `npm audit` (Vite ≤ 6.4.3, Vitest < 3.2.6,
  tinypool, esbuild; development server and test runner only, not the shipped bundle)
  - **Deferred by Henok's decision (Phase 3.1)** until after the hackathon; no major
    toolchain migration before submission. Dev and preview servers stay on localhost.
- [x] 23b. Production Content Security Policy (Phase 3.1): `frontend/config/csp.ts`; meta CSP in
  `dist/index.html`, `dist/serve.json` headers for `serve -s dist`, `vite preview` headers;
  `npm run verify:csp`; no `unsafe-eval` / `unsafe-inline`; verified with 0 violations in a
  real browser. Other hosts must set the header themselves (README).
- [x] 23c. Visual QA preparation (Phase 3.1): `docs/hackathon/VISUAL_QA.md`; automated pass at
  1280×720 and 1920×1080; pipeline moved first, trend full width, minimum text 11 px
- [ ] 23d. Manual visual review in a real browser by Henok (checklist in `VISUAL_QA.md`)
- [ ] 24. Apply the Kiroween visual theme without hiding state or safety labels

## Phase 5 — Release readiness and submission

- [ ] 25. Fix Docker so `docker compose up --build` works from a clean clone
  - _Requirements: 17.1, 17.3_
- [ ] 26. Verify a clean-clone install on Python 3.11 or 3.12 **(approval: virtualenv install)**
  - _Requirements: 17.1_
- [ ] 27. Rewrite the README to match the submitted build
  - _Requirements: 18.3, 18.6_
- [ ] 28. Write `docs/hackathon/KIRO_USAGE.md`, claiming only Kiro features that were used
  - _Requirements: 18.5_
- [ ] 29. Record the demo video (under 3 minutes, synthetic events only) and submit on Devpost
  **(approval: publishing)**
  - _Requirements: 18.1, 18.4_

## Open verification items (known gaps against requirements)

These come from the master spec. They are not fixed in Phase 1. Each needs a decision: implement
it, or record a spec revision approved by Henok. The requirement is never silently dropped.

- [ ] 30. AC-F01-1 asks for ≥ 1-second resolution, but the default `POLL_INTERVAL_SECONDS` is 2,
  matching the master spec's own §9.2 RELAXED row. Resolve this inconsistency in the spec.
  - _Requirements: 1.1_
- [ ] 31. AC-F02-1 requires ≥ 6 built-in rules. Count them: five rule classes exist (CPU, memory,
  network, process, synthetic security events).
  - _Requirements: 2.1_
- [ ] 32. AC-F02-5 and §8.4 call for baseline-deviation detection over a 60-sample window with
  baselines persisted across restarts. Today only the process rule uses a baseline.
  - _Requirements: 2.4_
- [ ] 33. §9.2 state effects (poll interval per state) are not applied; INCREASE_MONITORING is simulated.
  - _Requirements: 6.7_
- [ ] 34. Settings allow `AI_MAX_OUTPUT_TOKENS` up to 1000, above the AS-05 `explain_incident`
  budget of 500. The default is 500. Changing the cap is a production change **(approval)**.
  - _Requirements: 8.8_
- [ ] 35. AC-F06-1: only the `null` provider meets the 10 s explanation budget on this laptop.
  - **CPU LLM work deferred (Henok, 2026-11-26):** `qwen3:0.6b` classified NOT READY /
    DEFERRED for this hardware, based on the measured CPU results (`qwen2.5:0.5b` ~45 s,
    `llama3.2` ~140 s per explanation vs the 10 s budget). No model download, no CPU
    fine-tuning, no ML packages, no adapter or AI-boundary change. The `null` provider is the
    hackathon explanation path. See `docs/evaluation/QWEN3_0.6B_CPU_EVALUATION.md`.
  - Future: a fresh GPU benchmark with the same 15 cases and the unchanged gates. A model is
    recommended only if it passes every gate. Not part of the hackathon phase.
  - _Requirements: 8.9_
- [ ] 36. Unit-test coverage alone is 72.36%, below the ≥ 80% target. The full suite covers more.
  Add unit tests; do not lower the threshold.
  - _Requirements: 16.2_
- [ ] 37. Performance tests and the JSON test fixtures listed in the testing steering are missing.
  - _Requirements: 10.7, 14.4, 16.5_
- [ ] 38. Fix the 9 pre-existing ruff findings and 2 unformatted Phase 1 Alembic files, and remove
  the obsolete `ANN101` and `ANN102` ignores from `pyproject.toml`. Never format `guard.py`
  **(approval: touches a migration file)**.
  - _Requirements: 16.4_
