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

- [ ] 15. Build the runtime orchestrator **(approval: security review)**
  - Start and stop it in the FastAPI lifespan; collector loop → detection → `assess(now)` →
    `ResponseService.handle()` → `ExplanationService.observe()`
  - Restore state at startup; isolate stage failures; log with correlation IDs
  - Integration test: real app lifecycle with the fake telemetry provider
  - _Requirements: 5.1, 5.2, 14.1, 14.3_
- [ ] 16. Bootstrap the schema with Alembic at startup, never dropping data **(approval)**
  - _Requirements: 17.2_
- [ ] 17. Add structured JSON logging with secret masking
  - _Requirements: 13.2, 14.3_

## Phase 3 — API and demo controls

- [ ] 18. Build the read API (status, telemetry, events, score, state, actions, rules) and CORS
  - Bounded queries in domain read services; happy-path and error-path tests per endpoint
  - _Requirements: 3.6, 4.7, 10.1–10.5, 10.7, 16.2_
- [ ] 19. Build the demo API (inject, scenario, reset) **(approval: security-sensitive)**
  - Allowlist → 422; `DEMO_MODE=false` → 403; rate limit; synthetic intake only; reset keeps audit rows
  - Add `tests/security/test_demo_mode_guard.py`
  - _Requirements: 5.5, 12.1–12.5_
- [ ] 20. Decide whether to build runtime rule enable/disable (`PUT /rules/{id}/...`) **(approval)**
  - _Requirements: 2.3_

## Phase 4 — Dashboard

- [ ] 21. Scaffold the Vite + React + TypeScript app, API client and React Query polling
  **(approval: dependency install)**
  - _Requirements: 11.2, 11.6_
- [ ] 22. Build the ten F-07 panels, with state colors paired with text labels and SIMULATED badges
  - _Requirements: 11.1, 11.3, 11.4, 11.5, 11.7_
- [ ] 23. Add component tests (ThreatGauge, StateDisplay, EventFeed, ActionLog, AIPanel)
  - _Requirements: 16.4, 16.5_
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
