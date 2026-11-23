# Architecture Principles — HEDUGLENA Sentinel

These principles govern design decisions across the backend, frontend, and infrastructure.  
When a decision conflicts with a principle, raise it explicitly rather than silently ignoring the principle.

---

## P-01: Pipeline Isolation

Each stage of the core loop (DETECT → ANALYZE → DECIDE → DEFEND → EXPLAIN) must be an independent, replaceable module.

**Implications:**
- No stage calls another stage directly. Communication happens through the event store and a central orchestrator.
- Each stage can be unit-tested without instantiating any other stage.
- A stage can be replaced (e.g., swap the anomaly detector for a new algorithm) without touching adjacent code.

---

## P-02: Explicit Configuration

All behavioral parameters live in a single, validated configuration object loaded at startup.

**Implications:**
- No `os.getenv()` calls scattered through business logic. Configuration is read once, validated, and injected.
- Changing a threshold, polling interval, or state machine parameter requires editing config, not code.
- The configuration object is logged (with secrets masked) at INFO level on startup.

---

## P-03: Ports and Adapters for External Dependencies

The AI provider, the database, and any future external service must be accessed through a typed interface (Protocol), not a concrete class.

**Implications:**
- `AIProvider`, `TelemetrySource`, and `EventStore` are protocols.
- Concrete adapters (Ollama, OpenAI, SQLite, PostgreSQL) implement the protocol.
- Tests inject mock adapters without touching real infrastructure.
- Adding a new AI provider means writing a new adapter; no changes to the core pipeline.

---

## P-04: Fail-Safe Defaults

When a component fails, the system degrades to a safer, simpler mode rather than crashing or producing incorrect output.

**Implications:**
- Telemetry collection failure → log warning, return partial sample, continue.
- AI explanation failure → store fallback explanation, do not block incident creation.
- Database write failure → log error, attempt retry, continue detection.
- WebSocket failure → dashboard falls back to HTTP polling.

---

## P-05: Explicit Simulation Boundary

The boundary between simulated and live actions is a hard, verifiable invariant.

**Implications:**
- `is_simulated: bool` is a mandatory field on every `ActionRecord`. It is never inferred — it must be explicitly set.
- `ResponseGuard` is the single point of truth for action authorization. No action bypasses it.
- The `LIVE_ACTIONS` flag is read by the guard, not by individual action handlers.
- Tests assert the guard behavior; the implementation does not test itself.

---

## P-06: Thin API Layer

FastAPI route handlers must be thin. Business logic lives in the core domain modules, not in route functions.

**Implications:**
- Route handlers validate input, call a domain service, and return the result.
- If a route handler grows beyond ~20 lines of business logic, extract a service function.
- The API is a transport layer. The domain is independently testable.

---

## P-07: Immutable Event Records

Detection events, threat scores, and response actions are append-only.

**Implications:**
- No `UPDATE` statements on event, score, or action tables.
- State changes are recorded as new rows, not by modifying existing rows.
- This makes the audit trail tamper-evident and simplifies concurrent access.

---

## P-08: Frontend/Backend Contract

The frontend consumes the backend through the documented API contract only. It does not have direct database access or shared code with the backend.

**Implications:**
- API response types are defined in `/frontend/src/types/api.ts` and kept in sync with the Pydantic schemas.
- The frontend does not embed business logic (threat scoring, state machine rules). It displays what the API reports.
- If the API shape changes, both the Pydantic schema and the TypeScript type must be updated together.

---

## P-09: Observability First

Every meaningful state change must produce a structured log entry.

**Implications:**
- State transitions, rule firings, action executions, and AI calls all emit structured JSON logs.
- Log entries include a correlation ID tying them to an incident.
- Logging is the primary debugging tool; the application must be diagnosable from logs alone.

---

## P-10: Demo Parity

The demo control panel exercises the same code paths as real telemetry. Synthetic events flow through the full pipeline.

**Implications:**
- Synthetic events enter through the detection pipeline's event intake, not by directly writing to the database.
- The demo scenario outcomes are deterministic given the same injected events.
- If a demo scenario fails, it means the real pipeline has a bug — not a demo-specific problem.

---

## Dependency Rules

```
frontend  →  API layer  →  domain services  →  adapters  →  infrastructure
```

Dependencies flow inward only. Domain services must not import from the API layer. Adapters must not import from domain services (they implement protocols defined in the domain).

The database schema is owned by the domain layer. FastAPI route handlers must not construct raw SQL or SQLAlchemy queries directly.
