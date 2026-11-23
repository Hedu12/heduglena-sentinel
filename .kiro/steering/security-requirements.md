# Security Requirements — HEDUGLENA Sentinel

**Priority:** Highest. Security requirements override convenience.  
**Review:** Any code touching the response engine, AI pipeline, or telemetry ingestion requires explicit security review before merge.

---

## SR-01: No Real Offensive Capability

**Rule:** The system must never generate, store, or execute shellcode, exploits, or destructive OS operations.

**Enforcement:**
- The `ResponseGuard` class must gate every `LIVE_PROTECTIVE` action behind `LIVE_ACTIONS=true`.
- `LIVE_ACTIONS` defaults to `false` and must be set explicitly in the environment.
- On startup, if `LIVE_ACTIONS=true`, the application must log a prominent `[WARNING] LIVE ACTIONS ENABLED` message.
- `bandit` must report zero HIGH-severity findings on the response engine module.

**Prohibited code patterns:**
- `subprocess.call`, `os.system`, `os.popen` with user-influenced arguments.
- `iptables`, `netsh`, `kill`, `taskkill` in any non-guarded code path.
- Any file deletion (`os.remove`, `shutil.rmtree`) outside explicitly guarded live-action handlers.

---

## SR-02: AI Output Safety

**Rule:** AI-generated text is advisory only. It has no code execution pathway.

**Enforcement:**
- `AIOutputValidator` must run before any AI response is stored or displayed.
- The validator applies a blocklist regex against: shell metacharacters (`|`, `;`, `&&`, `||`, `$(`), common commands (`rm`, `del`, `wget`, `curl`, `python`, `bash`, `powershell`), and absolute path patterns.
- Matches must be replaced with `[REDACTED BY SAFETY FILTER]` and the event logged at WARNING level.
- Every AI adapter's system prompt must include: *"Do not include executable commands, scripts, shell syntax, or absolute file system paths in your response."*
- Raw AI responses are stored separately from validated responses for audit.

---

## SR-03: Input Validation

**Rule:** All externally supplied data must be validated before processing.

**Enforcement:**
- Every FastAPI endpoint body must use a Pydantic model. No `request.json()` without immediate Pydantic parsing.
- The `/api/v1/demo/inject` endpoint must validate event types against a hard-coded allowlist. Unknown types must return HTTP 422.
- All database interactions must use SQLAlchemy's parameterized queries. String interpolation into SQL is prohibited.
- Configuration values loaded from environment variables must be validated at startup; the application must refuse to start if required config is missing or invalid.

---

## SR-04: Secrets Management

**Rule:** No secret ever appears in source code, logs, or API responses.

**Enforcement:**
- LLM provider API keys must be loaded from environment variables: `OPENAI_API_KEY`, `OLLAMA_BASE_URL`.
- The `.env` file is listed in `.gitignore`. Its existence is documented; its contents are never committed.
- Log formatters must mask values of environment variables ending in `_KEY`, `_SECRET`, or `_TOKEN`.
- API responses must not echo back configuration values.

---

## SR-05: Least Privilege

**Rule:** The backend process must not require elevated privileges for normal operation.

**Enforcement:**
- The backend must start and collect telemetry as a non-root user.
- If a telemetry metric requires elevated privileges (e.g., per-process network stats on some OSes), it must degrade gracefully: log a warning and return `null` for that metric.
- Docker containers must run as a non-root user (`USER sentinel` in the Dockerfile).

---

## SR-06: Local Data Isolation

**Rule:** The SQLite database file is an internal implementation detail, not an API resource.

**Enforcement:**
- No endpoint may return the raw database file or its path.
- The database path must not appear in API responses, logs (except at startup at DEBUG level), or error messages returned to the client.
- Database access from outside the backend process must be blocked by file system permissions.

---

## SR-07: Prompt Injection Prevention

**Rule:** Telemetry data and event metadata are untrusted and must not be injected raw into AI prompts.

**Enforcement:**
- Telemetry values passed to the AI must be serialized as a JSON object, not as inline string interpolation.
- Process names, file names, and any user-influenced string must be JSON-escaped before inclusion in a prompt.
- The `IncidentContext` object passed to the AI must contain only pre-validated fields — not raw metric dictionaries.

---

## SR-08: Demo Mode Isolation

**Rule:** Demo injection endpoints must not be reachable in non-demo deployments.

**Enforcement:**
- All `/api/v1/demo/*` routes must check `settings.DEMO_MODE` and return HTTP 403 if false.
- `DEMO_MODE` defaults to `true` for development and must be explicitly set to `false` for production.
- Demo scenarios must only inject synthetic events; they must not modify real OS state.

---

## Security Review Checklist

Before any PR touching security-sensitive code is merged, verify:

- [ ] No new `subprocess` calls outside guarded handlers.
- [ ] No new string interpolation into SQL.
- [ ] No hardcoded credentials or tokens.
- [ ] `bandit -ll` reports no new HIGH-severity findings.
- [ ] AI output validator test suite still passes.
- [ ] `LIVE_ACTIONS` guard tested for the new code path.
- [ ] Any new telemetry field is JSON-escaped before use in prompts.
