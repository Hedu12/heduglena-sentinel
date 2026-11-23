# HEDUGLENA Sentinel

> An AI-native adaptive cyber-defense agent inspired by the adaptive behavior of *Euglena*.

**Hackathon:** Kiroween 2026  
**Status:** Active development

> **Current build status (2026-11-20).** The backend security pipeline is implemented and
> tested: telemetry, detection, threat scoring, the defense state machine, guarded simulated
> response, incidents and the explanation-only AI layer. 2,011 backend tests pass. The running
> application does not yet drive that pipeline and serves only `/health` and the read-only
> incident and explanation routes. The runtime orchestrator, the remaining API, the demo
> controls, the dashboard and a working Docker stack are **planned**. The quick-start, demo,
> frontend-test and Playwright sections below describe the target build, not the current one.
> See [`.kiro/specs/heduglena-sentinel/tasks.md`](.kiro/specs/heduglena-sentinel/tasks.md).

---

## What it does

Sentinel continuously monitors host telemetry, detects anomalous behavior, computes a threat score, selects a matching defense posture, executes safe and controlled responses, and explains every decision through an AI security analyst interface.

Core execution loop:

```
DETECT → ANALYZE → DECIDE → DEFEND → EXPLAIN
```

Four defense states — **RELAXED**, **ALERT**, **DEFENSIVE**, **AGGRESSIVE** — are selected by the state machine and change the system's monitoring intensity and response profile. All transitions are hysteresis-gated to prevent rapid oscillation.

---

## Quick start (Docker)

```bash
# 1. Clone and enter the repo
git clone <repo-url>
cd heduglena_Sentinel

# 2. Copy environment template
cp .env.example .env
# Edit .env if needed (defaults work for local demo)

# 3. Start the full stack
docker compose up --build

# 4. Open the dashboard
open http://localhost:3000
```

The backend API is at `http://localhost:8000`. Auto-generated API docs: `http://localhost:8000/docs`.

---

## Quick start (local development)

**Requirements:** Python 3.11+, Node.js 18+

```bash
# Backend
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -e ".[dev]"
cp ../.env.example ../.env
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

---

## Running the demo

With the system running, open the dashboard at `http://localhost:3000`.

The **Demo Control Panel** (bottom-right of the dashboard) lets you trigger built-in scenarios without terminal access:

| Scenario | What it shows |
|---|---|
| DS-01: CPU Spike | Single anomaly, RELAXED → ALERT transition |
| DS-02: Memory Pressure | Memory anomaly detection |
| DS-03: Brute Force | Repeated auth failures, rapid score escalation |
| DS-04: Suspicious Process | Critical-severity synthetic event |
| DS-05: Full Escalation | Combined DS-01 + DS-03, drives to AGGRESSIVE |
| DS-06: Recovery | Stop injections, watch score decay and state descent |

All demo scenarios use **synthetic events** — no real attacks occur.  
All response actions shown are **SIMULATED** (tagged with a blue badge) unless `LIVE_ACTIONS=true` is explicitly set.

---

## Running tests

```bash
# All backend tests
cd backend
pytest

# Unit tests only with coverage
pytest tests/unit/ --cov=backend --cov-report=term-missing

# Security tests
pytest tests/security/

# Integration tests
pytest tests/integration/

# Frontend tests
cd frontend
npm run test

# End-to-end (requires both backend and frontend running)
npx playwright test
```

---

## Project structure

```
heduglena_Sentinel/
├── backend/
│   ├── app/
│   │   └── main.py              # FastAPI application entry point
│   ├── api/                     # Route handlers (thin layer)
│   ├── core/                    # Configuration, orchestrator, base exceptions
│   ├── detection/               # Detection engine and built-in rules
│   ├── telemetry/               # Telemetry collection and storage
│   ├── threat/                  # Threat scorer and defense state machine
│   ├── response/                # Response engine and ResponseGuard
│   ├── ai/                      # AI provider protocol and adapters
│   ├── database/                # SQLAlchemy models, migrations (Alembic)
│   ├── models/                  # Pydantic schemas (API contracts)
│   └── tests/
│       ├── unit/
│       ├── integration/
│       ├── security/
│       ├── performance/
│       └── fixtures/
├── frontend/
│   ├── src/
│   │   ├── components/          # Dashboard panels and shared UI
│   │   ├── pages/               # Top-level page components
│   │   ├── hooks/               # Custom React hooks
│   │   ├── services/            # API client functions
│   │   └── types/               # TypeScript interfaces (API contract)
│   └── tests/
├── .kiro/
│   ├── specs/                   # Project specification
│   ├── steering/                # Coding, security, testing, AI safety rules
│   └── hooks/                   # Automated Kiro hooks
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Architecture overview

See [`.kiro/specs/sentinel-spec.md`](.kiro/specs/sentinel-spec.md) for the full specification.

Key design decisions:

- **Ports and adapters:** The AI provider, telemetry source, and event store are accessed through typed `Protocol` interfaces. Swapping providers (e.g., Ollama → OpenAI) requires only changing an adapter, not core logic.
- **Immutable events:** Detection events, scores, and actions are append-only. No UPDATE statements on the audit tables.
- **Simulation boundary:** `ResponseGuard` is the single gate between the system and OS actions. Simulated actions are tagged `is_simulated=True` unconditionally. Live actions require `LIVE_ACTIONS=true` in the environment.
- **AI is advisory only:** AI output passes through `AIOutputValidator` before storage or display. There is no code path from AI text to execution.

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and edit as needed.

Key variables:

| Variable | Default | Description |
|---|---|---|
| `DEMO_MODE` | `true` | Enable demo injection endpoints |
| `LIVE_ACTIONS` | `false` | Reserved for future live actions. None are implemented: `true` logs a warning and every action stays simulated |
| `AI_PROVIDER` | `null` | AI adapter: `null`, `ollama`, `openai` |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OPENAI_API_KEY` | — | Required if `AI_PROVIDER=openai` |
| `POLL_INTERVAL_SECONDS` | `2` | Telemetry polling interval |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `DATABASE_URL` | `sqlite+aiosqlite:///./sentinel.db` | SQLAlchemy connection string |

---

## Security notes

- Every response action is **simulated**. `ResponseGuard` blocks live protective actions unless `LIVE_ACTIONS=true`, and the executor has no live handler, so nothing touches the firewall, processes or files even then.
- The planned demo injection endpoints must return HTTP 403 when `DEMO_MODE=false` (not yet built).
- AI output is validated before storage or display. If the validator would redact anything, such as a shell command or a file path, the whole answer is rejected and a deterministic fallback is shown. AI output never reaches scoring, the state machine or the response engine.
- No credentials or secrets are returned by the API. API keys are held as secret values and are never echoed.

---

## Specification and design documents

| Document | Location |
|---|---|
| Kiro spec: requirements (EARS) | `.kiro/specs/heduglena-sentinel/requirements.md` |
| Kiro spec: design, security boundaries, protected files | `.kiro/specs/heduglena-sentinel/design.md` |
| Kiro spec: implementation plan and status | `.kiro/specs/heduglena-sentinel/tasks.md` |
| Master reference specification | `.kiro/specs/sentinel-spec.md` |
| Kiro hooks (read-only checks) | `.kiro/hooks/*.json`, logic in `scripts/hooks/check.py` |
| Readiness audit | `docs/hackathon/KIROWEEN_READINESS_AUDIT.md` |
| Architecture principles | `.kiro/steering/architecture-principles.md` |
| Coding standards | `.kiro/steering/coding-standards.md` |
| Security requirements | `.kiro/steering/security-requirements.md` |
| Testing requirements | `.kiro/steering/testing-requirements.md` |
| AI safety requirements | `.kiro/steering/ai-safety-requirements.md` |
