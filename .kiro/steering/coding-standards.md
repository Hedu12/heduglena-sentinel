# Coding Standards — HEDUGLENA Sentinel

**Applies to:** All backend (Python) and frontend (TypeScript/React) code.  
**Enforcement:** Automated via pre-commit hooks and CI.

---

## Python

### Version and tooling
- Python 3.11 or later.
- `ruff` for linting and formatting (replaces flake8 + black + isort).
- `mypy` in strict mode for type checking.
- `pytest` for all tests.

### Type annotations
- Every function and method must have full type annotations on all parameters and the return type.
- Use `from __future__ import annotations` at the top of every module.
- Prefer `X | None` over `Optional[X]`.
- Avoid `Any` except at genuine external boundaries (e.g., raw JSON from an external API). When used, add a `# type: ignore[assignment]` comment explaining why.

### Pydantic models
- All API request and response schemas must be Pydantic `BaseModel` subclasses.
- All database row models must use SQLAlchemy 2.x `DeclarativeBase` with `mapped_column`.
- Use `model_validator` and `field_validator` instead of custom `__init__` overrides.

### Async
- FastAPI route handlers must be `async def`.
- Database queries must use `AsyncSession` from `sqlalchemy.ext.asyncio`.
- CPU-bound work (e.g., statistical calculations) may use `asyncio.run_in_executor` to avoid blocking the event loop.

### Naming
- Modules and packages: `snake_case`.
- Classes: `PascalCase`.
- Functions, methods, variables: `snake_case`.
- Constants: `UPPER_SNAKE_CASE`.
- Pydantic models: `PascalCase` with `Response`, `Request`, or `Schema` suffix as appropriate.

### Error handling
- Never use bare `except:` or `except Exception:` without logging and re-raising or returning a structured error.
- FastAPI route handlers must catch domain exceptions and return appropriate HTTP status codes.
- Use a `SentinelError` base exception class for all application-specific exceptions.

### Module structure (backend)
Every module must have a module-level docstring describing its responsibility.  
Imports order (enforced by ruff): stdlib → third-party → local.

### Comments
- Comments explain *why*, not *what*.
- Remove commented-out code before merging; use git history instead.

---

## TypeScript / React

### Version and tooling
- TypeScript 5.x, strict mode enabled.
- ESLint with `@typescript-eslint/recommended`.
- Prettier for formatting.
- Vitest for unit tests.

### Types
- No `any`. Use `unknown` at external API boundaries and narrow with type guards.
- Define explicit interface types for all API response shapes in `/frontend/src/types/`.
- Use `z.infer` from Zod if runtime validation of API responses is added.

### Components
- One component per file, file name matches component name.
- Functional components only; no class components.
- Props interfaces must be explicitly typed, never inferred.
- Side effects belong in custom hooks in `/frontend/src/hooks/`.

### State management
- Server state: React Query (`@tanstack/react-query`).
- UI state: `useState` / `useReducer` local to the component or hook.
- No global state management library for the MVP.

### Naming
- Components: `PascalCase`.
- Hooks: `useCamelCase`.
- Services: `camelCase` file names.
- Types/interfaces: `PascalCase`.

### Accessibility
- Interactive elements must have accessible labels or `aria-label`.
- Color alone must not convey status — pair color with a text label or icon.

---

## Cross-cutting

### Git
- Branch names: `feature/short-description`, `fix/short-description`, `chore/short-description`.
- Commit messages: imperative mood, present tense. Example: `Add CPU spike detection rule`.
- One logical change per commit.
- No committing directly to `main`.

### File length
- Python files: prefer < 300 lines. If a file grows beyond 500 lines, split it by responsibility.
- React component files: prefer < 200 lines.

### Configuration over hardcoding
- No hardcoded hostnames, ports, file paths, timeouts, or thresholds in source code.
- All such values must come from environment variables or the central config module.
