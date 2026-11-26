/**
 * Minimal typed HTTP client for the Sentinel backend.
 *
 * Every failure becomes an ApiError with a `kind`, so the UI can show an honest
 * state (offline, not found, busy, rate limited, unavailable) instead of stale
 * or invented data. No credentials, cookies or secrets are ever sent.
 */

const BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";
const TIMEOUT_MS = 8000;

export type ApiErrorKind =
  | "offline" // network failure or timeout: the backend could not be reached
  | "forbidden" // 403 (for example DEMO_MODE=false)
  | "not_found" // 404
  | "conflict" // 409 (for example a scenario is already running)
  | "invalid" // 422
  | "rate_limited" // 429
  | "unavailable" // 503 (runtime not started, or no decision yet)
  | "server"; // any other non-2xx

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;

  constructor(kind: ApiErrorKind, status: number | null, message: string) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

function kindFor(status: number): ApiErrorKind {
  switch (status) {
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 422:
      return "invalid";
    case 429:
      return "rate_limited";
    case 503:
      return "unavailable";
    default:
      return "server";
  }
}

async function detailOf(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
    }
  } catch {
    // Non-JSON error body: fall back to the status text below.
  }
  return response.statusText || `HTTP ${response.status}`;
}

export async function request<T>(
  path: string,
  init: { method?: "GET" | "POST"; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const abort = () => controller.abort();
  init.signal?.addEventListener("abort", abort);
  let response: Response;
  try {
    response = await fetch(BASE_URL + path, {
      method: init.method ?? "GET",
      headers: init.body === undefined ? undefined : { "Content-Type": "application/json" },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      credentials: "omit",
      signal: controller.signal,
    });
  } catch {
    throw new ApiError("offline", null, "Sentinel backend is unreachable");
  } finally {
    clearTimeout(timer);
    init.signal?.removeEventListener("abort", abort);
  }
  if (!response.ok) {
    throw new ApiError(kindFor(response.status), response.status, await detailOf(response));
  }
  return (await response.json()) as T;
}

export const isApiError = (error: unknown, kind?: ApiErrorKind): error is ApiError =>
  error instanceof ApiError && (kind === undefined || error.kind === kind);
