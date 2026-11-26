import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { vi } from "vitest";

import { App } from "../src/app/App";
import { LiveClient } from "../src/services/live";
import contract from "./fixtures/contract.json";

export type Snapshot = "relaxed" | "critical";
type Recorded = { status: number; body: unknown };

// URL path (without query) -> fixture key, mirroring backend/tests/contract_fixture.py.
const ROUTES: Record<string, string> = {
  "/health": "health",
  "/api/v1/status": "status",
  "/api/v1/runtime": "runtime",
  "/api/v1/state/current": "state",
  "/api/v1/score/current": "score",
  "/api/v1/telemetry/latest": "telemetry",
  "/api/v1/events": "events",
  "/api/v1/actions": "actions",
  "/api/v1/incidents": "incidents",
  "/api/v1/ai/status": "ai_status",
  "/api/v1/demo/scenarios": "scenarios",
};

export function recorded(snapshot: Snapshot, key: string): Recorded {
  const snap = (contract as unknown as Record<Snapshot, Record<string, Recorded>>)[snapshot];
  const entry = snap[key];
  if (!entry) throw new Error(`no recorded ${key} in ${snapshot}`);
  return entry;
}

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

export interface FetchCall {
  method: string;
  path: string;
}

/**
 * A fetch stub that answers from the real recorded backend responses.
 * `overrides` replaces individual routes (by path) to simulate failures.
 */
export function stubBackend(
  initial: Snapshot | (() => Snapshot),
  overrides: Record<string, (method: string, init?: RequestInit, url?: URL) => Response | Promise<Response>> = {},
) {
  const calls: FetchCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const method = init?.method ?? "GET";
    const snapshot = typeof initial === "function" ? initial() : initial;
    calls.push({ method, path: url.pathname });
    const override = overrides[url.pathname];
    if (override) return override(method, init, url);
    if (url.pathname.startsWith("/api/v1/incidents/SIT-")) return respond(snapshot, "incident");
    if (url.pathname.startsWith("/api/v1/ai/explain/")) return respond(snapshot, "explanation");
    const key = ROUTES[url.pathname];
    if (!key) return json({ detail: "not found" }, 404);
    return respond(snapshot, key);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

function respond(snapshot: Snapshot, key: string): Response {
  const entry = recorded(snapshot, key);
  return json(entry.body, entry.status);
}

export const offline = () => {
  throw new TypeError("Failed to fetch");
};

/** A WebSocket double the tests drive by hand. */
export class FakeSocket {
  static instances: FakeSocket[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;
  readonly sent: unknown[] = [];

  constructor(readonly url: string) {
    FakeSocket.instances.push(this);
  }
  open() {
    this.onopen?.(new Event("open"));
  }
  receive(data: unknown) {
    this.onmessage?.(new MessageEvent("message", { data }));
  }
  drop(code = 1006) {
    this.onclose?.(new CloseEvent("close", { code }));
  }
  close() {
    this.closed = true;
  }
  send(data: unknown) {
    this.sent.push(data);
  }
  static latest(): FakeSocket {
    const s = FakeSocket.instances[FakeSocket.instances.length - 1];
    if (!s) throw new Error("no socket created");
    return s;
  }
}

export function fakeLiveClient(options: { staleAfterMs?: number } = {}) {
  FakeSocket.instances = [];
  return new LiveClient({
    url: "ws://test/ws/live",
    minBackoffMs: 10,
    maxBackoffMs: 40,
    ...options,
    createSocket: (url) => new FakeSocket(url) as unknown as WebSocket,
  });
}

export function testQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retryDelay: 0, staleTime: 0 }, mutations: { retry: false } },
  });
}

export function renderDashboard(liveClient = fakeLiveClient()) {
  const queryClient = testQueryClient();
  const view = render(<App queryClient={queryClient} liveClient={liveClient} />);
  return { ...view, queryClient, liveClient };
}

export const liveFrame = (type: string, payload: unknown, timestamp = new Date().toISOString()) =>
  JSON.stringify({ type, timestamp, payload });
