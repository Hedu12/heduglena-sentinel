/**
 * LiveClient: an observation-only client for WS /ws/live.
 *
 * It never sends anything. Every incoming frame is validated: frames that are
 * not well-formed LiveMessage objects are dropped and counted, and a frame
 * identical to one of the last few received is dropped as a duplicate. The
 * connection reconnects with capped exponential backoff, and is reported
 * "stale" when no frame has arrived within the stale window (the backend
 * publishes telemetry on every monitoring cycle).
 */

import type { LiveMessage, LiveMessageType } from "../types/api";

export type LiveStatus = "connecting" | "open" | "stale" | "closed";

const TYPES: ReadonlySet<LiveMessageType> = new Set([
  "telemetry",
  "detection_event",
  "threat_score",
  "defense_state_change",
  "response_action",
]);
const MAX_FRAME_CHARS = 64_000;
const DEDUP_WINDOW = 64;
const SERVICE_RESTART = 1012;

export interface LiveOptions {
  url: string;
  staleAfterMs?: number;
  minBackoffMs?: number;
  maxBackoffMs?: number;
  createSocket?: (url: string) => WebSocket;
}

export function parseLiveMessage(raw: unknown): LiveMessage | null {
  if (typeof raw !== "string" || raw.length > MAX_FRAME_CHARS) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const { type, timestamp, payload } = value as Record<string, unknown>;
  if (typeof type !== "string" || !TYPES.has(type as LiveMessageType)) return null;
  if (typeof timestamp !== "string" || Number.isNaN(Date.parse(timestamp))) return null;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  return { type: type as LiveMessageType, timestamp, payload };
}

export function liveUrl(location: Pick<Location, "protocol" | "host">): string {
  const configured: string | undefined = import.meta.env.VITE_WS_URL;
  if (configured) return `${configured.replace(/\/$/, "")}/ws/live`;
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws/live`;
}

type Listener = (message: LiveMessage) => void;
type StatusListener = (status: LiveStatus) => void;

export class LiveClient {
  private readonly opts: Required<LiveOptions>;
  private socket: WebSocket | null = null;
  private status: LiveStatus = "closed";
  private retries = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private staleTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = true;
  private readonly recent: string[] = [];
  private readonly listeners = new Set<Listener>();
  private readonly statusListeners = new Set<StatusListener>();
  malformed = 0;
  duplicates = 0;
  lastMessageAt: number | null = null;

  constructor(options: LiveOptions) {
    this.opts = {
      staleAfterMs: 15_000,
      minBackoffMs: 1_000,
      maxBackoffMs: 30_000,
      createSocket: (url) => new WebSocket(url),
      ...options,
    };
  }

  get currentStatus(): LiveStatus {
    return this.status;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onStatus(listener: StatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => this.statusListeners.delete(listener);
  }

  start(): void {
    if (!this.stopped) return; // never open a second socket
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.clearTimers();
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null;
      socket.close();
    }
    this.setStatus("closed");
  }

  private connect(): void {
    this.setStatus("connecting");
    let socket: WebSocket;
    try {
      socket = this.opts.createSocket(this.opts.url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;
    socket.onopen = () => {
      this.retries = 0;
      this.setStatus("open");
      this.armStale();
    };
    socket.onmessage = (event: MessageEvent) => this.receive(event.data);
    socket.onerror = () => {
      // The close event that follows performs the reconnect.
    };
    socket.onclose = (event: CloseEvent) => {
      if (this.socket === socket) this.socket = null;
      // 1012 "service restart": the backend replaced its runtime (for example a demo
      // reset). Reconnect promptly instead of continuing an earlier backoff.
      if (event.code === SERVICE_RESTART) this.retries = 0;
      if (!this.stopped) this.scheduleReconnect();
    };
  }

  private receive(data: unknown): void {
    const message = parseLiveMessage(data);
    if (message === null) {
      this.malformed += 1;
      return;
    }
    const key = data as string;
    if (this.recent.includes(key)) {
      this.duplicates += 1;
      return;
    }
    this.recent.push(key);
    if (this.recent.length > DEDUP_WINDOW) this.recent.shift();
    this.lastMessageAt = Date.now();
    if (this.status !== "open") this.setStatus("open");
    this.armStale();
    for (const listener of this.listeners) listener(message);
  }

  private armStale(): void {
    if (this.staleTimer) clearTimeout(this.staleTimer);
    this.staleTimer = setTimeout(() => {
      if (this.status === "open") this.setStatus("stale");
    }, this.opts.staleAfterMs);
  }

  private scheduleReconnect(): void {
    this.clearTimers();
    this.setStatus("closed");
    const delay = Math.min(this.opts.maxBackoffMs, this.opts.minBackoffMs * 2 ** this.retries);
    this.retries += 1;
    this.reconnectTimer = setTimeout(() => {
      if (!this.stopped) this.connect();
    }, delay);
  }

  private clearTimers(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.staleTimer) clearTimeout(this.staleTimer);
    this.reconnectTimer = this.staleTimer = null;
  }

  private setStatus(status: LiveStatus): void {
    if (status === this.status) return;
    this.status = status;
    for (const listener of this.statusListeners) listener(status);
  }
}
