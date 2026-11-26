/**
 * LiveProvider: one LiveClient for the whole app (never one per component).
 *
 * Live messages only refresh what the dashboard displays: they write the latest
 * telemetry and status into the read-only query cache and mark lists stale so
 * they are refetched from the backend. They never trigger a request that could
 * change security state. Refetches are debounced so a burst of events cannot
 * cause a burst of requests.
 */

import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { LiveClient, liveUrl, type LiveStatus } from "../services/live";
import type {
  LiveMessage,
  LiveMessageType,
  LiveThreatScore,
  SystemStatusResponse,
  TelemetrySnapshot,
} from "../types/api";
import { keys } from "./queries";

export interface TrendPoint {
  at: string;
  score: number;
}

interface LiveContextValue {
  status: LiveStatus;
  trend: TrendPoint[];
  lastSeen: Partial<Record<LiveMessageType, string>>;
  malformed: number;
  duplicates: number;
  /** Forget this page's session-only history (after a backend demo reset). */
  clearSession: () => void;
}

const TREND_POINTS = 90;
const REFETCH_DEBOUNCE_MS = 400;

const LiveContext = createContext<LiveContextValue>({
  status: "closed",
  trend: [],
  lastSeen: {},
  malformed: 0,
  duplicates: 0,
  clearSession: () => undefined,
});

// Which cached lists a message makes stale.
const STALE_BY_TYPE: Record<LiveMessageType, readonly (readonly string[])[]> = {
  telemetry: [keys.runtime],
  detection_event: [keys.events, keys.incidents, keys.incidentRoot],
  threat_score: [],
  defense_state_change: [keys.state, keys.incidents, keys.incidentRoot],
  response_action: [keys.actions, keys.incidentRoot, keys.runtime],
};

function isThreatScore(payload: unknown): payload is LiveThreatScore {
  const p = payload as Partial<LiveThreatScore>;
  return typeof p.score === "number" && typeof p.calculated_at === "string" &&
    typeof p.defense_state === "string";
}

function isTelemetry(payload: unknown): payload is TelemetrySnapshot {
  const p = payload as Partial<TelemetrySnapshot>;
  return typeof p.id === "number" && typeof p.collected_at === "string";
}

export function LiveProvider({
  children,
  client: injected,
}: {
  children: ReactNode;
  client?: LiveClient;
}) {
  const queryClient = useQueryClient();
  const clientRef = useRef<LiveClient | null>(injected ?? null);
  if (clientRef.current === null) clientRef.current = new LiveClient({ url: liveUrl(window.location) });
  const [status, setStatus] = useState<LiveStatus>("closed");
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [lastSeen, setLastSeen] = useState<Partial<Record<LiveMessageType, string>>>({});
  const [counters, setCounters] = useState({ malformed: 0, duplicates: 0 });

  useEffect(() => {
    const client = clientRef.current;
    if (client === null) return;
    const pending = new Map<string, ReturnType<typeof setTimeout>>();
    const markStale = (key: readonly string[]) => {
      const id = JSON.stringify(key);
      if (pending.has(id)) return;
      pending.set(
        id,
        setTimeout(() => {
          pending.delete(id);
          void queryClient.invalidateQueries({ queryKey: key });
        }, REFETCH_DEBOUNCE_MS),
      );
    };
    const onMessage = (message: LiveMessage) => {
      setLastSeen((prev) => ({ ...prev, [message.type]: message.timestamp }));
      setCounters({ malformed: client.malformed, duplicates: client.duplicates });
      if (message.type === "telemetry" && isTelemetry(message.payload)) {
        queryClient.setQueryData(keys.telemetry, message.payload);
      }
      if (message.type === "threat_score" && isThreatScore(message.payload)) {
        const p = message.payload;
        const next: SystemStatusResponse = {
          defense_state: p.defense_state,
          threat_score: p.score,
          timestamp: p.calculated_at,
        };
        queryClient.setQueryData(keys.status, next);
        setTrend((prev) => [...prev, { at: p.calculated_at, score: p.score }].slice(-TREND_POINTS));
      }
      for (const key of STALE_BY_TYPE[message.type]) markStale(key);
    };
    const unsubscribe = client.subscribe(onMessage);
    const unwatch = client.onStatus(setStatus);
    client.start();
    return () => {
      unsubscribe();
      unwatch();
      client.stop();
      for (const timer of pending.values()) clearTimeout(timer);
    };
  }, [queryClient]);

  const clearSession = useCallback(() => {
    setTrend([]);
    setLastSeen({});
  }, []);

  const value = useMemo(
    () => ({ status, trend, lastSeen, ...counters, clearSession }),
    [status, trend, lastSeen, counters, clearSession],
  );
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export const useLive = (): LiveContextValue => useContext(LiveContext);
