/**
 * Display formatting only. Nothing here scores, ranks or decides anything:
 * every value shown comes from the backend unchanged, only formatted.
 */

import type { ActionType, DefenseState } from "../types/api";

export const STATES: readonly DefenseState[] = ["RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE"];

export const STATE_COPY: Record<DefenseState, { label: string; meaning: string }> = {
  RELAXED: { label: "Relaxed", meaning: "Normal monitoring" },
  ALERT: { label: "Alert", meaning: "Heightened monitoring, incident recorded" },
  DEFENSIVE: { label: "Defensive", meaning: "Simulated blocking and isolation" },
  AGGRESSIVE: { label: "Aggressive", meaning: "Maximum simulated response" },
};

export const ACTION_LABELS: Record<ActionType, string> = {
  GENERATE_ALERT: "Raise alert",
  INCREASE_MONITORING: "Increase monitoring",
  RECORD_INCIDENT: "Record incident",
  SIMULATE_IP_BLOCK: "Simulated IP block",
  SIMULATE_PROCESS_ISOLATE: "Simulated process isolation",
  SIMULATE_QUARANTINE: "Simulated quarantine",
};

/** "AUTH_FAILURE_BURST" or "auth_failure" -> "Auth failure burst". */
export function humanize(code: string | null | undefined): string {
  if (!code) return "—";
  const words = code.replace(/[_-]+/g, " ").trim().toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Backend timestamps without a zone (SQLite) are UTC. */
export function parseTime(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const zoned = /([zZ]|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : `${iso}Z`;
  const date = new Date(zoned);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function clock(iso: string | null | undefined): string {
  const date = parseTime(iso);
  return date ? date.toLocaleTimeString(undefined, { hour12: false }) : "—";
}

export function ago(iso: string | null | undefined, now: number = Date.now()): string {
  const date = parseTime(iso);
  if (!date) return "never";
  const seconds = Math.max(0, Math.round((now - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

export function duration(fromIso: string | null | undefined, now: number = Date.now()): string {
  const date = parseTime(fromIso);
  if (!date) return "—";
  const total = Math.max(0, Math.floor((now - date.getTime()) / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
}

export function score(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toFixed(2);
}

export function percent(value: number | null | undefined, digits = 0): string {
  return value === null || value === undefined ? "—" : `${value.toFixed(digits)}%`;
}

/** A 0..1 fraction shown as a percentage (confidence). */
export function fraction(value: number | null | undefined): string {
  return value === null || value === undefined ? "not assessed" : `${Math.round(value * 100)}%`;
}

export function rate(bytesPerSecond: number | null | undefined): string {
  if (bytesPerSecond === null || bytesPerSecond === undefined) return "—";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let value = bytesPerSecond;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${value.toFixed(value >= 100 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function stateIndex(state: DefenseState): number {
  return STATES.indexOf(state);
}
