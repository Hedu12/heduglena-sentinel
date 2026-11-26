import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { parseLiveMessage, type LiveStatus } from "../../src/services/live";
import { FakeSocket, fakeLiveClient, liveFrame } from "../helpers";

describe("parseLiveMessage", () => {
  it("accepts a well-formed message", () => {
    const m = parseLiveMessage(liveFrame("threat_score", { score: 0.5 }, "2026-11-20T12:00:00Z"));
    expect(m).toEqual({ type: "threat_score", timestamp: "2026-11-20T12:00:00Z", payload: { score: 0.5 } });
  });

  it.each([
    ["not json", "{oops"],
    ["not an object", "[1,2]"],
    ["unknown type", liveFrame("set_state", { state: "RELAXED" })],
    ["bad timestamp", JSON.stringify({ type: "telemetry", timestamp: "soon", payload: {} })],
    ["missing payload", JSON.stringify({ type: "telemetry", timestamp: "2026-11-20T12:00:00Z" })],
    ["binary frame", new ArrayBuffer(4)],
    ["oversized", liveFrame("telemetry", { pad: "x".repeat(70_000) })],
  ])("rejects %s", (_label, raw) => {
    expect(parseLiveMessage(raw)).toBeNull();
  });
});

describe("LiveClient", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("delivers valid messages and drops malformed and duplicate ones", () => {
    const client = fakeLiveClient();
    const seen: string[] = [];
    client.subscribe((m) => seen.push(m.type));
    client.start();
    const socket = FakeSocket.latest();
    socket.open();
    const frame = liveFrame("telemetry", { id: 1 }, "2026-11-20T12:00:00Z");
    socket.receive(frame);
    socket.receive(frame); // duplicate
    socket.receive("garbage");
    socket.receive(liveFrame("detection_event", { id: 2 }, "2026-11-20T12:00:01Z"));
    expect(seen).toEqual(["telemetry", "detection_event"]);
    expect(client.duplicates).toBe(1);
    expect(client.malformed).toBe(1);
    client.stop();
  });

  it("reconnects with backoff after a disconnect, and stops cleanly", () => {
    const client = fakeLiveClient();
    const statuses: LiveStatus[] = [];
    client.onStatus((s) => statuses.push(s));
    client.start();
    FakeSocket.latest().open();
    FakeSocket.latest().drop();
    expect(client.currentStatus).toBe("closed");
    expect(FakeSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(10);
    expect(FakeSocket.instances).toHaveLength(2);
    FakeSocket.latest().drop();
    vi.advanceTimersByTime(10);
    expect(FakeSocket.instances).toHaveLength(2); // backoff doubled to 20 ms
    vi.advanceTimersByTime(10);
    expect(FakeSocket.instances).toHaveLength(3);
    FakeSocket.latest().open();
    expect(statuses).toContain("open");
    client.stop();
    expect(FakeSocket.latest().closed).toBe(true);
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.instances).toHaveLength(3); // no reconnect after stop
  });

  it("reconnects promptly after a service restart (demo reset)", () => {
    const client = fakeLiveClient();
    client.start();
    FakeSocket.latest().drop(); // 10 ms
    vi.advanceTimersByTime(10);
    FakeSocket.latest().drop(); // backoff now 20 ms
    vi.advanceTimersByTime(20);
    expect(FakeSocket.instances).toHaveLength(3);
    FakeSocket.latest().drop(1012); // service restart resets the backoff
    vi.advanceTimersByTime(10);
    expect(FakeSocket.instances).toHaveLength(4);
    client.stop();
  });

  it("marks a silent connection stale, and recovers on the next message", () => {
    const client = fakeLiveClient({ staleAfterMs: 1000 });
    client.start();
    const socket = FakeSocket.latest();
    socket.open();
    vi.advanceTimersByTime(1001);
    expect(client.currentStatus).toBe("stale");
    socket.receive(liveFrame("telemetry", { id: 3 }));
    expect(client.currentStatus).toBe("open");
    client.stop();
  });

  it("opens only one socket even if started twice, and never sends", () => {
    const client = fakeLiveClient();
    client.start();
    client.start();
    expect(FakeSocket.instances).toHaveLength(1);
    FakeSocket.latest().open();
    expect(FakeSocket.latest().sent).toEqual([]);
    client.stop();
  });
});
