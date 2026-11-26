/**
 * The whole dashboard against the real recorded API contract
 * (tests/fixtures/contract.json, recorded from the backend).
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { FakeSocket, json, liveFrame, offline, recorded, renderDashboard, stubBackend } from "../helpers";

const panel = (name: RegExp) => screen.getByRole("region", { name });

describe("Dashboard against the real API contract", () => {
  it("shows a normal RELAXED system with no incident", async () => {
    stubBackend("relaxed");
    renderDashboard();
    const posture = panel(/Defense posture/);
    await within(posture).findByText("Current defense state");
    expect(within(posture).getAllByText("RELAXED").length).toBeGreaterThan(0);
    expect(await within(panel(/Recent detections/)).findByText(/No detections yet/)).toBeTruthy();
    expect(within(panel(/Incident timeline/)).getByText(/No incident recorded/)).toBeTruthy();
    expect(within(panel(/Why this threat score/)).getByText(/No active incident/)).toBeTruthy();
    expect(await within(panel(/Host telemetry/)).findByText("20.0%")).toBeTruthy();
    expect(await screen.findByText("Online")).toBeTruthy();
  });

  it("shows the critical scenario end to end: detect, analyze, decide, defend, explain", async () => {
    stubBackend("critical");
    renderDashboard();
    const posture = panel(/Defense posture/);
    expect((await within(posture).findAllByText("AGGRESSIVE")).length).toBeGreaterThan(0);
    const score = recorded("critical", "status").body as { threat_score: number };
    expect(within(posture).getByText(score.threat_score.toFixed(2))).toBeTruthy();

    const detections = panel(/Recent detections/);
    expect((await within(detections).findAllByText("SYNTHETIC · DEMO")).length).toBeGreaterThan(0);

    const analysis = panel(/Why this threat score/);
    expect(await within(analysis).findByText("Cross-domain")).toBeTruthy();

    const defense = panel(/Guarded responses/);
    expect(await within(defense).findByText("Simulated quarantine")).toBeTruthy();
    expect(within(defense).getAllByText("SIMULATED").length).toBeGreaterThan(1);
    expect(within(defense).getAllByText("Guard: authorized").length).toBeGreaterThan(0);

    const timeline = panel(/Incident SIT-1 timeline/);
    for (const step of ["1. Detection", "3. State transition", "6. Guard decision", "8. AI explanation"]) {
      expect((await within(timeline).findAllByText(step)).length).toBeGreaterThan(0);
    }

    const explanation = panel(/Incident explanation/);
    const content = (recorded("critical", "explanation").body as { explanation: { content: { summary: string } } })
      .explanation.content;
    expect(await within(explanation).findByText(content.summary)).toBeTruthy();
    expect(within(explanation).getByText("AI EXPLANATION")).toBeTruthy();
    expect(within(explanation).getByText(/cannot modify threat scoring, defense state, or response actions/)).toBeTruthy();
    expect(screen.getByText(/AI explains security decisions; it does not make them/)).toBeTruthy();
  });

  it("never calls the backend with anything but GET on page load", async () => {
    const { calls } = stubBackend("critical");
    renderDashboard();
    await screen.findByText("Simulated quarantine");
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((c) => c.method === "GET")).toBe(true);
  });

  it("renders untrusted text as text, never as markup", async () => {
    const events = recorded("critical", "events").body as Record<string, unknown>[];
    const hostile = [{ ...events[0], rule_name: "<img src=x onerror=alert(1)>" }];
    stubBackend("critical", { "/api/v1/events": () => json(hostile) });
    const { container } = renderDashboard();
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("Failure and empty states", () => {
  it("shows Offline and no data when the backend is unreachable", async () => {
    stubBackend("relaxed", Object.fromEntries(
      ["/health", "/api/v1/status", "/api/v1/runtime", "/api/v1/telemetry/latest", "/api/v1/events",
        "/api/v1/actions", "/api/v1/incidents", "/api/v1/demo/scenarios", "/api/v1/ai/status"].map((p) => [p, offline]),
    ));
    renderDashboard();
    expect(await screen.findByText("Offline")).toBeTruthy();
    expect(within(panel(/Defense posture/)).queryByText("RELAXED")).toBeNull();
    expect((await screen.findAllByText(/Backend offline/)).length).toBeGreaterThan(0);
    expect(screen.queryByText("Online")).toBeNull();
  });

  it("shows loading states before data arrives", () => {
    stubBackend("relaxed", { "/api/v1/status": () => new Promise<Response>(() => undefined) });
    renderDashboard();
    expect(screen.getByText("Loading defense state…")).toBeTruthy();
  });

  it("explains 503 and 404 instead of inventing values", async () => {
    stubBackend("relaxed", {
      "/api/v1/status": () => json({ detail: "no decision yet" }, 503),
      "/api/v1/telemetry/latest": () => json({ detail: "no telemetry yet" }, 404),
    });
    renderDashboard();
    expect(await within(panel(/Defense posture/)).findByText(/Runtime not ready yet \(503\)/)).toBeTruthy();
    expect(await within(panel(/Host telemetry/)).findByText(/No data yet \(404\)/)).toBeTruthy();
  });
});

describe("Live stream", () => {
  it("applies backend score updates, ignores malformed frames, and reports disconnects", async () => {
    stubBackend("relaxed");
    const { liveClient } = renderDashboard();
    const posture = panel(/Defense posture/);
    await within(posture).findByText("Current defense state");
    const socket = FakeSocket.latest();
    act(() => socket.open());
    expect(await screen.findByText("Connected")).toBeTruthy();

    act(() => {
      socket.receive("{not json");
      socket.receive(liveFrame("threat_score", { calculated_at: "2026-11-20T12:00:05Z", score: 0.61, defense_state: "DEFENSIVE" }));
    });
    expect(await within(posture).findByText("0.61")).toBeTruthy();
    expect(within(posture).getAllByText("DEFENSIVE").length).toBeGreaterThan(0);
    expect(liveClient.malformed).toBe(1);

    act(() => socket.drop());
    expect(await screen.findByText("Disconnected")).toBeTruthy();
    liveClient.stop();
  });
});

describe("Demo controls", () => {
  it("starts a scenario only when the operator clicks", async () => {
    const posts: string[] = [];
    stubBackend("relaxed", {
      "/api/v1/demo/scenario/critical": (method) => {
        posts.push(method);
        return json({ scenario: "critical", status: "started", message: "ok" }, 202);
      },
    });
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    const button = await within(demo).findByRole("button", { name: /Critical/ });
    await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
    expect(posts).toEqual([]);
    await userEvent.click(button);
    await waitFor(() => expect(posts).toEqual(["POST"]));
  });

  it.each([
    [409, /already running/],
    [429, /rate limit/],
    [503, /runtime is not running/],
  ])("explains a %i response", async (status, message) => {
    stubBackend("relaxed", { "/api/v1/demo/scenario/suspicious": () => json({ detail: "x" }, status) });
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    const button = await within(demo).findByRole("button", { name: /Suspicious/ });
    await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
    await userEvent.click(button);
    expect(await within(demo).findByText(message)).toBeTruthy();
  });

  it("shows that demo mode is disabled when the backend says 403", async () => {
    stubBackend("relaxed", { "/api/v1/demo/scenarios": () => json({ detail: "demo mode is disabled" }, 403) });
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    expect(await within(demo).findByText(/Demo mode is disabled on the backend/)).toBeTruthy();
    expect(within(demo).queryByRole("button")).toBeNull();
  });

  it("offers no control that could choose a state, a score or an incident", async () => {
    stubBackend("relaxed");
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    expect(await within(demo).findByText(/cannot set the defense state/)).toBeTruthy();
    // The only controls are the three scenarios and the reset; none takes a value.
    const labels = within(demo).getAllByRole("button").map((b) => b.textContent ?? "");
    const allowed = [/^Normal/, /^Suspicious/, /^Critical/, /^Reset demo session$/];
    expect(labels).toHaveLength(4);
    for (const label of labels) expect(allowed.some((a) => a.test(label))).toBe(true);
    expect(within(demo).queryByRole("textbox")).toBeNull();
    expect(within(demo).queryByRole("spinbutton")).toBeNull();
  });
});

describe("Demo reset", () => {
  it("asks the backend, with no data, only after a deliberate confirmation", async () => {
    let snapshot: "relaxed" | "critical" = "critical";
    const resets: { method: string; body: unknown; query: string }[] = [];
    stubBackend(() => snapshot, {
      "/api/v1/demo/reset": (method, init, url) => {
        resets.push({ method, body: init?.body, query: url?.search ?? "" });
        snapshot = "relaxed"; // the backend started a new, empty session
        return json({ status: "reset", archived_session: "session-20261120T120000000000Z", defense_state: "RELAXED", message: "ok" });
      },
    });
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    const posture = panel(/Defense posture/);
    expect((await within(posture).findAllByText("AGGRESSIVE")).length).toBeGreaterThan(0);

    await userEvent.click(await within(demo).findByRole("button", { name: "Reset demo session" }));
    expect(resets).toEqual([]); // the first click only asks for confirmation
    await userEvent.click(within(demo).getByRole("button", { name: "Confirm reset" }));

    await waitFor(() => expect(resets).toHaveLength(1));
    expect(resets[0]).toEqual({ method: "POST", body: undefined, query: "" });
    expect(await within(demo).findByText("session-20261120T120000000000Z")).toBeTruthy();
    // Every panel is re-read from the backend's new session, not adjusted locally.
    expect(await within(panel(/Incident timeline/)).findByText(/No incident recorded/)).toBeTruthy();
    await waitFor(() => expect(within(posture).queryByText("AGGRESSIVE")).toBeNull());
    expect(within(posture).getAllByText("RELAXED").length).toBeGreaterThan(0);
  });

  it("can be cancelled without contacting the backend", async () => {
    const { calls } = stubBackend("critical");
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    await userEvent.click(await within(demo).findByRole("button", { name: "Reset demo session" }));
    await userEvent.click(within(demo).getByRole("button", { name: "Cancel" }));
    expect(calls.some((c) => c.path === "/api/v1/demo/reset")).toBe(false);
    expect(within(demo).getByRole("button", { name: "Reset demo session" })).toBeTruthy();
  });

  it("explains a refused reset and keeps showing the backend's state", async () => {
    stubBackend("critical", {
      "/api/v1/demo/reset": () => json({ detail: "a demo reset needs a local SQLite database file" }, 409),
    });
    renderDashboard();
    const demo = panel(/DEMO MODE/);
    await userEvent.click(await within(demo).findByRole("button", { name: "Reset demo session" }));
    await userEvent.click(within(demo).getByRole("button", { name: "Confirm reset" }));
    expect(await within(demo).findByText(/Reset not possible right now \(409\)/)).toBeTruthy();
    expect(within(panel(/Defense posture/)).getAllByText("AGGRESSIVE").length).toBeGreaterThan(0);
  });
});
