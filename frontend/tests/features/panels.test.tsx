import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { describe, expect, it } from "vitest";

import { DefenseStatePanel } from "../../src/features/defense-state/DefenseStatePanel";
import { DetectionsPanel } from "../../src/features/detections/DetectionsPanel";
import { ExplanationPanel } from "../../src/features/explanations/ExplanationPanel";
import { DefensePanel } from "../../src/features/responses/DefensePanel";
import type { DefenseState, ExplanationState, ResponseSimulation } from "../../src/types/api";
import { json, recorded, stubBackend, testQueryClient } from "../helpers";

const renderWith = (ui: ReactElement) =>
  render(<QueryClientProvider client={testQueryClient()}>{ui}</QueryClientProvider>);

describe("DefenseStatePanel", () => {
  it.each(["RELAXED", "ALERT", "DEFENSIVE", "AGGRESSIVE"] as DefenseState[])(
    "shows %s in text and marks it as the current step",
    async (state) => {
      stubBackend("relaxed", {
        "/api/v1/status": () => json({ defense_state: state, threat_score: 0.4, timestamp: "2026-11-20T12:00:00Z" }),
      });
      renderWith(<DefenseStatePanel lastTransition={null} />);
      const ladder = await screen.findByRole("list", { name: /Defense states/ });
      const current = within(ladder).getAllByRole("listitem").find((li) => li.getAttribute("aria-current") === "step");
      expect(current?.textContent).toContain(state.charAt(0) + state.slice(1).toLowerCase());
      expect(screen.getAllByText(state).length).toBeGreaterThan(0);
      expect(screen.getByText(`Defense state ${state.charAt(0)}${state.slice(1).toLowerCase()}`)).toBeTruthy();
    },
  );
});

describe("ExplanationPanel", () => {
  const base = recorded("critical", "explanation").body as ExplanationState;

  it("shows a neutral pending label with the deterministic fallback", () => {
    stubBackend("critical");
    renderWith(<ExplanationPanel ai={{ ...base, availability: "PENDING", explanation: null, latest_attempt: null }} />);
    expect(screen.getByText("Explanation pending")).toBeTruthy();
    expect(screen.getByText(base.fallback_text)).toBeTruthy();
    expect(screen.getByText("AI EXPLANATION")).toBeTruthy();
  });

  it("labels the fallback as not AI when no explanation validated", () => {
    stubBackend("critical");
    const failed = { ...(base.explanation as NonNullable<ExplanationState["explanation"]>), status: "REJECTED" as const, failure_reason: "VALIDATOR_REDACTED" as const, content: null };
    renderWith(<ExplanationPanel ai={{ ...base, availability: "UNAVAILABLE", explanation: null, latest_attempt: failed }} />);
    expect(screen.getByText(/Validator redacted/)).toBeTruthy();
    expect(screen.getByText(/Deterministic summary, not AI/)).toBeTruthy();
  });
});

describe("DefensePanel", () => {
  const sims = (recorded("critical", "incident").body as { simulations: ResponseSimulation[] }).simulations;

  it("labels every response SIMULATED and states that the host is unchanged", () => {
    stubBackend("critical");
    renderWith(<DefensePanel simulations={sims} />);
    expect(screen.getAllByText("SIMULATED").length).toBe(sims.length + 1); // + panel header
    expect(screen.getByText(/No firewall, process or file on this host is changed/)).toBeTruthy();
  });

  it("surfaces a non-simulated record instead of hiding it", () => {
    stubBackend("critical");
    const first = sims[0] as ResponseSimulation;
    renderWith(<DefensePanel simulations={[{ ...first, is_simulated: false }]} />);
    expect(screen.getByText("NOT SIMULATED — REVIEW")).toBeTruthy();
  });
});

describe("DetectionsPanel", () => {
  it("shows an empty state when there are no detections", async () => {
    stubBackend("relaxed");
    renderWith(<DetectionsPanel />);
    expect(await screen.findByText(/No detections yet/)).toBeTruthy();
  });

  it("never renders internal fields", async () => {
    stubBackend("critical");
    const { container } = renderWith(<DetectionsPanel />);
    await screen.findAllByText("SYNTHETIC · DEMO");
    for (const internal of ["event_data", "telemetry_sample_id", "scope_key", "raw_response"]) {
      expect(container.textContent).not.toContain(internal);
    }
  });
});
