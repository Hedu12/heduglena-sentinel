import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

import { DefenseStatePanel } from "../features/defense-state/DefenseStatePanel";
import { DemoPanel } from "../features/demo/DemoPanel";
import { DetectionsPanel } from "../features/detections/DetectionsPanel";
import { ExplanationPanel } from "../features/explanations/ExplanationPanel";
import { IncidentTimeline } from "../features/incidents/IncidentTimeline";
import { ThreatAnalysisPanel } from "../features/incidents/ThreatAnalysisPanel";
import { PipelinePanel } from "../features/overview/PipelinePanel";
import { SystemStatusBar } from "../features/overview/SystemStatusBar";
import { TelemetryPanel } from "../features/overview/TelemetryPanel";
import { DefensePanel } from "../features/responses/DefensePanel";
import { LiveProvider, useLive } from "../hooks/live";
import { currentIncident, useIncident, useIncidents } from "../hooks/queries";
import type { LiveClient } from "../services/live";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { staleTime: 2_000, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}

export function Dashboard() {
  const live = useLive();
  const incidents = useIncidents(live.status);
  const current = currentIncident(incidents.data);
  const detail = useIncident(current?.incident_id ?? null, live.status);
  const incident = detail.data ?? null;
  const transitions = incident?.transitions ?? [];
  const lastTransition = transitions.length > 0 ? (transitions[transitions.length - 1] ?? null) : null;

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to dashboard
      </a>
      <header className="app__header">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true" />
          <div>
            <p className="brand__name">HEDUGLENA Sentinel</p>
            <p className="brand__tagline">Adaptive defense console · bio-inspired posture control</p>
          </div>
        </div>
        <SystemStatusBar />
      </header>
      <main id="main" className="grid" tabIndex={-1}>
        <div className="grid__wide">
          <PipelinePanel ai={incident?.ai ?? null} />
        </div>
        <div className="grid__hero">
          <DefenseStatePanel lastTransition={lastTransition} />
        </div>
        <div className="grid__demo">
          <DemoPanel simulatedCount={incident?.simulations.length ?? 0} />
        </div>
        <div className="grid__half">
          <DetectionsPanel />
        </div>
        <div className="grid__half">
          <ThreatAnalysisPanel breakdown={incident?.current_score ?? null} />
        </div>
        <div className="grid__half">
          <DefensePanel simulations={incident?.simulations ?? null} />
        </div>
        <div className="grid__half">
          <ExplanationPanel ai={incident?.ai ?? null} />
        </div>
        <div className="grid__two-thirds">
          <IncidentTimeline detail={incident} />
        </div>
        <div className="grid__third">
          <TelemetryPanel />
        </div>
      </main>
      <footer className="app__footer">
        Security decisions are made by Sentinel's deterministic backend. This console only displays
        them. Every response is simulated; demo events are synthetic.
      </footer>
    </div>
  );
}

interface AppProps {
  queryClient?: QueryClient;
  liveClient?: LiveClient;
}

export function App({ queryClient, liveClient }: AppProps) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <QueryClientProvider client={client}>
      <LiveProvider client={liveClient}>
        <Dashboard />
      </LiveProvider>
    </QueryClientProvider>
  );
}
