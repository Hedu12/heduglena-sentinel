import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

import { cspString, securityHeaders, serveConfig, type CspOptions } from "./config/csp";

// The dev server proxies the backend, so the browser talks to one origin
// (http://localhost:3000, the backend's FRONTEND_ORIGIN) and the WebSocket
// origin check passes. The dev server listens on localhost only.
const apiTarget = process.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const wsTarget = process.env.VITE_WS_URL ?? "ws://localhost:8000";

// The production build calls these origins only when explicitly configured;
// otherwise it is same-origin (a reverse proxy serves /api, /health and /ws).
const cspOptions: CspOptions = {
  apiBaseUrl: process.env.VITE_API_BASE_URL || undefined,
  wsUrl: process.env.VITE_WS_URL || undefined,
};

/** Production only: a <meta> CSP in index.html and serve.json with the response headers. */
function productionSecurity(): Plugin {
  return {
    name: "sentinel-production-security",
    apply: "build",
    transformIndexHtml: () => [
      {
        tag: "meta",
        attrs: { "http-equiv": "Content-Security-Policy", content: cspString(cspOptions, { forMeta: true }) },
        injectTo: "head-prepend",
      },
    ],
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "serve.json",
        source: `${JSON.stringify(serveConfig(cspOptions), null, 2)}\n`,
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), productionSecurity()],
  server: {
    host: "localhost",
    port: 3000,
    strictPort: true,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/health": { target: apiTarget, changeOrigin: true },
      "/ws": { target: wsTarget, ws: true, changeOrigin: true },
    },
  },
  // `npm run preview` serves the production build with the production headers.
  preview: {
    host: "localhost",
    port: 3000,
    strictPort: true,
    headers: securityHeaders(cspOptions),
  },
  test: {
    globals: false,
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
