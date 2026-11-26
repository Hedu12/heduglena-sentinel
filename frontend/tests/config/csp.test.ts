import { describe, expect, it } from "vitest";

import { connectSources, cspDirectives, cspString, securityHeaders, serveConfig } from "../../config/csp";

describe("production Content Security Policy", () => {
  it("never allows eval or inline code, and defaults to nothing", () => {
    const policy = cspString({ apiBaseUrl: "http://localhost:8000", wsUrl: "ws://localhost:8000" });
    expect(policy).not.toMatch(/unsafe-eval|unsafe-inline|unsafe-hashes|\*|data:|blob:/);
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("script-src 'self'");
    expect(policy).toContain("style-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("base-uri 'none'");
    expect(policy).toContain("frame-ancestors 'none'");
  });

  it("is same-origin by default, which covers the same-origin /ws/live socket", () => {
    expect(connectSources()).toEqual(["'self'"]);
  });

  it("allows exactly the configured API and WebSocket origins", () => {
    expect(
      connectSources({ apiBaseUrl: "https://sentinel.example/api/v1", wsUrl: "wss://sentinel.example/ws/live" }),
    ).toEqual(["'self'", "https://sentinel.example", "wss://sentinel.example"]);
  });

  it.each([
    [{ apiBaseUrl: "javascript:alert(1)" }],
    [{ apiBaseUrl: "ws://localhost:8000" }],
    [{ wsUrl: "http://localhost:8000" }],
    [{ wsUrl: "not a url" }],
  ])("fails the build instead of weakening the policy for %o", (options) => {
    expect(() => cspDirectives(options)).toThrow();
  });

  it("drops frame-ancestors only from the meta variant (meta cannot carry it)", () => {
    expect(cspString({}, { forMeta: true })).not.toContain("frame-ancestors");
    expect(cspString({}, { forMeta: true })).toContain("connect-src 'self'");
  });

  it("ships the CSP and companion headers in serve.json", () => {
    const config = serveConfig() as { headers: { source: string; headers: { key: string; value: string }[] }[] };
    const entry = config.headers[0];
    expect(entry?.source).toBe("**/*");
    const keys = entry?.headers.map((h) => h.key) ?? [];
    expect(keys).toEqual(Object.keys(securityHeaders()));
    expect(keys).toContain("Content-Security-Policy");
    expect(keys).toContain("X-Frame-Options");
  });
});
