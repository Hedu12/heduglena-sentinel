/**
 * Content Security Policy for the production build (single source of truth).
 *
 * The built dashboard loads one module script and one stylesheet from its own
 * origin, makes fetch requests to the API and opens the /ws/live WebSocket. It has
 * no inline scripts, no inline <style>, no eval and no third-party resources, so the
 * policy allows exactly that and nothing else. React sets style values through the
 * CSSOM, which CSP does not restrict, so 'unsafe-inline' is not needed.
 *
 * connect-src is 'self' (CSP Level 3 includes same-origin ws:/wss: in 'self') plus
 * the explicit API and WebSocket origins when the build is configured to call a
 * different origin (VITE_API_BASE_URL, VITE_WS_URL). An invalid origin fails the
 * build instead of weakening the policy.
 */

export interface CspOptions {
  apiBaseUrl?: string;
  wsUrl?: string;
}

function origin(value: string, allowed: readonly string[], name: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
  if (!allowed.includes(url.protocol)) {
    throw new Error(`${name} must use ${allowed.join(" or ")}`);
  }
  return url.origin;
}

export function connectSources({ apiBaseUrl, wsUrl }: CspOptions = {}): string[] {
  const sources = ["'self'"];
  if (apiBaseUrl) sources.push(origin(apiBaseUrl, ["http:", "https:"], "VITE_API_BASE_URL"));
  if (wsUrl) {
    // A socket on another origin is never covered by 'self', so it is listed exactly.
    sources.push(origin(wsUrl, ["ws:", "wss:"], "VITE_WS_URL"));
  }
  return [...new Set(sources)];
}

export function cspDirectives(options: CspOptions = {}): Record<string, string[]> {
  return {
    "default-src": ["'none'"],
    "script-src": ["'self'"],
    "style-src": ["'self'"],
    "img-src": ["'self'"],
    "font-src": ["'self'"],
    "connect-src": connectSources(options),
    "manifest-src": ["'self'"],
    "base-uri": ["'none'"],
    "form-action": ["'none'"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
  };
}

/** The policy string. A <meta> CSP cannot carry frame-ancestors, so it is left out there. */
export function cspString(options: CspOptions = {}, { forMeta = false } = {}): string {
  return Object.entries(cspDirectives(options))
    .filter(([name]) => !(forMeta && name === "frame-ancestors"))
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}

/** Response headers for the production static server (serve.json, vite preview). */
export function securityHeaders(options: CspOptions = {}): Record<string, string> {
  return {
    "Content-Security-Policy": cspString(options),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
}

/** serve.json for `serve -s dist` (the frontend Docker image). */
export function serveConfig(options: CspOptions = {}): object {
  return {
    headers: [
      {
        source: "**/*",
        headers: Object.entries(securityHeaders(options)).map(([key, value]) => ({ key, value })),
      },
    ],
  };
}
