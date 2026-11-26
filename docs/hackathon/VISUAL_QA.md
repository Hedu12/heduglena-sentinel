# Visual QA checklist — HEDUGLENA Sentinel dashboard

Scope: the production build (`npm run build`, served by `npm run preview` with the real CSP
headers) against the real backend, at **1280×720** and **1920×1080**.

## How to run it

```bash
# terminal 1 — backend (uses its own SQLite file; demo reset archives it, never deletes)
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000

# terminal 2 — production build with production headers, proxied to the backend
cd frontend
npm run build && npm run verify:csp && npm run preview   # http://localhost:3000
```

In the browser, use DevTools device toolbar (or window size) for 1280×720 and 1920×1080, and
DevTools Rendering → "Emulate CSS prefers-reduced-motion: reduce" for the motion check.

## Checklist

| # | Check | Automated pass (2026-11-23, headless Edge via DevTools protocol) | Manual review |
|---|---|---|---|
| 1 | No horizontal overflow | Page scroll width equals viewport at both sizes, in RELAXED, AGGRESSIVE and after reset | ☐ |
| 2 | No clipped panels | No panel extends past the viewport at either size | ☐ |
| 3 | Readable typography | Body 15 px; smallest text 11.1 px (raised from 10.2 px in this phase) | ☐ |
| 4 | Defense state immediately visible | State badge (24 px) in the first screen at both sizes; at 1280×720 the posture panel starts at y≈350 under the pipeline | ☐ |
| 5 | Detect → Analyze → Decide → Defend → Explain obvious | The pipeline panel is now the first panel (moved above the posture row in this phase) | ☐ |
| 6 | Critical scenario understandable within seconds | Screenshot after "Critical": AGGRESSIVE, score 0.90, Simulated quarantine, all pipeline stages lit | ☐ |
| 7 | SIMULATED responses unmistakable | 23 SIMULATED badges during the critical scenario; "Would have:" wording on every response | ☐ |
| 8 | AI explanation cannot be mistaken for a decision-maker | "AI explains security decisions; it does not make them" in the pipeline; downstream note in the AI panel; Explain stage drawn dashed | ☐ |
| 9 | REAL HOST vs SYNTHETIC · DEMO obvious | Badges present in the telemetry and detection panels; real host memory-pressure detections appear as REAL HOST | ☐ |
| 10 | Keyboard focus visible | Tab reaches the skip link and each demo button; each shows a focus ring | ☐ |
| 11 | Reduced motion respected | Transition duration 0 s with `prefers-reduced-motion: reduce` (0.3 s otherwise) | ☐ |
| 12 | CSP compatible | 0 CSP violations and 0 script exceptions with the production header and meta policy enforced | ☐ |
| 13 | Reset behaves honestly | After reset: RELAXED from the new session, no 500 errors, live stream reconnects (close code 1012) | ☐ |

The ☐ column is for Henok's manual pass in a real browser window; the automated pass does not
replace a human look at the overall impression, colors and spacing.

## Known cosmetic items (not blocking)

- At 1920×1080 the posture panel has empty space below the trend when the DEMO MODE panel is
  taller; the row heights are equalized by the grid.
- The pipeline stages' decorative "→" separators extend into the gap between stages (by design;
  they do not clip text).
- Times are shown in the viewer's local time without a zone label.
