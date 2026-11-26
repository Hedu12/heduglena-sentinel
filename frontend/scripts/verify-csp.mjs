// Verify the production build is CSP-compatible: run after `npm run build`.
//
//   npm run verify:csp
//
// Fails if dist/index.html has no CSP <meta>, contains an inline script, inline
// style or event-handler attribute (which the policy would block), or if
// dist/serve.json is missing the response headers or allows unsafe sources.
import { readFileSync } from "node:fs";

const fail = (message) => {
  console.error(`verify-csp: ${message}`);
  process.exit(1);
};

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
const serve = JSON.parse(readFileSync(new URL("../dist/serve.json", import.meta.url), "utf8"));

const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/);
if (!meta) fail("index.html has no Content-Security-Policy meta tag");
for (const script of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
  if (!/\bsrc=/.test(script[1]) || script[2].trim() !== "") fail("index.html contains an inline script");
}
if (/<style\b/.test(html)) fail("index.html contains an inline <style>");
if (/\sstyle=/.test(html)) fail("index.html contains an inline style attribute");
if (/\son[a-z]+=/i.test(html)) fail("index.html contains an inline event handler");

const headers = Object.fromEntries(serve.headers[0].headers.map((h) => [h.key, h.value]));
const csp = headers["Content-Security-Policy"];
if (!csp) fail("serve.json has no Content-Security-Policy header");
for (const policy of [csp, meta[1]]) {
  if (/unsafe-(eval|inline)|\*/.test(policy)) fail(`policy allows an unsafe source: ${policy}`);
  if (!/script-src 'self'/.test(policy) || !/default-src 'none'/.test(policy)) fail("policy is not restrictive");
}
if (!/frame-ancestors 'none'/.test(csp)) fail("header policy lacks frame-ancestors 'none'");
for (const name of ["X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"]) {
  if (!headers[name]) fail(`serve.json lacks ${name}`);
}
console.log("verify-csp: ok");
console.log(`  header: ${csp}`);
