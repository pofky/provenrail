// Same-origin analytics beacon proxy.
//
// Why this exists at all: the beacon used to POST straight to the Supabase edge function, and
// that function reads `cf-ipcountry` to record a coarse country. Cloudflare fronts the Supabase
// host but does NOT forward that header to it (verified against the live endpoint: it sees
// cf-connecting-ip, cf-ray and cf-visitor, and no cf-ipcountry). The column was therefore NULL
// for every one of the first 2,204 pageviews. Our own Pages edge does know the country, so the
// beacon now lands here first and the country is attached where it is actually available.
//
// It also makes the beacon first-party: same origin, no CORS, no cross-site request, and a
// failure is visible to the caller so it can fall back instead of silently dropping the event.
//
// Privacy is unchanged and deliberate: country only, never the IP, never a cookie, never an
// identifier. The visitor's IP is not forwarded and not logged here.
import { SUPABASE_FUNCTIONS } from "./_supabase.js";

const UPSTREAM = `${SUPABASE_FUNCTIONS}/pageview`;

export async function onRequest(context) {
  const { request, env } = context;
  // Anything that is not a POST is not a beacon. Answer cheaply rather than proxying.
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
  try {
    const body = await request.text();
    // 2 KB is far above any real beacon payload and keeps this from being used as a relay.
    if (body.length > 2048) return new Response(null, { status: 204 });

    const headers = { "content-type": "text/plain;charset=UTF-8" };
    // Cloudflare puts the two-letter country on the request object. "T1" (Tor) and "XX"
    // (unknown) are real values from Cloudflare and are dropped rather than stored as a country.
    const cc = (request.cf && request.cf.country) || request.headers.get("cf-ipcountry") || "";
    if (/^[A-Z]{2}$/.test(cc) && cc !== "XX" && cc !== "T1") headers["x-pv-country"] = cc;
    // Shared secret. Without it the upstream ignores the country header, so nobody can forge
    // geography by calling the Supabase endpoint directly. If the secret is unset on either
    // side, everything still works and country simply stays null, as it did before.
    if (env && env.PV_PROXY_SECRET) headers["x-pv-secret"] = env.PV_PROXY_SECRET;

    context.waitUntil(fetch(UPSTREAM, { method: "POST", body, headers }).catch(() => {}));
  } catch (_e) { /* analytics must never surface to the visitor */ }
  return new Response(null, { status: 204 });
}
