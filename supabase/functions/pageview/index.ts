// Cookieless first-party analytics beacon for provenrail.com.
// Deliberately stores NO IP address, NO cookie, NO device or cross-site identifier.
// Country comes from the edge header and is coarse (country only).
// verify_jwt is false: this is a public beacon, like any analytics endpoint.
import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = new Set([
  "https://provenrail.com",
  "https://www.provenrail.com",
  "https://provenrail.pages.dev",
]);

const ALLOWED_EVENTS = new Set([
  "pageview",
  "cta_start_free",
  "cta_checkout_builder",
  "cta_checkout_team",
  "cta_verify",
  "cta_docs",
  "verify_run",
]);

function cors(origin: string | null) {
  const allow = origin && ALLOWED_ORIGINS.has(origin) ? origin : "https://provenrail.com";
  return {
    "Access-Control-Allow-Origin": allow,
    // Kept only for the navigator.sendBeacon fallback in web/main.js, which issues in
    // credentials mode "include" and would otherwise have its response rejected. The
    // normal path is a fetch with credentials:'omit', which does not need this and, more
    // to the point, does not make the browser process the __cf_bm cookie our host's edge
    // attaches to every response (Firefox rejects it and logs an error on every page).
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

// Keep only the host of a referrer, never the full URL (which can carry personal data).
function refHost(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw) return null;
  try {
    const h = new URL(raw).hostname.toLowerCase();
    if (h.endsWith("provenrail.com") || h.endsWith("provenrail.pages.dev")) return null; // internal
    return h.slice(0, 120);
  } catch {
    return null;
  }
}

// Path only, no query string and no fragment, capped.
function cleanPath(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw.startsWith("/")) return null;
  return raw.split("?")[0].split("#")[0].slice(0, 200);
}

function cleanShort(raw: unknown, max = 60): string | null {
  if (typeof raw !== "string" || !raw) return null;
  return raw.replace(/[^\w .:-]/g, "").slice(0, max) || null;
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  const headers = { ...cors(origin), "content-type": "application/json" };

  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(origin) });
  if (req.method !== "POST") return new Response("method not allowed", { status: 405, headers });

  try {
    // The beacon sends text/plain (CORS-safelisted) so sendBeacon needs no preflight;
    // parse the raw body rather than relying on the declared content type.
    const body = JSON.parse(await req.text());
    const path = cleanPath(body?.p);
    if (!path) return new Response(JSON.stringify({ ok: false }), { status: 400, headers });

    const event = typeof body?.e === "string" && ALLOWED_EVENTS.has(body.e) ? body.e : "pageview";

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    await supabase.from("pageviews").insert({
      path,
      event,
      ref_host: refHost(body?.r),
      utm_source: cleanShort(body?.u, 40),
      country: (req.headers.get("cf-ipcountry") || "").slice(0, 2) || null,
      viewport: cleanShort(body?.v, 12),
    });

    return new Response(JSON.stringify({ ok: true }), { headers });
  } catch {
    // Analytics must never break or slow the page: swallow everything.
    return new Response(JSON.stringify({ ok: false }), { status: 200, headers });
  }
});
