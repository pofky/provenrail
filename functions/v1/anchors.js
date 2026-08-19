// POST /v1/anchors, on provenrail.com.
//
// This exists so the hosted service answers on the same path as the sink a customer runs
// themselves. `pr anchor-push --url https://provenrail.com` and `pr anchor-push --url
// http://my-own-sink:8000` then differ by one word, and nothing in the CLI has to know that one
// of them is a Supabase edge function.
//
// It is a proxy and nothing else: no logic, no storage, no logging of the body. The coverage
// rules, the signing key and the account lookup all live upstream in supabase/functions/anchor,
// because a rule enforced in two places is a rule that disagrees with itself.
import { SUPABASE_FUNCTIONS } from "../_supabase.js";

const UPSTREAM = `${SUPABASE_FUNCTIONS}/anchor`;

export async function onRequest(context) {
  const { request } = context;
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, content-type, accept",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      },
    });
  }
  if (request.method !== "POST") {
    return json({ error: "POST an anchor here; read one at /v1/anchors/{id}" }, 405);
  }

  const body = await request.text();
  // An anchor request is a stream label, 64 hex characters and an integer. 4 KB is far above
  // that and stops this route being useful as a general relay.
  if (body.length > 4096) return json({ error: "that is not an anchor request" }, 413);

  let upstream;
  try {
    upstream = await fetch(UPSTREAM, {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        authorization: request.headers.get("authorization") || "",
      },
    });
  } catch (_e) {
    // Say which half is down. "Anchor failed" sends the customer to read their own code.
    return json({ error: "the anchor service is unreachable; your records are unaffected" }, 502);
  }
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}
