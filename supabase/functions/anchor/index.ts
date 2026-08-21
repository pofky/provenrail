// The anchor-only trust service, hosted.
//
// A customer self-hosts the AGPL sink, keeps every record, and sends the Merkle root over their
// own record hashes plus how far it reaches. Nothing else. There is no field in this request a
// record could arrive in, which is the point: the operator is a sole proprietor with no liability
// shield, and holding customer agent records would make him a GDPR processor. A SHA-256 root over
// hashes is not personal data by any route, so this service can be operated without that.
//
// It runs here rather than on a paid host because the whole thing is "receive 32 bytes, sign
// them, never lose them", which the free tier does perfectly well, and paying monthly to find out
// whether anyone wants it would be the wrong way round.
//
// The receipt format is byte-identical to LocalAnchor in src/provenrail/anchor.py: the signature
// covers `${merkle_root}|${gen_time}` and is hex, and the public key is raw Ed25519 as hex. That
// is what lets `pr anchor-verify` check a receipt minted here without knowing it was minted here.
// tests/test_anchor_edge_function.py holds the two implementations to that.
//
// verify_jwt is false: pushing an anchor authenticates with an account key, and reading one is
// deliberately public so an auditor needs no account. See supabase/config.toml.
import { createClient } from "jsr:@supabase/supabase-js@2";
import { trustedTimestamp } from "./rfc3161.js";
import { hex, resolveAccount } from "./account.ts";

const ALLOWED_ORIGINS = new Set([
  "https://provenrail.com",
  "https://www.provenrail.com",
  "https://provenrail.pages.dev",
]);

function cors(origin: string | null) {
  const allow = origin && ALLOWED_ORIGINS.has(origin) ? origin : "https://provenrail.com";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, content-type, accept",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}

function json(body: unknown, status: number, origin: string | null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...cors(origin) },
  });
}

// ---- signing -------------------------------------------------------------------------------
// The private key is a 32-byte Ed25519 seed, hex, in the ANCHOR_SIGNING_KEY secret. It never
// leaves this function and is never returned; only the public half appears in a receipt.

let cachedKey: CryptoKey | null = null;
let cachedPub: string | null = null;



function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// PKCS8 wrapper for a raw Ed25519 seed. WebCrypto will not import a bare seed, and hand-rolling
// the 16-byte prefix is the smallest way in without pulling a dependency into an edge function.
const PKCS8_ED25519_PREFIX = unhex("302e020100300506032b657004220420");

async function signingKey(): Promise<{ key: CryptoKey; pub: string }> {
  if (cachedKey && cachedPub) return { key: cachedKey, pub: cachedPub };
  const seedHex = (Deno.env.get("ANCHOR_SIGNING_KEY") || "").trim();
  if (!/^[0-9a-f]{64}$/i.test(seedHex)) {
    // Refusing here is deliberate. A service that signs with a key it invented on boot would
    // hand out receipts that stop verifying the next time it restarts, which is worse than being
    // down: the customer would only discover it when an auditor checked.
    throw new Error("ANCHOR_SIGNING_KEY must be 32 hex-encoded bytes");
  }
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(unhex(seedHex), PKCS8_ED25519_PREFIX.length);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);

  // The public half is derived by signing nothing useful? No: derive it properly by importing
  // the seed as a JWK is not available, so the public key is supplied alongside and checked.
  const pub = (Deno.env.get("ANCHOR_PUBLIC_KEY") || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pub)) {
    throw new Error("ANCHOR_PUBLIC_KEY must be 32 hex-encoded bytes");
  }
  cachedKey = key;
  cachedPub = pub;
  return { key, pub };
}

function utcNow(): string {
  // Matches Python's "%Y-%m-%dT%H:%M:%S.%fZ": microseconds, not milliseconds, because the
  // signature covers this string and the two implementations must produce the same bytes.
  const d = new Date();
  const iso = d.toISOString();                      // 2026-08-19T04:26:48.336Z
  return iso.slice(0, -1) + "000Z";                 // 2026-08-19T04:26:48.336000Z
}

async function selfSigned(root: string) {
  const { key, pub } = await signingKey();
  const genTime = utcNow();
  const payload = new TextEncoder().encode(`${root}|${genTime}`);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, payload);
  return {
    kind: "local",
    merkle_root: root,
    gen_time: genTime,
    token_b64: null,
    signature: hex(sig),
    anchor_pubkey: pub,
    tsa_url: null,
  };
}

// A public RFC 3161 authority. FreeTSA is the default because its root is already in the
// verifier's trust store, so an auditor validates the certificate chain with no flags and no
// configuration. Overridable, since a customer's own auditor may insist on a particular one.
const TSA_URL = (Deno.env.get("ANCHOR_TSA_URL") || "https://freetsa.org/tsr").trim();

/**
 * The strongest receipt available right now.
 *
 * A trusted timestamp is the difference between "they say it was anchored then" and "an
 * independent authority signed that it was", and it is the reason to use a hosted anchor at all
 * rather than signing your own roots. So it is tried first.
 *
 * When the authority is unreachable the anchor still goes through, self-signed. Refusing would
 * leave the customer's chain unanchored because a third party was having an outage, which is a
 * worse outcome than a weaker receipt, and the receipt is not quietly weaker: kind is "local",
 * every verifier warns that the time is self-asserted, and the auditor page says so in words.
 * The one thing that must never happen is a self-signed receipt wearing an rfc3161 label.
 */
async function mintReceipt(root: string) {
  try {
    const { genTime, tokenB64 } = await trustedTimestamp(
      unhex(root),
      TSA_URL,
      (url: RequestInfo | URL, init?: RequestInit) =>
        fetch(url, { ...init, signal: AbortSignal.timeout(8000) }),
    );
    return {
      kind: "rfc3161",
      merkle_root: root,
      gen_time: genTime,
      token_b64: tokenB64,
      signature: null,
      anchor_pubkey: null,
      tsa_url: TSA_URL,
    };
  } catch (e) {
    console.error("trusted timestamp unavailable, falling back to self-signed:",
                  (e as Error).message);
    return await selfSigned(root);
  }
}

// ---- validation ----------------------------------------------------------------------------

function checkedRoot(v: unknown): string {
  const root = String(v ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(root)) {
    throw new Error("a Merkle root is 32 bytes, so 64 hex characters");
  }
  return root;
}

function checkedCoverage(v: unknown): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 2 ** 53) {
    throw new Error("covers_up_to is how many records the root spans, so it must be a whole number of at least 1");
  }
  return v;
}

function checkedStream(v: unknown): string {
  const s = String(v ?? "").trim();
  if (!s || s.length > 200) throw new Error("stream_id must be a label of 1 to 200 characters");
  return s;
}

// ---- handler -------------------------------------------------------------------------------

// ---- who is asking -------------------------------------------------------------------------

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(origin) });

  const db = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  const url = new URL(req.url);
  const anchorId = url.searchParams.get("id");

  // Reading one anchor is public, with no account and no permission from the customer, because
  // an auditor holding a receipt must be able to check it without asking either party.
  if (req.method === "GET") {
    if (!anchorId) return json({ error: "pass ?id=anc_..." }, 400, origin);
    const { data, error } = await db
      .from("external_anchors")
      .select("anchor_id, stream_id, merkle_root, covers_up_to, receipt, created_at")
      .eq("anchor_id", anchorId)
      .maybeSingle();
    if (error) return json({ error: "lookup failed" }, 500, origin);
    if (!data) return json({ error: "no such anchor" }, 404, origin);
    return json(data, 200, origin);          // note: account_id is never selected, so never leaks
  }

  if (req.method !== "POST") return json({ error: "method not allowed" }, 405, origin);

  const auth = req.headers.get("authorization") || "";
  const key = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!key) return json({ error: "missing API key" }, 401, origin);

  let stream_id: string, merkle_root: string, covers_up_to: number;
  try {
    const body = await req.json();
    stream_id = checkedStream(body.stream_id);
    merkle_root = checkedRoot(body.merkle_root);
    covers_up_to = checkedCoverage(body.covers_up_to);
  } catch (e) {
    return json({ error: String((e as Error).message || e) }, 422, origin);
  }

  const account = await resolveAccount(db, key);
  if (account.error || !account.acct) {
    return json({ error: account.error || "invalid API key" }, account.status || 401, origin);
  }
  const acct = account.acct;

  // Coverage may only grow, and one prefix may only have one history. This is the service: a
  // customer who anchors 1000 records, breaks at 400, and re-anchors the shorter chain must not
  // get our signature on the rewrite. Settled before anything is signed.
  const { data: prev } = await db
    .from("external_anchors")
    .select("anchor_id, merkle_root, covers_up_to, receipt, stream_id, created_at")
    .eq("account_id", acct.account_id)
    .eq("stream_id", stream_id)
    .order("covers_up_to", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (prev) {
    if (covers_up_to < prev.covers_up_to) {
      return json({
        error: `this stream is already anchored to ${prev.covers_up_to} records; an anchor ` +
          `covering only ${covers_up_to} would drop the tail. Anchor the full chain, or open a ` +
          `new stream if you meant to start over.`,
      }, 409, origin);
    }
    if (covers_up_to === prev.covers_up_to) {
      if (prev.merkle_root !== merkle_root) {
        return json({
          error: `this stream is already anchored at ${covers_up_to} records with a different ` +
            `root. The same prefix cannot have two histories.`,
        }, 409, origin);
      }
      // An exact duplicate is a retry, not a new fact. Same id back, no second row.
      const { account_id: _drop, ...row } = prev as Record<string, unknown>;
      return json(row, 200, origin);
    }
  }

  let receipt;
  try {
    receipt = await mintReceipt(merkle_root);
  } catch (e) {
    console.error("signing unavailable:", (e as Error).message);
    return json({ error: "anchor signing is not configured" }, 503, origin);
  }

  const anchor_id = "anc_" + hex(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const row = {
    anchor_id,
    account_id: acct.account_id,
    stream_id,
    merkle_root,
    covers_up_to,
    receipt,
    created_at: new Date().toISOString(),
  };
  const { error } = await db.from("external_anchors").insert(row);
  if (error) {
    // A unique index on (account_id, stream_id, covers_up_to) turns a race into this, which is
    // the same answer the pre-check would have given.
    if (String(error.code) === "23505") {
      return json({ error: "this stream is already anchored at that length" }, 409, origin);
    }
    console.error("insert failed:", error.message);
    return json({ error: "could not record the anchor" }, 500, origin);
  }

  const { account_id: _hidden, ...publicRow } = row;
  return json(publicRow, 200, origin);
});
