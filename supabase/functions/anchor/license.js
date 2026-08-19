// Verifying a Provenrail license key, at the edge, offline.
//
// The point of this file is that buying the product is the only provisioning step. A license key
// is a self-contained Ed25519-signed token: prefix, base64url payload, dot, base64url signature.
// The Polar webhook mints one the moment a subscription activates, so by the time a customer
// types `pr anchor-push --key prl_live_...` the key already exists, already names their account,
// and already carries their plan and expiry. Nothing here has to be issued, emailed, or looked
// up in a table, and there is no state that can be out of step with what they paid for.
//
// This is a port of verify_license() in src/provenrail/license.py and must stay one:
// tests/test_anchor_license_auth.py signs keys with the Python issuer and requires this code to
// reach the same verdict, including on the tampered and expired cases.
//
// Written as .js so that test can import this exact file under Node rather than a copy of it.

const PREFIX = "prl_live_";

function b64urlToBytes(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Verify a license key against the issuer's public key.
 *
 * Returns {valid, plan, account, expires_at, reason}. Never throws on bad input: a malformed key
 * is an ordinary thing for a service to receive, and an exception here would answer 500 to what
 * is really a 401.
 *
 * `nowSeconds` is a parameter rather than a call to the clock so the expiry boundary is testable
 * without waiting for it.
 */
export async function verifyLicense(token, publicKeyHex, nowSeconds) {
  if (!token || !token.startsWith(PREFIX)) {
    return { valid: false, reason: "not a Provenrail license key" };
  }
  const body = token.slice(PREFIX.length);
  const dot = body.indexOf(".");
  if (dot < 0 || body.indexOf(".", dot + 1) >= 0) {
    return { valid: false, reason: "malformed license key" };
  }
  const b64payload = body.slice(0, dot);
  const b64sig = body.slice(dot + 1);

  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw", unhex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    // The signature covers the base64url payload as ASCII, not the decoded JSON. Signing the
    // decoded form instead would let two different encodings of one payload share a signature.
    ok = await crypto.subtle.verify(
      { name: "Ed25519" }, key, b64urlToBytes(b64sig), new TextEncoder().encode(b64payload));
  } catch (_e) {
    return { valid: false, reason: "license signature does not verify" };
  }
  if (!ok) return { valid: false, reason: "license signature does not verify" };

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(b64payload)));
  } catch (_e) {
    return { valid: false, reason: "license payload is unreadable" };
  }
  const exp = payload.exp;
  if (exp !== null && exp !== undefined && nowSeconds > Number(exp)) {
    return { valid: false, plan: payload.plan, account: payload.account, expires_at: exp,
             reason: "license expired" };
  }
  return { valid: true, plan: payload.plan, account: payload.account, expires_at: exp ?? null };
}
