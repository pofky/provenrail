// Minting a Provenrail licence key, in one place.
//
// Two functions issue keys now: polar-webhook, when a subscription goes active, and
// trial-license, when a signed-in visitor claims the one free anchor. A second copy of this
// routine would be a second thing that can drift from src/provenrail/license.py, and a key that
// verifies in one place and not the other is indistinguishable from a forged key to the person
// holding it.
//
// Shape, byte-for-byte with the Python verifier:
//   prl_live_<base64url(payload_json)>.<base64url(ed25519_sig_over_the_b64payload_bytes)>
// The signature covers the base64url payload segment, so JSON key order never matters.
import * as ed from "npm:@noble/ed25519@2";

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Sign a licence token. Returns null (never throws) if the signing secret is missing or signing
 * fails, so whatever called this is never blocked by licence issuance: a subscription still
 * updates, a trial still records, the key is just absent.
 *
 * `exp` is unix seconds, or null for a non-expiring key. Callers set it; nothing here defaults
 * it, because a default expiry is exactly the kind of invisible decision that mints a perpetual
 * key by accident.
 */
export async function mintLicense(
  account: string,
  plan: string,
  exp: number | null,
): Promise<string | null> {
  const secretHex = (Deno.env.get("PROVENRAIL_LICENSE_SECRET") ?? "").trim();
  if (!secretHex) return null;
  try {
    const payload = JSON.stringify({ account, plan, iat: Math.floor(Date.now() / 1000), exp });
    const b64payload = b64url(new TextEncoder().encode(payload));
    const sig = await ed.signAsync(new TextEncoder().encode(b64payload), secretHex);
    return "prl_live_" + b64payload + "." + b64url(sig);
  } catch (_e) {
    return null;
  }
}
