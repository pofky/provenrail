// Mint a receipt exactly the way supabase/functions/anchor/index.ts does, so the Python
// verifier can be held to the same bytes. Reads {seed, pub, root} as JSON on argv[2] and prints
// the receipt as JSON.
//
// This duplicates the signing lines from the edge function on purpose: the function itself
// cannot be imported here because it calls Deno.serve at module scope and expects Supabase
// environment. The test that uses this file also greps the real function to prove the payload
// format has not drifted apart from this copy.
const { seed, pub, root } = JSON.parse(process.argv[2]);

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const PKCS8_ED25519_PREFIX = unhex("302e020100300506032b657004220420");

function utcNow() {
  const iso = new Date().toISOString();
  return iso.slice(0, -1) + "000Z";
}

const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
pkcs8.set(PKCS8_ED25519_PREFIX, 0);
pkcs8.set(unhex(seed), PKCS8_ED25519_PREFIX.length);

const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
const gen_time = utcNow();
const sig = await crypto.subtle.sign(
  { name: "Ed25519" },
  key,
  new TextEncoder().encode(`${root}|${gen_time}`),
);

console.log(JSON.stringify({
  kind: "local",
  merkle_root: root,
  gen_time,
  token_b64: null,
  signature: hex(sig),
  anchor_pubkey: pub,
  tsa_url: null,
}));
