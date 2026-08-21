// Claiming the free anchor writes to the same column the Polar webhook owns, so the failure this
// guards against is not "the trial does not work". It is a paying customer's licence key being
// quietly replaced by a free-plan one, discovered when their anchoring starts refusing a plan
// they are paying for.
//
// Run: deno test --allow-env tests/deno/trial_license_test.ts
import { assertEquals } from "jsr:@std/assert@1";
import * as ed from "npm:@noble/ed25519@2";

const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const seedHex = hexOf(crypto.getRandomValues(new Uint8Array(32)));
Deno.env.set("PROVENRAIL_LICENSE_SECRET", seedHex);
const pubHex = hexOf(await ed.getPublicKeyAsync(seedHex));

// Imported after the environment is set, for the same reason as anchor_gate_test.ts.
const { claimTrial, TRIAL_SECONDS } = await import(
  "../../supabase/functions/trial-license/claim.ts"
);
const { verifyLicense } = await import("../../supabase/functions/anchor/license.js");

const NOW = 1_800_000_000;
const stored: string[] = [];
const store = (key: string) => {
  stored.push(key);
  return Promise.resolve({ ok: true });
};

Deno.test("a free account with no key gets one, and it verifies as a free-plan key", async () => {
  stored.length = 0;
  const res = await claimTrial("user_1", { plan: "free", license_key: null }, NOW, store);
  assertEquals(res.status, 200);
  const key = String(res.body.key);
  assertEquals(stored, [key]);  // what was returned is what was written
  const lic = await verifyLicense(key, pubHex, NOW);
  assertEquals(lic.valid, true);
  assertEquals(lic.plan, "free");
  assertEquals(lic.account, "user_1");
  assertEquals(res.body.expires_at, NOW + TRIAL_SECONDS);
});

Deno.test("a subscriber is refused, so their paid key is never overwritten", async () => {
  stored.length = 0;
  const res = await claimTrial("user_2", { plan: "builder", license_key: "prl_live_paid" }, NOW,
    store);
  assertEquals(res.status, 409);
  assertEquals(stored, []);
  assertEquals(res.body.key, undefined);
});

Deno.test("a subscriber with no key yet is still refused", async () => {
  // The webhook mints their real key asynchronously. A trial key written into that gap would be
  // overwritten minutes later, or would overwrite the real one, depending on which landed last.
  stored.length = 0;
  const res = await claimTrial("user_3", { plan: "team", license_key: null }, NOW, store);
  assertEquals(res.status, 409);
  assertEquals(stored, []);
});

Deno.test("clicking twice returns the same key rather than minting another", async () => {
  stored.length = 0;
  const res = await claimTrial("user_4", { plan: "free", license_key: "prl_live_existing" }, NOW,
    store);
  assertEquals(res.status, 200);
  assertEquals(res.body.key, "prl_live_existing");
  assertEquals(res.body.reissued, true);
  assertEquals(stored, []);
});

Deno.test("a missing profile row is treated as a free account, not as a crash", async () => {
  stored.length = 0;
  const res = await claimTrial("user_5", null, NOW, store);
  assertEquals(res.status, 200);
  assertEquals(stored.length, 1);
});

Deno.test("a key that could not be stored is not handed out", async () => {
  const res = await claimTrial("user_6", { plan: "free", license_key: null }, NOW,
    () => Promise.resolve({ ok: false }));
  assertEquals(res.status, 500);
  assertEquals(res.body.key, undefined);
});

Deno.test("with no signing secret, nothing is issued and nothing is claimed", async () => {
  const real = Deno.env.get("PROVENRAIL_LICENSE_SECRET")!;
  Deno.env.delete("PROVENRAIL_LICENSE_SECRET");
  stored.length = 0;
  const res = await claimTrial("user_7", { plan: "free", license_key: null }, NOW, store);
  Deno.env.set("PROVENRAIL_LICENSE_SECRET", real);
  assertEquals(res.status, 503);
  assertEquals(stored, []);
});
