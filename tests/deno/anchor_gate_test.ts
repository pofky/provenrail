// The free trial anchor is a rule about money, and rules about money are the ones that get
// asserted on a pricing page and never exercised. This drives the real decision function from
// supabase/functions/anchor/account.ts against a stub database, so "one free anchor, ever" is a
// tested claim rather than a sentence.
//
// Run: deno test --allow-env tests/deno/anchor_gate_test.ts
import { assertEquals } from "jsr:@std/assert@1";
import * as ed from "npm:@noble/ed25519@2";

// A throwaway signing pair. The public half goes into LICENSE_PUBLIC_KEY so the gate verifies
// keys minted here and nothing else; the real production key never appears in a test.
//
// Both modules are imported DYNAMICALLY, after the environment is set: account.ts reads
// LICENSE_PUBLIC_KEY at module scope, so a static import would capture the production key and
// every licence minted here would fail to verify for a reason that looks like a gate bug.
const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const seedHex = hexOf(crypto.getRandomValues(new Uint8Array(32)));
Deno.env.set("PROVENRAIL_LICENSE_SECRET", seedHex);
Deno.env.set("LICENSE_PUBLIC_KEY", hexOf(await ed.getPublicKeyAsync(seedHex)));

const { mintLicense } = await import("../../supabase/functions/_shared/license-mint.ts");
const { resolveAccount } = await import("../../supabase/functions/anchor/account.ts");

/** A database that answers exactly two questions: how many anchors an account has, and whether
 * the upsert of its account row succeeded. Nothing else in resolveAccount touches it. */
function stubDb(opts: { count?: number; countError?: boolean }) {
  const upserts: unknown[] = [];
  return {
    upserts,
    from(_table: string) {
      return {
        select(_cols: string, _o?: unknown) {
          return {
            eq(_col: string, _val: string) {
              return opts.countError
                ? { count: null, error: { message: "boom" } }
                : { count: opts.count ?? 0, error: null };
            },
          };
        },
        upsert(row: unknown, _o?: unknown) {
          upserts.push(row);
          return { error: null };
        },
      };
    },
  };
}

const YEAR = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60;

Deno.test("a free account with no anchors gets its one trial anchor", async () => {
  const key = await mintLicense("acct_trial", "free", YEAR);
  const res = await resolveAccount(stubDb({ count: 0 }), key!);
  assertEquals(res.error, undefined);
  assertEquals(res.acct?.account_id, "acct_trial");
});

Deno.test("a free account that already anchored once is refused, and told why", async () => {
  const key = await mintLicense("acct_spent", "free", YEAR);
  const res = await resolveAccount(stubDb({ count: 1 }), key!);
  assertEquals(res.status, 403);
  // The refusal must name the spent allowance, not the key. Someone holding a working key who
  // is told "invalid API key" goes looking for a typo that is not there.
  assertEquals(res.error?.includes("free anchor"), true);
  assertEquals(res.error?.includes("pricing"), true);
});

Deno.test("a count that failed to run is not treated as zero", async () => {
  // Failing open here would hand out unlimited free anchors the first time this query breaks,
  // which is the failure nobody would notice until the bill or the abuse arrived.
  const key = await mintLicense("acct_dberror", "free", YEAR);
  const res = await resolveAccount(stubDb({ countError: true }), key!);
  assertEquals(res.status, 503);
});

Deno.test("a paid plan is never counted against the trial allowance", async () => {
  // The stub reports an exhausted allowance. A builder key must still be admitted, or a paying
  // customer would be cut off after their first anchor.
  const key = await mintLicense("acct_paid", "builder", YEAR);
  const res = await resolveAccount(stubDb({ count: 99 }), key!);
  assertEquals(res.error, undefined);
  assertEquals(res.acct?.account_id, "acct_paid");
});

Deno.test("an expired key is refused with renewal advice, whatever its plan", async () => {
  const key = await mintLicense("acct_old", "builder", Math.floor(Date.now() / 1000) - 60);
  const res = await resolveAccount(stubDb({ count: 0 }), key!);
  assertEquals(res.status, 403);
  assertEquals(res.error?.includes("expired"), true);
});

Deno.test("a licence signed by another key never resolves to an account", async () => {
  const otherSeed = crypto.getRandomValues(new Uint8Array(32));
  const otherHex = [...otherSeed].map((b) => b.toString(16).padStart(2, "0")).join("");
  const real = Deno.env.get("PROVENRAIL_LICENSE_SECRET")!;
  Deno.env.set("PROVENRAIL_LICENSE_SECRET", otherHex);
  const forged = await mintLicense("acct_forged", "team", YEAR);
  Deno.env.set("PROVENRAIL_LICENSE_SECRET", real);
  // It falls through to the manually-issued-key path, finds no row, and is refused there.
  const res = await resolveAccount(
    { from: () => ({ select: () => ({ eq: () => ({ maybeSingle: () => ({ data: null }) }) }) }) },
    forged!,
  );
  assertEquals(res.status, 401);
});
