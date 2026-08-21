// Who is asking, and whether their plan may anchor.
//
// This lives beside the handler rather than inside it so the decision can be tested directly.
// The free trial anchor is a rule about money and abuse, not about cryptography, and a rule of
// that kind is exactly the sort that is asserted in marketing copy and never exercised in a
// test until someone finds the hole.
import { verifyLicense } from "./license.js";

/** Hex for a digest. Shared with the handler, which hashes anchor ids and roots the same way. */
export function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The license key already says. It is Ed25519-signed, carries the account and the plan, and is
// minted by the Polar webhook the moment a subscription activates, so paying for the plan is the
// entire provisioning step: nothing to issue by hand, nothing to email, and no table that can
// disagree with what the customer actually bought.
// Overridable only so the whole authentication path can be exercised end to end against a test
// issuer, which is the same reason verify_license() in Python takes a public_key_hex argument.
// It is not a deployment knob: anyone able to set it already controls the process, and the
// default is the key every issued license was signed with.
const LICENSE_PUBLIC_KEY = (Deno.env.get("LICENSE_PUBLIC_KEY") ||
  "9ced1248464c8f884d4ff445b49e83089549505e5a49c01e8f33182f02c2ca73").trim();

// Hosted anchoring is a paid feature. Free plans run the sink and anchor against a server they
// run themselves; the whole point of the paid tier is having an independent party hold the root.
const ANCHOR_PLANS = new Set(["builder", "team", "enterprise"]);

// ...with one exception, deliberate: a free account may take exactly ONE anchor, ever. Until
// this existed, the only feature worth paying for was also the only feature nobody could try,
// so the argument for it had to be made in prose on a pricing page instead of by a receipt in
// the customer's own hands. The limit is a count of rows this service already writes, so there
// is no allowance to meter and no counter to reset, and a second free anchor costs a second
// verified email rather than a second request.
const FREE_TRIAL_ANCHORS = 1;

export type Resolved = { error?: string; status?: number; acct?: { account_id: string; active: boolean } };

// `db` is untyped on purpose. supabase-js infers its row types from generated database types,
// and without those every table resolves to `never`, so naming the client type here turns every
// real column into a compile error. There are no generated types for this project and adding
// them to describe two tables would be more machinery than the tables are worth.
// deno-lint-ignore no-explicit-any
export async function resolveAccount(db: any, key: string): Promise<Resolved> {
  const lic = await verifyLicense(key, LICENSE_PUBLIC_KEY, Math.floor(Date.now() / 1000));
  if (lic.valid) {
    const paidPlan = ANCHOR_PLANS.has(String(lic.plan));
    const account_id = String(lic.account || "");
    if (!account_id) return { error: "this license names no account", status: 401 };
    if (!paidPlan) {
      // The free trial anchor. Counted from the anchors themselves, so the check cannot
      // disagree with what was actually issued, and a failed or refused push never burns it.
      const { count, error } = await db
        .from("external_anchors")
        .select("anchor_id", { count: "exact", head: true })
        .eq("account_id", account_id);
      // A count that did not run is not a count of zero. Failing closed here costs a trial
      // user one retry; failing open would hand out unlimited free anchors the first time
      // this query breaks.
      if (error) return { error: "could not check the free anchor allowance", status: 503 };
      if ((count ?? 0) >= FREE_TRIAL_ANCHORS) {
        // Naming the plan matters. "Invalid key" sends someone with a real, working key to
        // check for a typo that is not there, when what happened is that their tier ran out.
        return {
          error: "your one free anchor has been used. A paid plan anchors without limit: " +
                 "https://provenrail.com/pricing",
          status: 403,
        };
      }
    }
    // First anchor from a new customer creates their row. api_key_hash is not a hash here and
    // deliberately cannot be one: license holders authenticate by signature, never by lookup, and
    // a value that is not 64 hex characters can never collide with a manually issued key.
    await db.from("anchor_accounts").upsert(
      { account_id, api_key_hash: `license:${account_id}`, label: `plan:${lic.plan}`, active: true },
      { onConflict: "account_id", ignoreDuplicates: true });
    return { acct: { account_id, active: true } };
  }
  if (lic.reason === "license expired") {
    return { error: "this license has expired; renew it to keep anchoring", status: 403 };
  }

  // A key issued by hand, which is how the service is exercised and how access is granted
  // outside Polar. Stored hashed, so a leaked database does not leak keys.
  const keyHash = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  const { data: acct } = await db
    .from("anchor_accounts")
    .select("account_id, active")
    .eq("api_key_hash", keyHash)
    .maybeSingle();
  if (!acct || !acct.active) return { error: "invalid API key", status: 401 };
  return { acct };
}
