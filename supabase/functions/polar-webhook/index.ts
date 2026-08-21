// polar-webhook: Polar tells us when a subscription changes. We update the
// profile's plan/status and issue a license key on first activation.
// verify_jwt is OFF for this function: Polar signs with the webhook secret
// (Standard Webhooks), not a Supabase JWT. We validate that signature instead.
import { createClient } from "jsr:@supabase/supabase-js@2";
import { Webhook } from "npm:standardwebhooks@1";
import { mintLicense } from "../_shared/license-mint.ts";

// Licence minting lives in ../_shared/license-mint.ts, because trial-license issues keys too and
// two copies of a signing routine drift. `exp` (unix seconds, or null for non-expiring) bounds
// how long the offline key verifies. For a subscription we set it to the current period end plus
// a grace window, so a key from one month's payment is NOT perpetual: it expires unless a
// renewal webhook refreshes it.

// Grace added to the billing period end before an offline license key expires, so a slightly
// late renewal webhook never locks out a paying customer mid-cycle.
const LICENSE_GRACE_SECONDS = 7 * 24 * 60 * 60;

// Resolve the license expiry (unix seconds) from a subscription's current period end. Falls back
// to ~38 days from now when the field is absent or unparseable, so a missing period end can never
// silently mint a perpetual key.
function licenseExpiry(periodEndIso: unknown): number {
  const fallback = Math.floor(Date.now() / 1000) + 31 * 24 * 60 * 60 + LICENSE_GRACE_SECONDS;
  if (typeof periodEndIso !== "string") return fallback;
  const ms = Date.parse(periodEndIso);
  if (Number.isNaN(ms)) return fallback;
  return Math.floor(ms / 1000) + LICENSE_GRACE_SECONDS;
}

// Polar product id -> our plan name. Reverse of the checkout map. BOTH plans resolve from
// secrets. Builder used to be pinned to a literal id here, from a period when
// POLAR_PRODUCT_BUILDER pointed at a $1 live-test SKU and the secret was believed uneditable.
// That id belonged to the OLD shared organization, so after the move to Provenrail's own org it
// silently stopped recognizing Builder purchases: the webhook would ack with 202 and never
// provision the plan or mint a licence, with no error anywhere. Team was unaffected because it
// already read the secret. Never hardcode a product id here again.
const PRODUCT_PLAN: Record<string, string> = {};
const PLAN_IDS: Record<string, string | undefined> = {
  builder: Deno.env.get("POLAR_PRODUCT_BUILDER"),
  team: Deno.env.get("POLAR_PRODUCT_TEAM"),
};
for (const [plan, id] of Object.entries(PLAN_IDS)) {
  if (id) PRODUCT_PLAN[id] = plan;
}

const ACTIVE = new Set(["active", "trialing"]);

// deno-lint-ignore no-explicit-any
function pick(o: any, ...keys: string[]) {
  for (const k of keys) if (o && o[k] != null) return o[k];
  return null;
}

Deno.serve(async (req) => {
  const body = await req.text();
  const headers = Object.fromEntries(req.headers);
  // Verify the Standard Webhooks signature ourselves. Polar signs the `${id}.${ts}.${body}`
  // string with the RAW UTF-8 bytes of the webhook secret (including the polar_whs_ prefix),
  // verified empirically in sandbox against this same Polar org (see Rateven lib/polar.ts). The
  // standardwebhooks Webhook constructor base64-DECODES whatever string it is given to obtain the
  // HMAC key, so we pass btoa(secret): decode(encode(secret)) == the raw secret bytes. The result
  // is identical to the hand-rolled HMAC path. We deliberately do NOT use the SDK's validateEvent:
  // its strict Zod parse throws on any payload shape the pinned SDK version does not model exactly,
  // which would turn a legitimately signed event into a 500 and silently break billing as Polar
  // evolves its payloads. The signature + timestamp are the security boundary; we read the fields
  // we need defensively.
  // deno-lint-ignore no-explicit-any
  let event: any;
  try {
    const wh = new Webhook(btoa(Deno.env.get("POLAR_WEBHOOK_SECRET") ?? ""));
    event = wh.verify(body, headers);
  } catch (_e) {
    return new Response("", { status: 403 });
  }

  const type = String(event.type ?? "");
  if (type.startsWith("subscription.")) {
    const sub = event.data ?? {};
    const customer = sub.customer ?? {};
    const userId = pick(customer, "externalId", "external_id") ?? sub?.metadata?.user_id;

    if (userId) {
      const productId = pick(sub, "productId", "product_id") ?? sub?.product?.id;
      const recognized = Boolean(PRODUCT_PLAN[productId]);

      const admin = createClient(
        Deno.env.get("SUPABASE_URL")!,
        Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
      );

      // Defense-in-depth: a Polar organization fans every webhook event out to ALL of its
      // registered endpoints, so when projects share one org we also receive their
      // subscription events. Act ONLY on our own products; ignore anything else with no DB
      // write and no license. This also removes the old `?? "builder"` fallback, which would
      // otherwise have granted Builder for an unrecognized product (a free-plan leak).
      //
      // The exception that matters: an unrecognized product can also be OUR OWN retired one.
      // Ignoring those events strands the row forever, because no future event can ever
      // downgrade it, so a cancelled subscription keeps a valid license indefinitely (this
      // actually happened, see the 2026-08-04 cleanup). Ownership of the subscription id is
      // the sound discriminator: another project's subscription id never lands on our row.
      // An owned-but-unrecognized subscription is allowed to take the DOWNGRADE path only,
      // never to grant a plan, so the isolation guarantee is unchanged.
      const status = String(sub.status ?? "");
      // During Polar's dunning retry window a subscription is `past_due` but still alive, so we
      // keep the paid plan: a transient card decline must not instantly revoke a paying customer.
      // Only an explicit revoke, or a status outside {active, trialing, past_due}, downgrades to
      // free. When the retry succeeds Polar sends a fresh active event that refreshes the key.
      const alive = (ACTIVE.has(status) || status === "past_due")
        && type !== "subscription.revoked";

      if (!recognized) {
        // A live subscription to a product we cannot price is left completely alone: we have no
        // idea which plan it should grant, and revoking a customer who is still paying would be
        // far worse than a stale row. Only an ENDING subscription is acted on, and only after
        // confirming it is ours.
        if (alive) return new Response("", { status: 202 });
        const { data: owner } = await admin.from("profiles")
          .select("id").eq("id", userId).eq("polar_subscription_id", sub.id ?? "").maybeSingle();
        if (!owner) return new Response("", { status: 202 });
      }

      const entitled = recognized && alive;
      const periodEnd = pick(sub, "currentPeriodEnd", "current_period_end");
      const plan = entitled ? PRODUCT_PLAN[productId] : "free";
      // deno-lint-ignore no-explicit-any
      const patch: Record<string, any> = {
        plan,
        subscription_status: status,
        polar_customer_id: pick(customer, "id") ?? pick(sub, "customerId", "customer_id"),
        polar_subscription_id: sub.id ?? null,
        current_period_end: periodEnd,
      };

      // Issue (or refresh) the signed license so the displayed key always encodes the current
      // plan and a period-bounded expiry. The key carries the tier, so on an upgrade the customer
      // re-activates with the new key shown on their account page. On revoke we mint nothing and
      // the last key expires at period end + grace, so a one-month payment is not a perpetual
      // license. We also clear the stored key on downgrade so the account page stops showing it.
      if (entitled) {
        const key = await mintLicense(userId, plan, licenseExpiry(periodEnd));
        if (key) patch.license_key = key;
      } else {
        patch.license_key = null;
      }
      await admin.from("profiles").update(patch).eq("id", userId);
    }
  }

  return new Response("", { status: 202 });
});
