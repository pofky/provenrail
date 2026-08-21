// trial-license: a signed-in visitor claims the one free anchor.
//
// Why this exists. The only thing Provenrail sells that a self-hoster cannot manufacture is an
// independent timestamp, and until 2026-08-21 it was entirely behind the paywall. So the free
// tier could demonstrate every part of the product EXCEPT the part worth paying for, and the
// moment that teaches the value (a receipt signed by someone who is not you) never happened
// before the credit card. One anchor, once, per verified email fixes that without giving away
// the recurring product.
//
// Why one, ever, and not a monthly allowance: an allowance is a free tier of the paid service,
// and it would have to be metered, rate-limited and defended. One row per account, checked
// against the anchors table the service already writes, needs no counter, no reset job and no
// new column. Someone determined to get a second free anchor has to create a second verified
// account, which costs them more than the anchor is worth.
//
// verify_jwt stays ON for this function (the default, and no block in supabase/config.toml),
// the same as polar-checkout and polar-portal: the page always sends the signed-in visitor's
// JWT. The claim is tied to a Supabase-verified identity on purpose, because the email
// verification IS the abuse control and no signature scheme here could replace it. Everything
// else about the key is identical to a paid one, so `pr activate` and the anchor service need
// no special case beyond the plan name.
import { createClient } from "jsr:@supabase/supabase-js@2";
import { mintLicense } from "../_shared/license-mint.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

// A trial key verifies for a year. It is not a subscription, so there is no renewal event to
// refresh it, and a key that expires in a month would silently rot for anyone who signed up and
// came back later. The single anchor it can buy is enforced by the anchor service counting rows,
// not by this expiry, so a long life costs nothing.
const TRIAL_SECONDS = 365 * 24 * 60 * 60;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const asUser = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: authHeader } } },
    );
    const { data: { user }, error } = await asUser.auth.getUser();
    if (error || !user) return json({ error: "unauthorized" }, 401);

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const { data: profile } = await admin.from("profiles")
      .select("plan, license_key").eq("id", user.id).maybeSingle();

    const plan = String(profile?.plan ?? "free");
    // A paying customer already holds a better key. Handing them a trial key here would
    // overwrite it in the same column the webhook owns, downgrading a subscription by accident.
    if (plan !== "free") {
      return json({ error: "your plan already includes anchoring", plan }, 409);
    }
    // Idempotent: clicking twice returns the same key rather than minting a second one. The
    // anchor count is what limits the free anchor, so re-issuing would not grant anything, but a
    // key that changes every click is a key nobody can trust they activated.
    if (profile?.license_key) {
      return json({ key: profile.license_key, plan: "free", reissued: true });
    }

    const exp = Math.floor(Date.now() / 1000) + TRIAL_SECONDS;
    const key = await mintLicense(user.id, "free", exp);
    if (!key) return json({ error: "key issuing is not configured" }, 503);

    const { error: writeError } = await admin.from("profiles")
      .update({ license_key: key }).eq("id", user.id);
    // Returning a key that was not stored would leave the account page showing nothing next
    // visit, and the visitor holding a key this service cannot recognise as already claimed.
    if (writeError) return json({ error: "could not record the trial key" }, 500);

    return json({ key, plan: "free", expires_at: exp });
  } catch (_e) {
    return json({ error: "unexpected" }, 500);
  }
});
