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
import { claimTrial } from "./claim.ts";

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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  try {
    const asUser = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
    );
    const { data: { user }, error } = await asUser.auth.getUser();
    if (error || !user) return json({ error: "unauthorized" }, 401);

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const { data: profile } = await admin.from("profiles")
      .select("plan, license_key").eq("id", user.id).maybeSingle();

    const result = await claimTrial(
      user.id,
      profile,
      Math.floor(Date.now() / 1000),
      async (key: string) => {
        const { error: writeError } = await admin.from("profiles")
          .update({ license_key: key }).eq("id", user.id);
        return { ok: !writeError };
      },
    );
    return json(result.body, result.status);
  } catch (_e) {
    return json({ error: "unexpected" }, 500);
  }
});
