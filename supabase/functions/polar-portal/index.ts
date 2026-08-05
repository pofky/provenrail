// polar-portal: an authenticated subscriber opens Polar's customer portal to
// update payment method, see invoices, or cancel.
// verify_jwt is off so the browser CORS preflight passes; we validate the user
// in-code via getUser().
import { createClient } from "jsr:@supabase/supabase-js@2";
import { Polar } from "npm:@polar-sh/sdk@0.34.3";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
    );
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) return json({ error: "unauthorized" }, 401);

    const polar = new Polar({
      accessToken: Deno.env.get("POLAR_ACCESS_TOKEN")!,
      server: (Deno.env.get("POLAR_MODE") ?? "production") as "production" | "sandbox",
    });

    // customerSessions.create takes a union of `customerId` OR `externalCustomerId`. Both the
    // checkout and the session APIs use `externalCustomerId` in this SDK (it serializes to
    // external_customer_id). Prefer the Polar customer id the webhook stored; fall back to our
    // user id, which checkout set as the customer's external id.
    const { data: profile } = await supabase
      .from("profiles").select("polar_customer_id").eq("id", user.id).maybeSingle();
    const params = profile?.polar_customer_id
      ? { customerId: profile.polar_customer_id as string }
      : { externalCustomerId: user.id };
    const session = await polar.customerSessions.create(params);
    // SDK returns camelCase; fall back across shapes just in case.
    // deno-lint-ignore no-explicit-any
    const s = session as any;
    const url = s.customerPortalUrl ?? s.customer_portal_url ?? null;
    if (!url) return json({ error: "We could not open the billing portal just now. Please try " +
                                   "again, or email support@provenrail.com." }, 502);
    return json({ url }, 200);
  } catch (e) {
    // Same reasoning as polar-checkout: never put Polar's raw validation JSON in front of a
    // paying customer. "Customer does not exist" in particular is our plumbing, not their
    // problem, and it is what they would see if the webhook had not linked them yet.
    console.error("polar-portal failed:", e);
    return json({ error: "We could not open the billing portal just now. Your subscription is " +
                         "unaffected. Please try again, or email support@provenrail.com." }, 502);
  }
});
