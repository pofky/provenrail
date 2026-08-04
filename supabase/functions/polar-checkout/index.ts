// polar-checkout: an authenticated user starts a subscription.
// We never see card data; Polar is the Merchant of Record and handles EU VAT.
// verify_jwt is off so the browser CORS preflight passes; we validate the user
// in-code via getUser() and reject if there is no valid session.
import { createClient } from "jsr:@supabase/supabase-js@2";
import { Polar } from "npm:@polar-sh/sdk@0.34.3";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

// plan -> Polar product id. Team reads its function secret; Builder is pinned to the real product
// id (owner-confirmed) because the POLAR_PRODUCT_BUILDER secret points at a $1 "live test" SKU and
// project secrets cannot be edited through the deploy tooling. See SUPABASE_SETUP.md.
const BUILDER_PRODUCT_ID = "59860ba7-f978-4301-b598-70f85e188a36";
const PLAN_PRODUCT: Record<string, string | undefined> = {
  builder: BUILDER_PRODUCT_ID,
  team: Deno.env.get("POLAR_PRODUCT_TEAM"),
};

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

    const { plan } = await req.json().catch(() => ({}));
    const productId = PLAN_PRODUCT[String(plan)];
    if (!productId) return json({ error: "unknown_plan" }, 400);

    const polar = new Polar({
      accessToken: Deno.env.get("POLAR_ACCESS_TOKEN")!,
      server: (Deno.env.get("POLAR_MODE") ?? "production") as "production" | "sandbox",
    });

    const origin = Deno.env.get("SITE_URL") ?? "https://provenrail.com";
    const checkout = await polar.checkouts.create({
      products: [productId],
      successUrl: `${origin}/account?checkout=success`,
      // SDK field is `externalCustomerId` (serialized to external_customer_id). This links the
      // Polar customer to our Supabase user so the portal's externalCustomerId fallback resolves
      // and Polar dedupes the customer across checkouts. The webhook also reads metadata.user_id
      // as a backstop, but the external id is the canonical link.
      externalCustomerId: user.id,
      customerEmail: user.email ?? undefined,
      metadata: { user_id: user.id, plan: String(plan) },
    });
    return json({ url: checkout.url }, 200);
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
