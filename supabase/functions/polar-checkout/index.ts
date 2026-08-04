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

// plan -> Polar product id. BOTH plans resolve from secrets. Builder used to be pinned to a
// literal id here, from a period when POLAR_PRODUCT_BUILDER pointed at a $1 live-test SKU and the
// secret was believed uneditable. That id belonged to the OLD shared organization, so after the
// move to Provenrail's own org "Start Builder" would have created a checkout for a product that
// does not exist. Never hardcode a product id here again.
const PLAN_PRODUCT: Record<string, string | undefined> = {
  builder: Deno.env.get("POLAR_PRODUCT_BUILDER"),
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
