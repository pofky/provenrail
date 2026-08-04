// polar-prices: public, read-only. Returns OUR real Polar products with their live prices so the
// pricing UI can never drift from what Polar will actually charge at checkout. We return a plan
// only when its mapped Polar product (POLAR_PRODUCT_BUILDER / POLAR_PRODUCT_TEAM) exists, is not
// archived, and carries a non-archived FIXED recurring price ("only good products"). Anything
// missing, archived, or mispriced is omitted, so the page falls back to its static copy rather
// than showing a broken or wrong number.
// verify_jwt is off: prices are public marketing data and no user data is touched.
import { Polar } from "npm:@polar-sh/sdk@0.34.3";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });

// Builder is pinned to the real product id (owner-confirmed); the POLAR_PRODUCT_BUILDER secret
// points at a $1 "live test" SKU and project secrets cannot be edited through the deploy tooling.
const BUILDER_PRODUCT_ID = "59860ba7-f978-4301-b598-70f85e188a36";
const PLAN_PRODUCT: Record<string, string | undefined> = {
  builder: BUILDER_PRODUCT_ID,
  team: Deno.env.get("POLAR_PRODUCT_TEAM"),
};

const SYMBOL: Record<string, string> = { usd: "$", eur: "€", gbp: "£" };
const INTERVAL_SHORT: Record<string, string> = { month: "mo", year: "yr", week: "wk", day: "day" };

function display(amountCents: number, currency: string, interval: string | null): string {
  const sym = SYMBOL[currency.toLowerCase()] ?? (currency.toUpperCase() + " ");
  // Whole-dollar amounts render without cents (29, not 29.00); fractional keep two places.
  const major = amountCents / 100;
  const num = Number.isInteger(major) ? String(major) : major.toFixed(2);
  const per = interval ? "/" + (INTERVAL_SHORT[interval] ?? interval) : "";
  return sym + num + per;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const polar = new Polar({
      accessToken: Deno.env.get("POLAR_ACCESS_TOKEN")!,
      server: (Deno.env.get("POLAR_MODE") ?? "production") as "production" | "sandbox",
    });

    // deno-lint-ignore no-explicit-any
    const products: Record<string, any> = {};
    for (const [plan, productId] of Object.entries(PLAN_PRODUCT)) {
      if (!productId) continue;
      try {
        const p = await polar.products.get({ id: productId });
        if (!p || p.isArchived) continue;
        // First live, fixed, recurring price. We sell monthly recurring fixed prices only.
        const price = (p.prices ?? []).find((pr) => {
          // deno-lint-ignore no-explicit-any
          const x = pr as any;
          return x && x.amountType === "fixed" && x.isArchived === false
            && typeof x.priceAmount === "number";
        });
        if (!price) continue;
        // deno-lint-ignore no-explicit-any
        const x = price as any;
        const interval: string | null = x.recurringInterval ?? p.recurringInterval ?? null;
        products[plan] = {
          name: p.name,
          amount: x.priceAmount, // integer minor units (cents)
          currency: String(x.priceCurrency ?? "usd"),
          interval,
          display: display(x.priceAmount, String(x.priceCurrency ?? "usd"), interval),
        };
      } catch (_e) {
        // A single missing/unreadable product must not blank the whole response; skip it.
        continue;
      }
    }
    return json({ products });
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
