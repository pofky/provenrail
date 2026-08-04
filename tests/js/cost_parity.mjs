// Cost-estimation parity: the JS verifier's price table and arithmetic must agree with
// pricing.py to the cent. A divergence here would make one verifier accuse a clean run of
// not enforcing its own spend cap, which is worse than having no cap at all.
//
// The estimator is internal to web/verify.js (nothing outside the policy replay should be
// pricing anything), so this harness slices it out of the source and imports that slice
// rather than widening the module's public surface for a test.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "..", "web", "verify.js"), "utf8");
const start = src.indexOf("const JS_PRICES");
const end = src.indexOf("function policyDecide");
if (start < 0 || end < 0) { console.log("FAIL could not locate the estimator in web/verify.js"); process.exit(1); }
const mod = await import("data:text/javascript," + encodeURIComponent(src.slice(start, end) + "\nexport {estimateCost};"));

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
let bad = 0;
for (const c of cases) {
  const js = mod.estimateCost(c.model, c.usage);
  if (Math.abs(js - c.py) > 1e-9) {
    bad++;
    console.log(`FAIL ${c.model} ${JSON.stringify(c.usage)} python=${c.py} js=${js}`);
  }
}
console.log(bad ? `${bad} mismatches` : `PASS all ${cases.length} cost cases agree`);
process.exit(bad ? 1 : 0);
