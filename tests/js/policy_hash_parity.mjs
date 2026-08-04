// Policy-hash parity: the browser verifier must hash the SAME bytes the SDK committed, which
// are the bytes of Policy.to_dict(), not of the raw dict carried in the bundle. When these
// diverge the two implementations reach OPPOSITE verdicts on tampering for a genuine file:
// the CLI says verified, the browser says tampered, and the product's central claim that an
// independent implementation reaches the same conclusion is simply false.
import { readFileSync } from "node:fs";
import { hashValue, policyCanonicalForm } from "../../web/verify.js";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
let bad = 0;
for (const c of cases) {
  const js = await hashValue(policyCanonicalForm(c.policy));
  if (js !== c.py) {
    bad++;
    console.log(`FAIL ${JSON.stringify(c.policy)}\n  python=${c.py}\n  js    =${js}`);
  }
}
console.log(bad ? `${bad} mismatches` : `PASS all ${cases.length} policy hashes agree`);
process.exit(bad ? 1 : 0);
