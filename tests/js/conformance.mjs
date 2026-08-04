// Conformance harness: run the JS verifier against fixtures produced by the Python side and
// check the verdict (and key finding codes) match what Python's fr verify produced. Invoked
// by tests/test_js_verifier.py with a manifest path. Exits non-zero on any mismatch.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { verifyBundle } from "../../web/verify.js";

const manifestPath = process.argv[2];
const dir = dirname(manifestPath);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

let failures = 0;
for (const t of manifest) {
  const bundle = JSON.parse(readFileSync(join(dir, t.bundle), "utf8"));
  const pin = t.pin ? JSON.parse(readFileSync(join(dir, t.pin), "utf8")) : null;
  const opts = {
    tlogLogKey: t.tlog_log_key || null,
    witnessPubkeys: t.witness_pubkeys || {},
    nowUtc: t.now_utc || null,
    maxCosigAgeDays: t.max_cosig_age_days ?? 30,
    auditTrail: t.audit_trail || false,
    openings: t.openings || null,
    bitcoinHeaders: t.bitcoin_headers || null,
  };
  const rep = await verifyBundle(bundle, pin, opts);
  const codes = new Set(rep.findings.map(f => f.code));
  let ok = rep.ok === t.expect_ok;
  const missing = (t.codes || []).filter(c => !codes.has(c));
  if (missing.length) ok = false;
  const resultBad = t.expect_result && rep.result !== t.expect_result;
  if (resultBad) ok = false;
  console.log(`${ok ? "PASS" : "FAIL"} ${t.name} (ok=${rep.ok} expect=${t.expect_ok}${missing.length ? " missing=" + missing.join(",") : ""}${resultBad ? ` result=${rep.result} expect_result=${t.expect_result}` : ""})`);
  if (!ok) { failures++; console.log("  findings:", JSON.stringify(rep.findings)); }
}
process.exit(failures ? 1 : 0);
