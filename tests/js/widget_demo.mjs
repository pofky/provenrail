// Regression guard for the homepage live-tamper widget (web/index.html #try-it).
// The widget loads web/demo-bundle.json, verifies it with web/verify.js, and on "flip one byte"
// mutates one server_record_hash and re-verifies. This script reproduces exactly that, so any
// drift in the static demo fixture, the demo witness key, or the verifier that would break the
// green-then-red demo fails in CI instead of shipping a broken hero. Exit non-zero on any break.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyBundle } from "../../web/verify.js";

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "web");
// Same options the widget and /verify pass for the hosted demo log.
const OPTS = { witnessPubkeys: { "demo-witness": "f5f6d366ff50408229e0e4717e342a38a2dbd6eb9c7f435ecac55319cf787876" } };

const good = JSON.parse(readFileSync(join(web, "demo-bundle.json"), "utf8"));
const r1 = await verifyBundle(good, good.__pin || null, OPTS);
if (!r1.ok) {
  console.error("FAIL: web/demo-bundle.json does not verify; the homepage widget would show an error, not VERIFIED.");
  console.error(JSON.stringify((r1.findings || []).slice(0, 4)));
  process.exit(1);
}

const bad = JSON.parse(JSON.stringify(good));
const rec = (bad.records || []).find(r => typeof r.server_record_hash === "string" && r.server_record_hash.length > 2);
if (!rec) {
  console.error("FAIL: no server_record_hash in the demo bundle to flip; widget tamper would be a no-op.");
  process.exit(1);
}
rec.server_record_hash = rec.server_record_hash.slice(0, -1) + (rec.server_record_hash.slice(-1) === "0" ? "1" : "0");
const r2 = await verifyBundle(bad, bad.__pin || null, OPTS);
if (r2.ok) {
  console.error("FAIL: a one-byte change still verified; the widget 'flip one byte' would not show TAMPERING DETECTED.");
  process.exit(1);
}

console.log(`OK widget demo: clean VERIFIED, one-byte tamper rejected with ${r2.findings.length} findings.`);
