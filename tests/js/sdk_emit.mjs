// Record a session with the JavaScript SDK and print the signed records as JSON.
//
// Used by tests/test_js_sdk.py to prove cross-language compatibility: the records this emits are
// ingested by the Python sink and must verify under BOTH the Python verifier and web/verify.js.
// A collector transport captures records instead of sending them over the network, so the test is
// deterministic and offline. The stream id is passed in so it matches the Python-provisioned stream
// (stream_id is part of the signed content).

import { record } from "../../sdk-js/src/index.js";

const streamId = process.argv[2];
if (!streamId) {
  process.stderr.write("usage: sdk_emit.mjs <stream_id>\n");
  process.exit(2);
}

const collected = [];
const transport = async (records) => { collected.push(...records); };

await record("demo-agent", async (pr) => {
  await pr.recordModelCall(
    "openai", "gpt-5",
    { prompt: "summarize the contract" },
    { text: "summary: ok" },
    { usage: { input: "1280", output: "210" } },
  );
  await pr.recordToolCall("web_search", { q: "provenrail" }, { hits: 3 });
  await pr.recordDecision("answer grounded; returning", { confidence: "high" });
  await pr.recordHumanOversight("approved", { approver: "auditor@example.com" });
}, { transport, streamId });

process.stdout.write(JSON.stringify(collected));
