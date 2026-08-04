# Provenrail for TypeScript and Node

The verifiable audit trail for AI agents, for the TypeScript ecosystem. Capture every model and
tool call your agent makes, hash-chain and sign it off-box, and verify it with the **same**
open-source verifiers as the Python SDK. A run recorded in TypeScript is byte-for-byte compatible
with one recorded in Python: the same sink accepts it and the same two verifiers (`pr verify` and
the in-browser `verify.js`) prove it, trusting neither the agent nor the vendor.

Observability you can take to court, now in your TypeScript stack. Drop-in capture for the OpenAI
and Anthropic JS clients; record any other provider or framework (the Vercel AI SDK, Mastra,
LangChain.js, or a custom loop) with one line.

## Install

```
npm install provenrail
```

Requires Node 20+ (uses WebCrypto Ed25519). Works in modern browsers too.

## Quickstart

```ts
import { record } from "provenrail";

// PROVENRAIL_URL (and an account key, or a stream + write token) come from the environment,
// or pass them explicitly. With just an endpoint, a stream is auto-provisioned.
await record("billing-agent", async (pr) => {
  const out = await callTheModel(prompt);
  await pr.recordModelCall("openai", "gpt-5", { prompt }, out, {
    usage: { input: out.usage?.prompt_tokens, output: out.usage?.completion_tokens },
  });
  await pr.recordToolCall("charge", { amount: 340 }, { ok: true });
  await pr.recordDecision("charge approved by policy");
});
```

That session is now signed, hash-chained, pushed off-box, and independently verifiable.

## Auto-instrument the OpenAI / Anthropic clients

```ts
import OpenAI from "openai";
import { makeRecorder, instrumentOpenAI } from "provenrail";

const pr = await makeRecorder("support-agent");
const openai = instrumentOpenAI(new OpenAI(), pr);

await pr.session({ agent: "support-agent" }, async () => {
  // every openai.chat.completions.create call is now recorded automatically
  await openai.chat.completions.create({ model: "gpt-5", messages });
});
```

## What it records, and what it does not

By default the SDK is **hash-not-content**: inputs and outputs are SHA-256 hashed, not stored, so
PII stays out of the sink. Pass `{ captureContent: true }` to store cleartext.

Honest scope, identical to the Python SDK: this runs inside the agent process, so a hostile agent
can refuse to call it. It cannot make capture complete. Its job is to make whatever IS captured
tamper-evident and independently verifiable the moment it reaches the off-box sink.

## Verify a run

Any run recorded with this SDK verifies with the standard tools, trusting neither the agent nor the
sink:

```
pip install provenrail
pr verify bundle.json
```

or in the browser at `/verify`. Both verifiers run the same algorithm and are tested against a
frozen public conformance-vector suite, and against runs produced by THIS SDK
(`tests/test_js_sdk.py`).

## License

MIT.
