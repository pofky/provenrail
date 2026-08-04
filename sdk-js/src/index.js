// Provenrail TypeScript / Node SDK: the front door.
//
//   import { record } from "provenrail";
//
//   await record("billing-agent", async (pr) => {
//     // your agent runs; record model and tool calls (manually or via instrument*)
//     await pr.recordModelCall("openai", "gpt-5", { prompt }, { text });
//   });
//
// Connection comes from, in priority order: explicit options, configure(), then the
// PROVENRAIL_URL / PROVENRAIL_WRITE_TOKEN / PROVENRAIL_STREAM_ID / PROVENRAIL_ACCOUNT_KEY
// environment variables. With an endpoint but no stream, a stream is auto-provisioned.

import { Recorder } from "./recorder.js";
import { MODEL_CALL } from "./chain.js";

export { Recorder } from "./recorder.js";
export { SigningKey } from "./crypto.js";
export { canon, hashValue, CanonicalError } from "./canonical.js";

const _global = {};

function env(name) {
  const p = globalThis.process;
  return (p && p.env && p.env[name]) || undefined;
}

export function configure(opts = {}) {
  Object.assign(_global, opts);
}

function resolve(opts = {}) {
  return {
    endpoint: opts.endpoint ?? _global.endpoint ?? env("PROVENRAIL_URL"),
    writeToken: opts.writeToken ?? _global.writeToken ?? env("PROVENRAIL_WRITE_TOKEN"),
    streamId: opts.streamId ?? _global.streamId ?? env("PROVENRAIL_STREAM_ID"),
    accountKey: opts.accountKey ?? _global.accountKey ?? env("PROVENRAIL_ACCOUNT_KEY"),
    captureContent: opts.captureContent ?? _global.captureContent ?? false,
    transport: opts.transport ?? _global.transport,
  };
}

export async function provisionStream(endpoint, { label, accountKey } = {}) {
  const base = (endpoint || "").replace(/\/+$/, "");
  const headers = { "Content-Type": "application/json" };
  if (accountKey) headers.Authorization = `Bearer ${accountKey}`;
  const resp = await fetch(base + "/v1/streams", {
    method: "POST", headers, body: JSON.stringify({ label }),
  });
  if (!resp.ok) throw new Error(`provision failed ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

export async function makeRecorder(agent, opts = {}) {
  const cfg = resolve(opts);
  // A test/offline transport needs no endpoint; otherwise an endpoint is required.
  if (!cfg.transport && !cfg.endpoint) {
    throw new Error(
      "no Provenrail endpoint configured. Set PROVENRAIL_URL, pass { endpoint }, or call configure().",
    );
  }
  let { streamId, writeToken } = cfg;
  if (!cfg.transport && !(streamId && writeToken)) {
    const prov = await provisionStream(cfg.endpoint, { label: agent, accountKey: cfg.accountKey });
    streamId = prov.stream_id;
    writeToken = prov.write_token;
  }
  return Recorder.create({
    endpoint: cfg.endpoint,
    writeToken,
    streamId: streamId || "offline",
    transport: cfg.transport,
    captureContent: cfg.captureContent,
  });
}

// One-line recorded session. Provisions, opens, runs fn, seals, all off-box.
export async function record(agent, fn, opts = {}) {
  const recorder = await makeRecorder(agent, opts);
  return recorder.session({ agent, ...(opts.meta || {}) }, fn);
}

// ---- auto-instrumentation for the OpenAI and Anthropic JS clients ----
// Wrap the call method so every model call is recorded with no per-call glue. Best-effort and
// defensive: instrumentation never breaks the underlying call.

function _usageFrom(resp) {
  const u = resp && resp.usage;
  if (!u) return undefined;
  // Normalize the common shapes to string token counts (canonical-safe, exact).
  const input = u.input_tokens ?? u.prompt_tokens ?? u.input;
  const output = u.output_tokens ?? u.completion_tokens ?? u.output;
  const out = {};
  if (input !== undefined) out.input = String(input);
  if (output !== undefined) out.output = String(output);
  return Object.keys(out).length ? out : undefined;
}

export function instrumentOpenAI(client, recorder) {
  const completions = client?.chat?.completions;
  if (!completions || typeof completions.create !== "function") {
    throw new Error("instrumentOpenAI: not an OpenAI client (missing chat.completions.create)");
  }
  const original = completions.create.bind(completions);
  completions.create = async (params, ...rest) => {
    const resp = await original(params, ...rest);
    try {
      await recorder.recordModelCall("openai", params?.model ?? "unknown", params,
        resp, { usage: _usageFrom(resp) });
    } catch { /* recording must never break the call */ }
    return resp;
  };
  return client;
}

export function instrumentAnthropic(client, recorder) {
  const messages = client?.messages;
  if (!messages || typeof messages.create !== "function") {
    throw new Error("instrumentAnthropic: not an Anthropic client (missing messages.create)");
  }
  const original = messages.create.bind(messages);
  messages.create = async (params, ...rest) => {
    const resp = await original(params, ...rest);
    try {
      await recorder.recordModelCall("anthropic", params?.model ?? "unknown", params,
        resp, { usage: _usageFrom(resp) });
    } catch { /* never break the call */ }
    return resp;
  };
  return client;
}

export { MODEL_CALL };
