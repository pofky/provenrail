// The Recorder: opens a signed session and pushes records off-box (mirrors sdk.py FlightRecorder).
//
// Privacy default is store-hash-not-content: inputs and outputs are SHA-256 hashed, not stored,
// unless captureContent is true. This keeps PII out of the sink by default. Records are flushed
// to the sink as they are emitted, so whatever IS recorded becomes immutable off-box quickly.
//
// Honest limitation, identical to the Python SDK: this runs inside the agent process, so a hostile
// agent can refuse to call it. It cannot make capture complete; it makes what is captured verifiable.

import { hashValue } from "./canonical.js";
import {
  Chain, DATA_ACCESS, DECISION, HEARTBEAT, HUMAN_OVERSIGHT, MCP_CALL, MODEL_CALL, TOOL_CALL,
} from "./chain.js";
import { SigningKey } from "./crypto.js";

function networkTransport(endpoint, writeToken) {
  const base = (endpoint || "").replace(/\/+$/, "");
  return async (records) => {
    const resp = await fetch(base + "/v1/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${writeToken}` },
      body: JSON.stringify({ records }),
    });
    if (!resp.ok) throw new Error(`ingest failed ${resp.status}: ${await resp.text()}`);
    return resp.json();
  };
}

export class Recorder {
  constructor({ endpoint, writeToken, streamId, key, transport, captureContent = false } = {}) {
    if (!streamId) throw new Error("Recorder requires a streamId");
    this.streamId = streamId;
    this.key = key;
    this.captureContent = captureContent;
    // transport is async (records[]) => any; default posts to the sink, injectable for tests.
    this._transport = transport || networkTransport(endpoint, writeToken);
    this.records = []; // every emitted record, also kept locally for inspection/offline use
    this._chain = null;
  }

  static async create(opts) {
    const r = new Recorder(opts);
    r.key = r.key || await SigningKey.generate();
    r._chain = new Chain(r.streamId, r.key);
    return r;
  }

  async _content(label, value) {
    const d = { hash: await hashValue(value) };
    if (this.captureContent) d.content = value;
    return { [label]: d };
  }

  async _push(rec) {
    this.records.push(rec);
    await this._transport([rec]);
    return rec;
  }

  async start(meta) {
    const rec = await this._chain.start(meta);
    return this._push(rec);
  }

  async seal(outcome = "success", trigger = "normal") {
    const rec = await this._chain.seal(outcome, trigger);
    return this._push(rec);
  }

  // Open a session, run fn, and always seal (even on throw, with a failure outcome).
  async session(meta, fn) {
    await this.start(meta);
    try {
      const result = await fn(this);
      await this.seal("success", "normal");
      return result;
    } catch (e) {
      await this.seal("failure", "exception");
      throw e;
    }
  }

  async record(actionType, payload) {
    const rec = await this._chain.append(actionType, payload);
    return this._push(rec);
  }

  async recordModelCall(provider, model, request, response, { usage, ...extra } = {}) {
    const payload = { provider, model };
    Object.assign(payload, await this._content("request", request));
    Object.assign(payload, await this._content("response", response));
    if (usage) payload.usage = usage;
    if (Object.keys(extra).length) payload.extra = extra;
    return this.record(MODEL_CALL, payload);
  }

  async recordToolCall(name, args, result, { outcome = "success", kind = TOOL_CALL, ...extra } = {}) {
    const payload = { tool: name, outcome };
    Object.assign(payload, await this._content("args", args));
    Object.assign(payload, await this._content("result", result));
    if (Object.keys(extra).length) payload.extra = extra;
    return this.record(kind, payload);
  }

  async recordMcpCall(name, args, result, opts = {}) {
    return this.recordToolCall(name, args, result, { ...opts, kind: MCP_CALL });
  }

  async recordDecision(summary, fields = {}) {
    return this.record(DECISION, { summary, ...fields });
  }

  async recordDataAccess(resource, op, fields = {}) {
    return this.record(DATA_ACCESS, { resource, op, ...fields });
  }

  async recordHumanOversight(action, fields = {}) {
    return this.record(HUMAN_OVERSIGHT, { action, ...fields });
  }

  async heartbeat() {
    return this._push(await this._chain.heartbeat());
  }
}
