// Client-side hash chain over agent activity records (mirrors chain.py).
//
// Each record links to the previous via prev_hash, carries a monotonic seq, and is signed with
// the device key. A session opens with a genesis record (prev_hash = GENESIS) and closes with a
// seal carrying session_hash = hash of the ordered list of all record hashes. The exact field
// set and ordering MUST match chain.py so the dual hash chains and signatures verify across
// languages.

import { canon, canonBytes, sha256Hex } from "./canonical.js";
import { uuid4 } from "./crypto.js";

export const SCHEMA_VERSION = "1";
export const GENESIS_PREV_HASH = "0".repeat(64);

export const GENESIS = "lifecycle.session_start";
export const SEAL = "lifecycle.session_end";
export const HEARTBEAT = "lifecycle.heartbeat";
export const MODEL_CALL = "model_call";
export const TOOL_CALL = "tool_call";
export const MCP_CALL = "mcp_call";
export const DECISION = "decision";
export const DATA_ACCESS = "data_access";
export const HUMAN_OVERSIGHT = "human_oversight";

function utcNowIso() {
  // Python uses microsecond precision ("...%f Z"); JS Date gives milliseconds. Pad to 6 digits
  // so the shape matches. The value is a signed string, never parsed for the chain itself.
  return new Date().toISOString().slice(0, -1) + "000Z";
}

export class Chain {
  constructor(streamId, key, { clock = utcNowIso, idgen = uuid4 } = {}) {
    this.streamId = streamId;
    this.key = key;
    this.sessionId = idgen();
    this._seq = 0;
    this._lastHash = GENESIS_PREV_HASH;
    this._hashes = [];
    this._open = false;
    this._clock = clock;
    this._idgen = idgen;
  }

  async _emit(actionType, payload) {
    const content = {
      v: SCHEMA_VERSION,
      stream_id: this.streamId,
      session_id: this.sessionId,
      record_id: this._idgen(),
      seq: this._seq,
      prev_hash: this._lastHash,
      ts_utc: this._clock(),
      pubkey: this.key.publicKeyHex(),
      action_type: actionType,
      payload,
    };
    const bytes = canonBytes(content);
    const rec = { ...content };
    rec.record_hash = await sha256Hex(bytes);
    rec.record_sig = await this.key.sign(bytes);
    this._seq += 1;
    this._lastHash = rec.record_hash;
    this._hashes.push(rec.record_hash);
    return rec;
  }

  async start(meta) {
    if (this._open || this._seq !== 0) throw new Error("session already started");
    this._open = true;
    return this._emit(GENESIS, { meta: meta || {} });
  }

  async append(actionType, payload) {
    if (!this._open) throw new Error("session not started");
    if (actionType === GENESIS || actionType === SEAL) {
      throw new Error(`${actionType} is emitted by start()/seal(), not append()`);
    }
    return this._emit(actionType, payload);
  }

  async heartbeat() {
    if (!this._open) throw new Error("session not started");
    return this._emit(HEARTBEAT, {});
  }

  async seal(outcome = "success", trigger = "normal") {
    if (!this._open) throw new Error("session not started");
    const sessionHash = await sha256Hex(canonBytes(this._hashes));
    const rec = await this._emit(SEAL, {
      outcome,
      trigger,
      count: String(this._seq), // string, exactly like chain.py
      session_hash: sessionHash,
    });
    this._open = false;
    return rec;
  }
}

export { canon };
