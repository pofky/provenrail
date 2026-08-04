// Deterministic canonicalization, SHA-256, and Ed25519 signing for Provenrail records.
//
// This is the byte-for-byte counterpart of the Python `canonical.py` and the canon() in
// `web/verify.js`. A record signed here MUST hash identically in the Python verifier and the
// JavaScript verifier, or cross-language verification breaks. The cross-implementation test
// (tests/test_js_sdk.py) proves it: records signed by this SDK are verified by `pr verify`.
//
// Rules (RFC 8785 subset, matching canonical.py):
//   - object keys sorted by Unicode code point (Python sorted() on str)
//   - compact separators, no whitespace
//   - strings NFC-normalized; non-ASCII preserved as raw UTF-8 (not \u-escaped)
//   - floats rejected; integers outside the JS-safe range rejected (pass as strings)

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const JS_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1

export class CanonicalError extends Error {}

function codePointSort(a, b) {
  const ai = [...a], bi = [...b];
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i++) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
}

function canonicalString(s) {
  return JSON.stringify(s.normalize("NFC"));
}

export function canon(value) {
  if (value === null || value === undefined) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return canonicalString(value);
  if (t === "number") {
    if (!Number.isInteger(value)) throw new CanonicalError("floats are not allowed in records");
    if (Math.abs(value) > JS_SAFE_INT_MAX) throw new CanonicalError("integer out of safe range");
    return String(value);
  }
  if (t === "bigint") {
    throw new CanonicalError("bigint not allowed in records; pass large integers as strings");
  }
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).sort(codePointSort);
    return "{" + keys.map(k => canonicalString(k) + ":" + canon(value[k])).join(",") + "}";
  }
  throw new CanonicalError("unsupported type " + t);
}

export function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(bytes) {
  return hex(await subtle.digest("SHA-256", bytes));
}

export async function hashValue(value) {
  return sha256Hex(enc.encode(canon(value)));
}

export function canonBytes(value) {
  return enc.encode(canon(value));
}
