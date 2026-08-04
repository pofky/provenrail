// Provenrail standalone verifier, JavaScript (browser + Node, ESM).
//
// A second, independent implementation of the verification algorithm in SPEC.md. It runs in
// any modern browser and in Node 18+ using WebCrypto (Ed25519 + SHA-256), so a record can be
// checked with no install and trusting not even the Provenrail server. Agreeing with the
// Python `pr verify` on the same bundles is a conformance guarantee that the evidence format
// is portable, not tied to one implementation.
//
// Scope: this verifier fully checks the dual hash chains, signatures, arrival order, Merkle
// anchors, and local-anchor signatures. RFC 3161 trusted-timestamp CMS validation requires
// ASN.1/PKCS#7 parsing and is intentionally left to `pr verify` / the hosted verifier; an
// rfc3161 anchor is reported here as "present, timestamp not validated in this verifier".

const GENESIS_PREV_HASH = "0".repeat(64);
const SEAL = "lifecycle.session_end";
const GENESIS = "lifecycle.session_start";
const HUMAN_OVERSIGHT = "human_oversight";
const MODEL_CALL = "model_call";
const JS_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1

// WebCrypto is a global in modern browsers and in Node 20+.
const subtle = globalThis.crypto.subtle;

const enc = new TextEncoder();

// ---- canonicalization (RFC 8785 subset, matches canonical.py) ----
function codePointSort(a, b) {
  // compare by Unicode code point (Python sorted() on str), not UTF-16 code unit
  const ai = [...a], bi = [...b];
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i++) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
}

function canonicalString(s) {
  // JSON.stringify escaping matches Python json.dumps(ensure_ascii=False) for our inputs
  return JSON.stringify(s.normalize("NFC"));
}

export class CanonicalError extends Error {}

function canon(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return canonicalString(value);
  if (t === "number") {
    if (!Number.isInteger(value)) throw new CanonicalError("floats are not allowed in records");
    if (Math.abs(value) > JS_SAFE_INT_MAX) throw new CanonicalError("integer out of safe range");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).sort(codePointSort);
    return "{" + keys.map(k => canonicalString(k) + ":" + canon(value[k])).join(",") + "}";
  }
  throw new CanonicalError("unsupported type " + t);
}

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(s) {
  const a = new Uint8Array(s.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16);
  return a;
}
async function sha256Hex(bytes) {
  return hex(await subtle.digest("SHA-256", bytes));
}
export async function hashValue(value) {
  return sha256Hex(enc.encode(canon(value)));
}

async function verifySig(pubkeyHex, msgBytes, sigHex) {
  try {
    const key = await subtle.importKey("raw", fromHex(pubkeyHex), { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, fromHex(sigHex), msgBytes);
  } catch { return false; }
}

function recordContent(rec) {
  const out = {};
  for (const k of Object.keys(rec)) if (k !== "record_hash" && k !== "record_sig") out[k] = rec[k];
  return out;
}

// ---- Merkle (RFC 6962, matches anchor.py) ----
async function leafHash(hHex) {
  const h = fromHex(hHex);
  const buf = new Uint8Array(1 + h.length); buf[0] = 0x00; buf.set(h, 1);
  return new Uint8Array(await subtle.digest("SHA-256", buf));
}
async function nodeHash(l, r) {
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01; buf.set(l, 1); buf.set(r, 1 + l.length);
  return new Uint8Array(await subtle.digest("SHA-256", buf));
}
async function merkleRoot(leavesHex) {
  if (!leavesHex.length) return "0".repeat(64);
  let level = [];
  for (const h of leavesHex) level.push(await leafHash(h));
  while (level.length > 1) {
    const nxt = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) nxt.push(await nodeHash(level[i], level[i + 1]));
      else nxt.push(level[i]);
    }
    level = nxt;
  }
  return hex(level[0]);
}

// ---- transparency log (RFC 6962 + C2SP, matches tlog.py) ----
const TLOG_LEAF_DOMAIN = enc.encode("flightrecorder.io/v1/tlog-leaf:");
const EM = "\u2014"; // signed-note signature line marker (U+2014, escaped, no glyph in source)

function fromB64(s) {
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
async function sha256Bytes(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}
function concatBytes(...parts) {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function anchorCommit(a, streamId) {
  const r = a.receipt || {};
  const tos = r.kind === "rfc3161" ? (r.token_b64 || "") : (r.signature || "");
  const commit = canon({
    stream_id: streamId, anchor_seq: a.anchor_seq, covers_up_to: a.covers_up_to,
    merkle_root: r.merkle_root || "", gen_time: r.gen_time || "", kind: r.kind || "",
    token_b64_or_sig: tos,
  });
  return sha256Bytes(enc.encode(commit));
}
async function tlogLeafHash(commitBytes) {
  return sha256Bytes(concatBytes(new Uint8Array([0x00]), TLOG_LEAF_DOMAIN, commitBytes));
}
function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
async function verifyInclusionBytes(leaf, leafIndex, treeSize, proof, root) {
  if (leafIndex < 0 || treeSize < 0 || leafIndex >= treeSize) return false;
  let fn = leafIndex, sn = treeSize - 1, r = leaf;
  for (const p of proof) {
    if (p.length !== 32) return false;
    if ((fn & 1) || fn === sn) {
      r = await nodeHash(p, r);
      if (!(fn & 1)) { while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; } }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eqBytes(r, root);
}
function isPow2(n) { return n > 0 && (n & (n - 1)) === 0; }
async function verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof) {
  if (oldSize < 0 || newSize < 0 || oldSize > newSize) return false;
  if (oldSize === newSize) return eqBytes(oldRoot, newRoot) && proof.length === 0;
  if (oldSize === 0) return proof.length === 0;
  if (proof.some(p => p.length !== 32)) return false;
  let pr = proof;
  if (isPow2(oldSize)) pr = [oldRoot, ...proof];
  if (!pr.length) return false;
  let fn = oldSize - 1, sn = newSize - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = pr[0], sr = pr[0];
  for (const c of pr.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = await nodeHash(c, fr); sr = await nodeHash(c, sr);
      if (!(fn & 1)) { while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; } }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eqBytes(fr, oldRoot) && eqBytes(sr, newRoot);
}
function parseSignedNote(note) {
  const rawLines = (note.endsWith("\n") ? note.slice(0, -1) : note).split("\n");
  let i = rawLines.length;
  while (i > 0 && rawLines[i - 1].startsWith(EM + " ")) i--;
  const sigLines = rawLines.slice(i);
  let bodyLines = rawLines.slice(0, i);
  if (!sigLines.length) return { body: note, signatures: [] };
  if (bodyLines.length && bodyLines[bodyLines.length - 1] === "") bodyLines = bodyLines.slice(0, -1);
  const body = bodyLines.join("\n") + "\n";
  const signatures = [];
  for (const line of sigLines) {
    const rest = line.slice(EM.length + 1);
    const sp = rest.lastIndexOf(" ");
    if (sp < 0) continue;
    const name = rest.slice(0, sp);
    let payload;
    try { payload = fromB64(rest.slice(sp + 1)); } catch { continue; }
    if (payload.length < 4) continue;
    signatures.push({ key_name: name, payload });
  }
  return { body, signatures };
}
async function keyId(name, pubkey, alg) {
  return (await sha256Bytes(concatBytes(enc.encode(name), new Uint8Array([0x0a, alg]), pubkey))).slice(0, 4);
}
async function verifyLogSig(body, payload, pubkeyHex, name) {
  const pub = fromHex(pubkeyHex);
  const expect = await keyId(name, pub, 0x01);
  if (!eqBytes(payload.slice(0, 4), expect)) return "key_id_mismatch";
  const sig = payload.slice(4);
  if (sig.length !== 64 || !(await verifySig(pubkeyHex, enc.encode(body), hex(sig)))) return "bad_sig";
  return "ok";
}
function readU64BE(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return Number(v);
}
async function verifyCosig(payload, pubkeyHex, body, name) {
  if (payload.length !== 4 + 8 + 64) return [false, 0];
  const pub = fromHex(pubkeyHex);
  if (!eqBytes(payload.slice(0, 4), await keyId(name, pub, 0x04))) return [false, 0];
  const ts = readU64BE(payload.slice(4, 12));
  const sig = payload.slice(12);
  const msg = concatBytes(enc.encode("cosignature/v1\ntime " + ts + "\n"), enc.encode(body));
  return [await verifySig(pubkeyHex, msg, hex(sig)), ts];
}
function parseTs(s) {
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t / 1000;
}
async function verifyTlog(bundle, rep, opts) {
  const logKey = opts.tlogLogKey || null;
  const witnesses = opts.witnessPubkeys || {};
  const maxAgeS = (opts.maxCosigAgeDays ?? 30) * 86400;
  const SKEW = 5.0;
  const nowS = opts.nowUtc ? parseTs(opts.nowUtc) : Date.now() / 1000;
  const hasSchema = bundle.tlog_schema_version !== undefined && bundle.tlog_schema_version !== null;
  const anchors = bundle.anchors || [];
  const streamId = bundle.stream_id;
  const seenRoots = {};
  for (const a of anchors) {
    const incl = a.tlog_inclusion;
    if (!incl) {
      rep.add(hasSchema ? "warn" : "info", "tlog_no_inclusion",
        `anchor ${a.anchor_seq}: no transparency-log inclusion proof present`);
      continue;
    }
    const parsed = parseSignedNote(incl.checkpoint || "");
    const body = parsed.body;
    const bodyLines = body.split("\n");
    const origin = bodyLines[0] || "";
    const rootB64 = bodyLines.length >= 3 ? bodyLines[2] : null;
    const treeSize = parseInt(bodyLines[1], 10);
    if (rootB64 === null || Number.isNaN(treeSize)) {
      rep.add("fail", "tlog_inclusion_fail", `anchor ${a.anchor_seq}: malformed checkpoint body`);
      continue;
    }
    seenRoots[treeSize] = rootB64;
    const leaf = await tlogLeafHash(await anchorCommit(a, streamId));
    const proof = (incl.proof_hashes || []).map(fromB64);
    const ok = await verifyInclusionBytes(leaf, incl.leaf_index ?? -1, incl.tree_size ?? treeSize, proof, fromB64(rootB64));
    if (!ok) {
      rep.add("fail", "tlog_inclusion_fail",
        `anchor ${a.anchor_seq}: inclusion proof does not verify against the checkpoint root`);
      continue;
    }
    const logSig = parsed.signatures.find(s => s.payload.length === 68);
    if (!logKey) {
      rep.add("warn", "tlog_log_key_unknown", `anchor ${a.anchor_seq}: no log public key configured`);
    } else if (!logSig) {
      rep.add("fail", "tlog_log_key_invalid", `anchor ${a.anchor_seq}: checkpoint carries no log-key signature`);
    } else {
      const st = await verifyLogSig(body, logSig.payload, logKey, origin);
      if (st === "key_id_mismatch") rep.add("fail", "tlog_log_key_id_mismatch", `anchor ${a.anchor_seq}: log key id mismatch`);
      else if (st !== "ok") rep.add("fail", "tlog_log_key_invalid", `anchor ${a.anchor_seq}: log-key signature invalid`);
    }
    let validCosigs = 0;
    for (const s of parsed.signatures) {
      if (s.payload.length !== 76) continue;
      const pub = witnesses[s.key_name];
      if (!pub) { rep.add("info", "tlog_cosig_unrecognized", `anchor ${a.anchor_seq}: cosignature from unconfigured witness ${s.key_name}`); continue; }
      // Wrong key supplied for this witness (key id differs) is a verifier-input problem, not
      // tampering; only a key-id match with a bad signature is a forgery. Mirrors verify.py.
      if (!eqBytes(s.payload.slice(0, 4), await keyId(s.key_name, fromHex(pub), 0x04))) {
        rep.add("fail", "tlog_cosig_key_id_mismatch", `anchor ${a.anchor_seq}: the witness key you supplied for ${s.key_name} does not match this cosignature (wrong or stale key, or a different witness). The record itself is unaffected.`);
        continue;
      }
      const [valid, ts] = await verifyCosig(s.payload, pub, body, s.key_name);
      if (!valid) { rep.add("fail", "tlog_cosig_invalid", `anchor ${a.anchor_seq}: witness ${s.key_name} cosignature invalid`); continue; }
      const genTime = parseTs((a.receipt || {}).gen_time || "");
      if (ts > nowS + SKEW) { rep.add("fail", "tlog_cosig_invalid", `anchor ${a.anchor_seq}: witness ${s.key_name} cosignature is in the future`); continue; }
      if (genTime !== null && genTime > ts + SKEW) { rep.add("warn", "tlog_cosig_stale", `anchor ${a.anchor_seq}: witness ${s.key_name} cosigned before the anchor`); continue; }
      if (nowS - ts > maxAgeS) { rep.add("warn", "tlog_cosig_stale", `anchor ${a.anchor_seq}: witness ${s.key_name} cosignature too old`); continue; }
      rep.add("info", "tlog_cosig_valid", `anchor ${a.anchor_seq}: witness ${s.key_name} cosignature valid`);
      validCosigs++;
    }
    if (validCosigs >= 1)
      rep.add("info", "tlog_inclusion_witnessed_ok", `anchor ${a.anchor_seq}: in the transparency log and witnessed by ${validCosigs}`);
    else
      rep.add(opts.auditTrail ? "fail" : "warn", "tlog_inclusion_unwitnessed", `anchor ${a.anchor_seq}: in the transparency log but not witnessed`);
  }
  for (const cp of bundle.tlog_consistency_proofs || []) {
    const oldRoot = seenRoots[cp.old_size], newRoot = seenRoots[cp.new_size];
    if (oldRoot === undefined || newRoot === undefined) {
      rep.add("info", "tlog_consistency_skipped", `consistency ${cp.old_size}->${cp.new_size}: root not in bundle`);
      continue;
    }
    const proof = (cp.proof_hashes || []).map(fromB64);
    if (!(await verifyConsistency(cp.old_size, fromB64(oldRoot), cp.new_size, fromB64(newRoot), proof)))
      rep.add("fail", "tlog_consistency_fail", `consistency ${cp.old_size}->${cp.new_size}: not an append-only extension`);
  }
}

// ---- minimal canonical CBOR (RFC 8949 subset, byte-for-byte match to cbor.py) ----
// Only what SCITT COSE_Sign1 receipts need: ints, byte/text strings, arrays, maps, tags, null.
const CBOR_MAX_DEPTH = 64;
const cborDec = new TextDecoder();

function cborHead(major, n) {
  const mt = major << 5;
  if (n < 24) return new Uint8Array([mt | n]);
  if (n < 0x100) return new Uint8Array([mt | 24, n]);
  if (n < 0x10000) return new Uint8Array([mt | 25, (n >> 8) & 0xff, n & 0xff]);
  if (n < 0x100000000) return new Uint8Array([mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  const hi = Math.floor(n / 0x100000000) >>> 0, lo = n >>> 0;
  return new Uint8Array([mt | 27, (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff]);
}
// Encoder: only the shapes a Sig_structure needs (text string, byte strings, array, int).
function cborEncode(value) {
  if (value === null) return new Uint8Array([0xf6]);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("cbor: non-integer");
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === "string") { const b = enc.encode(value); return concatBytes(cborHead(3, b.length), b); }
  if (value instanceof Uint8Array) return concatBytes(cborHead(2, value.length), value);
  if (Array.isArray(value)) {
    let out = cborHead(4, value.length);
    for (const it of value) out = concatBytes(out, cborEncode(it));
    return out;
  }
  throw new Error("cbor: unsupported encode type");
}
function cborNeed(st, n) { if (st.i + n > st.b.length) throw new Error("cbor: truncated"); }
function cborRead(st, depth) {
  if (depth > CBOR_MAX_DEPTH) throw new Error("cbor: nesting too deep");
  cborNeed(st, 1);
  const ib = st.b[st.i++];
  const major = ib >> 5, ai = ib & 0x1f;
  let arg;
  if (ai < 24) arg = ai;
  else if (ai === 24) { cborNeed(st, 1); arg = st.b[st.i++]; }
  else if (ai === 25) { cborNeed(st, 2); arg = (st.b[st.i] << 8) | st.b[st.i + 1]; st.i += 2; }
  else if (ai === 26) { cborNeed(st, 4); arg = (st.b[st.i] * 0x1000000) + ((st.b[st.i + 1] << 16) | (st.b[st.i + 2] << 8) | st.b[st.i + 3]); st.i += 4; }
  else if (ai === 27) {
    cborNeed(st, 8);
    const hi = (st.b[st.i] * 0x1000000) + ((st.b[st.i + 1] << 16) | (st.b[st.i + 2] << 8) | st.b[st.i + 3]);
    const lo = (st.b[st.i + 4] * 0x1000000) + ((st.b[st.i + 5] << 16) | (st.b[st.i + 6] << 8) | st.b[st.i + 7]);
    arg = hi * 0x100000000 + lo; st.i += 8;
  } else throw new Error("cbor: unsupported additional info " + ai);
  switch (major) {
    case 0: return arg;
    case 1: return -1 - arg;
    case 2: { cborNeed(st, arg); const s = st.b.slice(st.i, st.i + arg); st.i += arg; return s; }
    case 3: { cborNeed(st, arg); const s = st.b.slice(st.i, st.i + arg); st.i += arg; return cborDec.decode(s); }
    case 4: { const a = []; for (let k = 0; k < arg; k++) a.push(cborRead(st, depth + 1)); return a; }
    case 5: { const m = new Map(); for (let k = 0; k < arg; k++) { const key = cborRead(st, depth + 1); m.set(key, cborRead(st, depth + 1)); } return m; }
    case 6: { return { __cborTag: arg, value: cborRead(st, depth + 1) }; }
    case 7: if (arg === 22) return null; throw new Error("cbor: unsupported simple value " + arg);
    default: throw new Error("cbor: unsupported major " + major);
  }
}
function cborDecode(bytes) {
  const st = { b: bytes, i: 0 };
  const v = cborRead(st, 0);
  if (st.i !== bytes.length) throw new Error("cbor: trailing bytes");
  return v;
}

// ---- SCITT COSE receipt verification (step 13, matches scitt.py verify_receipt) ----
// COSE/SCITT label constants, frozen in SPEC.md section 18.
const COSE_SIGN1_TAG = 18, COSE_ALG = 1, ALG_EDDSA = -8, VDS_LABEL = -111, VDS_RFC9162_SHA256 = 1;
const PROOFS_LABEL = -222, INCLUSION_TYPE = -1;

async function verifyScittReceipt(receiptB64, commitBytes, tsPubkeyHex) {
  const verdict = { ok: false, signature_ok: false, inclusion_ok: false, kid_match: null, error: null };
  try {
    const cose = cborDecode(fromB64(receiptB64));
    if (!cose || cose.__cborTag !== COSE_SIGN1_TAG) { verdict.error = "not_cose_sign1"; return verdict; }
    const arr = cose.value;
    if (!Array.isArray(arr) || arr.length !== 4) { verdict.error = "malformed_cose_sign1"; return verdict; }
    const [protectedBstr, unprotected, payload, signature] = arr;
    const protectedMap = cborDecode(protectedBstr);
    // COSE_KID (label 4) is the raw TS public key; mismatch => wrong key supplied, not a forgery.
    const kid = (protectedMap instanceof Map) ? protectedMap.get(4) : undefined;
    verdict.kid_match = (kid instanceof Uint8Array) && eqBytes(kid, fromHex(tsPubkeyHex));
    if (!(protectedMap instanceof Map) || protectedMap.get(COSE_ALG) !== ALG_EDDSA) { verdict.error = "unexpected_alg"; return verdict; }
    if (protectedMap.get(VDS_LABEL) !== VDS_RFC9162_SHA256) { verdict.error = "unexpected_vds"; return verdict; }
    if (!(payload instanceof Uint8Array) || payload.length !== 32) { verdict.error = "bad_payload"; return verdict; }

    const sigStructure = cborEncode(["Signature1", protectedBstr, new Uint8Array(0), payload]);
    verdict.signature_ok = (signature instanceof Uint8Array) && await verifySig(tsPubkeyHex, sigStructure, hex(signature));

    const proofs = (unprotected instanceof Map) ? unprotected.get(PROOFS_LABEL) : undefined;
    const inclList = (proofs instanceof Map) ? proofs.get(INCLUSION_TYPE) : undefined;
    if (!inclList || !inclList.length) { verdict.error = "no_inclusion_proof"; return verdict; }
    const [treeSize, leafIndex, path] = cborDecode(inclList[0]);
    const leaf = await tlogLeafHash(commitBytes);
    verdict.inclusion_ok = await verifyInclusionBytes(leaf, leafIndex, treeSize, path, payload);
  } catch (e) {
    verdict.error = "exception:" + (e && e.name ? e.name : "Error");
    return verdict;
  }
  verdict.ok = verdict.signature_ok && verdict.inclusion_ok;
  return verdict;
}

async function verifyScitt(bundle, rep, opts) {
  // A receipt re-expresses a tlog inclusion as a standards-format COSE_Sign1 signed by the
  // transparency-service key. Present-but-forged is a hard fail; present-but-unverifiable
  // (no TS key supplied) is info, identical to the Python verifier.
  const logKey = opts.tlogLogKey || null;
  const streamId = bundle.stream_id || "";
  const receipts = (bundle.anchors || []).filter(a => a.scitt_receipt);
  if (!receipts.length) return;
  if (!logKey) {
    rep.add("info", "scitt_receipt_present",
      `${receipts.length} SCITT COSE receipt(s) present but unverified; supply the transparency-service key to verify them`);
    return;
  }
  let nOk = 0;
  for (const a of receipts) {
    let commit;
    try { commit = await anchorCommit(a, streamId); }
    catch { rep.add("fail", "scitt_receipt_invalid", `anchor ${a.anchor_seq}: cannot recompute commitment for its SCITT receipt`); continue; }
    const v = await verifyScittReceipt(a.scitt_receipt, commit, logKey);
    if (v.ok) nOk++;
    else if (v.inclusion_ok && !v.signature_ok && v.kid_match === false)
      rep.add("fail", "scitt_key_mismatch",
        `anchor ${a.anchor_seq}: the transparency-log key you supplied does not match this SCITT receipt's key id; cannot confirm it (wrong or stale key). The receipt's inclusion proof is intact.`);
    else rep.add("fail", "scitt_receipt_invalid",
      `anchor ${a.anchor_seq}: SCITT receipt failed verification (signature_ok=${v.signature_ok}, inclusion_ok=${v.inclusion_ok}, error=${v.error})`);
  }
  if (nOk) rep.add("info", "scitt_receipt_ok",
    `${nOk} SCITT COSE receipt(s) verified against the transparency service (standards-aligned, draft-ietf-scitt-architecture)`);
}

// ---- OpenTimestamps (Bitcoin) proof verification (step 14, matches ots.py) ----
const OTS_MAGIC = concatBytes(enc.encode("\x00OpenTimestamps\x00\x00Proof\x00"),
  new Uint8Array([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]));
const OTS_TAG_BITCOIN = fromHex("0588960d73d71901");
const OTS_TAG_PENDING = fromHex("83dfe30d2ef90c8e");
const OTS_CRYPT_LEN = { 0x02: 20, 0x03: 20, 0x08: 32, 0x67: 32 };
const OTS_MAX_RESULT = 4096, OTS_MAX_PAYLOAD = 8192, OTS_RECURSION = 256;

function otsRead(r, n) {
  if (r.i + n > r.b.length) throw new Error("truncated OTS proof");
  const out = r.b.slice(r.i, r.i + n);
  r.i += n;
  return out;
}
function otsVaruint(r) {
  let value = 0, shift = 0;
  for (;;) {
    const byte = otsRead(r, 1)[0];
    value += (byte & 0x7f) * Math.pow(2, shift);  // Math.pow, not <<, to stay correct past 31 bits
    if (!(byte & 0x80)) return value;
    shift += 7;
    if (shift > 63) throw new Error("varuint too large");
  }
}
function otsVarbytes(r, max, min = 0) {
  const n = otsVaruint(r);
  if (n > max) throw new Error("varbytes too long");
  if (n < min) throw new Error("varbytes too short");
  return otsRead(r, n);
}
async function otsApplyCrypt(tag, msg) {
  if (tag === 0x08) return new Uint8Array(await subtle.digest("SHA-256", msg));
  if (tag === 0x02) return new Uint8Array(await subtle.digest("SHA-1", msg));
  // ripemd160 (0x03) is not in WebCrypto; it never appears on a Bitcoin block-header path.
  throw new Error(`crypto op 0x${tag.toString(16)} unsupported in the browser verifier`);
}
async function otsWalk(r, msg, acc, depth) {
  if (depth <= 0) throw new Error("OTS recursion limit reached");
  const step = async (tag) => {
    if (tag === 0x00) {
      const attTag = otsRead(r, 8);
      const payload = otsVarbytes(r, OTS_MAX_PAYLOAD);
      const pr = { b: payload, i: 0 };
      if (eqBytes(attTag, OTS_TAG_BITCOIN)) {
        acc.bitcoin.push({ height: otsVaruint(pr), merkleRootHex: hex(msg) });
      } else if (eqBytes(attTag, OTS_TAG_PENDING)) {
        acc.pending.push(cborDec.decode(otsVarbytes(pr, OTS_MAX_PAYLOAD)));
      }  // unknown attestation types ignored (forward-compatible), like the reference lib
      return;
    }
    let nm;
    if (tag === 0x08 || tag === 0x02 || tag === 0x03) nm = await otsApplyCrypt(tag, msg);
    else if (tag === 0xf0) nm = concatBytes(msg, otsVarbytes(r, OTS_MAX_RESULT, 1));
    else if (tag === 0xf1) nm = concatBytes(otsVarbytes(r, OTS_MAX_RESULT, 1), msg);
    else if (tag === 0xf2) nm = msg.slice().reverse();
    else if (tag === 0xf3) nm = enc.encode(hex(msg));
    else throw new Error(`unsupported op 0x${tag.toString(16)}`);
    if (nm.length > OTS_MAX_RESULT) throw new Error("op result too long");
    await otsWalk(r, nm, acc, depth - 1);
  };
  let tag = otsRead(r, 1)[0];
  while (tag === 0xff) { await step(otsRead(r, 1)[0]); tag = otsRead(r, 1)[0]; }
  await step(tag);
}
async function otsParse(bytes) {
  const r = { b: bytes, i: 0 };
  if (!eqBytes(otsRead(r, OTS_MAGIC.length), OTS_MAGIC)) throw new Error("not an OpenTimestamps proof");
  if (otsVaruint(r) !== 1) throw new Error("unsupported OTS major version");
  const fileOp = otsRead(r, 1)[0];
  if (!(fileOp in OTS_CRYPT_LEN)) throw new Error("unsupported file hash op");
  const fileDigest = otsRead(r, OTS_CRYPT_LEN[fileOp]);
  const acc = { bitcoin: [], pending: [] };
  await otsWalk(r, fileDigest, acc, OTS_RECURSION);
  if (r.i !== r.b.length) throw new Error("trailing bytes after OTS proof");
  return { fileDigestHex: hex(fileDigest), bitcoin: acc.bitcoin, pending: acc.pending };
}
function otsRootMatches(computedHex, trustedHex) {
  const c = computedHex.toLowerCase(), t = trustedHex.toLowerCase();
  return c === t || hex(fromHex(c).slice().reverse()) === t;
}
async function otsVerify(bytes, dataHex, headers) {
  const verdict = { ok: false, structurally_valid: false, data_matches: false,
    bitcoin_attested: false, bitcoin: [], pending: [], error: null };
  let parsed;
  try { parsed = await otsParse(bytes); } catch (e) { verdict.error = e.message; return verdict; }
  verdict.structurally_valid = true;
  verdict.data_matches = parsed.fileDigestHex.toLowerCase() === (dataHex || "").toLowerCase();
  verdict.pending = parsed.pending;
  let confirmedAny = false;
  for (const att of parsed.bitcoin) {
    const trusted = headers ? headers[att.height] : undefined;
    let confirmed = null;
    if (trusted !== undefined && trusted !== null) {
      confirmed = otsRootMatches(att.merkleRootHex, trusted);
      confirmedAny = confirmedAny || confirmed;
    }
    verdict.bitcoin.push({ height: att.height, merkle_root_hex: att.merkleRootHex, confirmed });
  }
  verdict.bitcoin_attested = parsed.bitcoin.length > 0;
  verdict.ok = verdict.data_matches && confirmedAny;
  return verdict;
}
async function verifyOts(bundle, rep, opts) {
  const proofs = bundle.ots_proofs || [];
  if (!proofs.length) return;
  const headers = opts.bitcoinHeaders || null;
  for (const p of proofs) {
    const treeSize = p.tree_size;
    let proofBytes, stamped;
    try { proofBytes = fromB64(p.ots_b64 || ""); stamped = await sha256Hex(fromHex(p.root_hex || "")); }
    catch { rep.add("fail", "ots_invalid", `OTS proof for tree_size ${treeSize}: malformed proof or root`); continue; }
    const v = await otsVerify(proofBytes, stamped, headers);
    if (!v.structurally_valid) {
      rep.add("fail", "ots_invalid", `OTS proof for tree_size ${treeSize}: not a valid OpenTimestamps proof (${v.error})`); continue;
    }
    if (!v.data_matches) {
      rep.add("fail", "ots_wrong_target", `OTS proof for tree_size ${treeSize}: does not commit to the checkpoint root`); continue;
    }
    if (v.bitcoin.some(b => b.confirmed === false)) {
      const hs = v.bitcoin.filter(b => b.confirmed === false).map(b => b.height).join(", ");
      rep.add("fail", "ots_block_mismatch", `OTS proof for tree_size ${treeSize}: replayed root does not match the trusted Bitcoin header at block ${hs}`); continue;
    }
    const confirmed = v.bitcoin.filter(b => b.confirmed === true).map(b => b.height);
    if (confirmed.length) {
      rep.add("info", "ots_bitcoin_confirmed", `checkpoint (tree_size ${treeSize}) anchored in Bitcoin block(s) ${confirmed.join(", ")}, confirmed against a trusted header`);
    } else if (v.bitcoin_attested) {
      rep.add("info", "ots_bitcoin_attested", `checkpoint (tree_size ${treeSize}) is Bitcoin-attested at block(s) ${v.bitcoin.map(b => b.height).join(", ")}; supply a trusted header to confirm it against the chain`);
    } else if (v.pending.length) {
      rep.add("info", "ots_pending", `checkpoint (tree_size ${treeSize}) submitted to OpenTimestamps calendar(s), Bitcoin confirmation pending`);
    }
  }
}

// ---- coherence signals (step 11, mirrors coherence.py detect()) ----
// Heuristics, never a verdict: the cryptographic checks decide whether a record is authentic,
// and nothing here can promote or demote that. What these do is point at the seams. They were
// missing from this verifier entirely, so someone auditing in the browser saw a clean result
// and never learned that the run recorded no human governance at all, while the CLI told them.
const GAP_SECONDS = 3600.0;
const BACKWARDS_TOLERANCE_S = 1.0;

function detectCoherence(ordered, rep) {
  if (!ordered.length) return;
  let prevTs = null, prevSeq = null;
  for (const rec of ordered) {
    const ts = parseTs(rec.ts_utc || "");
    const seq = rec.seq;
    if (ts !== null && prevTs !== null) {
      const delta = ts - prevTs;
      if (delta < -BACKWARDS_TOLERANCE_S) {
        rep.add("warn", "nonmonotonic_ts",
          `seq ${seq}: timestamp ${rec.ts_utc} is earlier than the previous record's (seq ${prevSeq}); clock skew or reordering (hashes still intact)`);
      } else if (delta > GAP_SECONDS) {
        rep.add("info", "time_gap",
          `seq ${prevSeq} to ${seq}: ${Math.floor(delta)}s passed between consecutive records; a long quiet window worth confirming was not an un-instrumented period`);
      }
    }
    prevTs = ts === null ? prevTs : ts;
    prevSeq = seq;
  }
  const seen = new Map();
  for (const rec of ordered) {
    const rid = rec.record_id;
    if (rid === undefined || rid === null) continue;
    if (seen.has(rid)) rep.add("warn", "duplicate_record_id", `record_id ${rid} appears at seq ${seen.get(rid)} and ${rec.seq}`);
    else seen.set(rid, rec.seq);
  }
  const missingUsage = ordered.filter(r => r.action_type === MODEL_CALL && !((r.payload || {}).usage)).length;
  if (missingUsage) {
    rep.add("info", "usage_missing",
      `${missingUsage} model call(s) recorded no token usage; cost and spend-cap accounting cannot be reconstructed for them`);
  }
  const actions = new Set(ordered.map(r => r.action_type));
  if (actions.has(MODEL_CALL) && !actions.has("decision") && !actions.has(HUMAN_OVERSIGHT)) {
    rep.add("info", "no_governance",
      "the session made model calls but recorded no decision or human-oversight event; fine for an autonomous job, notable for one expected to be supervised");
  }
  for (const rec of ordered) {
    if (rec.action_type !== SEAL) continue;
    const stated = parseInt(String((rec.payload || {}).count), 10);
    if (Number.isNaN(stated)) continue;
    if (stated !== rec.seq) {
      rep.add("warn", "seal_count_mismatch", `seal claims ${stated} prior records but sits at seq ${rec.seq}`);
    }
  }
}

// ---- committed policy (step 10, matches policy.py + verifier/verify.py _verify_policy) ----
// This is the enforcement half of the lockstep. Without it the browser verifier could prove
// the record was untampered but not that the guardrails the operator committed to were
// actually applied, which is the claim the guardrail packs are sold on.
const POLICY_MEANINGFUL = { model_call: "model_call", tool_call: "tool_call", mcp_call: "mcp_call", data_access: "data_access" };

// Must equal policy.MAX_GLOB_PATTERN. A bundle is an untrusted input handed to a public web
// page, and a 100k-character glob compiles to a ~600k-character regex, so this verifier will
// not compile one. Rules that exceed it are excluded from the replay and REPORTED, upstream in
// verifyPolicy, so the CLI and the browser skip the same rules and say the same thing.
const MAX_GLOB_PATTERN = 512;

function oversizedGlob(rule) {
  return [rule.tool, rule.resource, rule.provider].some(p => String(p ?? "").length > MAX_GLOB_PATTERN);
}

function globMatch(pattern, value) {
  // fnmatch subset used by policy.Rule: *, ?, and [seq]. Case-insensitive, like _glob().
  const p = String(pattern == null ? "*" : pattern).toLowerCase();
  const v = String(value == null ? "" : value).toLowerCase();
  // Belt and braces: verifyPolicy already drops these rules before replay.
  if (p.length > MAX_GLOB_PATTERN) return false;
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") re += "[\\s\\S]*";
    else if (c === "?") re += "[\\s\\S]";
    else if (c === "[") {
      const close = p.indexOf("]", i + 1);
      if (close < 0) { re += "\\["; }
      else { let set = p.slice(i + 1, close); if (set.startsWith("!")) set = "^" + set.slice(1); re += "[" + set + "]"; i = close; }
    } else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  try { return new RegExp("^" + re + "$").test(v); } catch { return false; }
}

// Price table mirror of pricing.py, restricted to what a cost estimate needs. It is used
// ONLY to replay a spend cap; it never touches a hash or a signature, exactly as in Python.
// Rates verified against each provider's own pricing page on 2026-08-04. These mirror
// pricing.py entry for entry: a divergence here is a divergence in the verdict a budget
// replay reaches, which is the one thing two independent implementations exist to prevent.
// Anthropic: cache read 0.1x input, 5m write 1.25x, 1h write 2x, usage EXCLUSIVE of cache.
const _a = (i, o) => ({ in: i, out: o, cr: i * 0.10, cw: i * 1.25, cw1h: i * 2.00, incl: false });
// OpenAI: cached input at a discount, no separate write charge, usage INCLUSIVE.
const _o = (i, o, ratio = 0.25) => ({ in: i, out: o, cr: i * ratio, cw: null, incl: true });
// Google: cache read 0.1x input, usage INCLUSIVE, thinking tokens billed at the output rate
// ON TOP of candidatesTokenCount (totalTokenCount is defined as prompt + thoughts + candidates).
const _g = (i, o, tier) => ({ in: i, out: o, cr: i * 0.10, cw: null, incl: true, radd: true, ...(tier || {}) });
const _flat = (i, o) => ({ in: i, out: o, cr: null, cw: null, incl: false });
const JS_PRICES = {
  "gpt-4o-mini": _o(0.15, 0.60, 0.50), "gpt-4o": _o(2.50, 10.00, 0.50),
  "gpt-4.1-nano": _o(0.10, 0.40), "gpt-4.1-mini": _o(0.40, 1.60),
  "gpt-4.1": _o(2.00, 8.00), "gpt-4-turbo": _o(10.00, 30.00, 1.0),
  "gpt-3.5-turbo": _o(0.50, 1.50, 1.0), "o4-mini": _o(1.10, 4.40),
  "o3-mini": _o(1.10, 4.40), "o3": _o(2.00, 8.00),
  "o1-mini": _o(1.10, 4.40), "o1": _o(15.00, 60.00),
  "claude-3-5-haiku": _a(0.80, 4.00), "claude-3-5-sonnet": _a(3.00, 15.00),
  "claude-3-haiku": _a(0.25, 1.25), "claude-3-opus": _a(15.00, 75.00),
  "claude-haiku-4-5": _a(1.00, 5.00), "claude-haiku-4": _a(1.00, 5.00),
  "claude-sonnet-4-5": _a(3.00, 15.00), "claude-sonnet-4-6": _a(3.00, 15.00),
  "claude-sonnet-4": _a(3.00, 15.00), "claude-sonnet-5": _a(2.00, 10.00),
  // Every current Opus is listed: longest-substring resolution would otherwise hand 4-6, 4-7
  // and 4-8 to "claude-opus-4" and bill them at the retired $15/$75 rate.
  "claude-opus-4-5": _a(5.00, 25.00), "claude-opus-4-6": _a(5.00, 25.00),
  "claude-opus-4-7": _a(5.00, 25.00), "claude-opus-4-8": _a(5.00, 25.00),
  "claude-opus-4-1": _a(15.00, 75.00), "claude-opus-4": _a(15.00, 75.00),
  "claude-opus-5": _a(5.00, 25.00), "claude-fable-5": _a(10.00, 50.00),
  "gemini-2.5-flash-lite": _g(0.10, 0.40), "gemini-2.5-flash": _g(0.30, 2.50),
  "gemini-2.5-pro": _g(1.25, 10.00, { tierAt: 200000, tierIn: 2.50, tierOut: 15.00 }),
  "gemini-1.5-flash": _g(0.075, 0.30), "gemini-1.5-pro": _g(1.25, 5.00),
  "llama-3.1-405b": _flat(3.50, 3.50), "llama-3.1-70b": _flat(0.90, 0.90),
  "mistral-large": _flat(2.00, 6.00),
  "deepseek-chat": _flat(0.27, 1.10), "deepseek-reasoner": _flat(0.55, 2.19),
};
// Must stay identical to pricing.py's key lists, including Google's camelCase REST spellings
// and the Python SDK's snake_case ones, or a budget replays differently here than on the CLI.
const IN_KEYS = ["input", "in", "input_tokens", "prompt_tokens", "prompt", "tokens_in", "promptTokenCount", "prompt_token_count"];
const OUT_KEYS = ["output", "out", "output_tokens", "completion_tokens", "completion", "tokens_out", "candidatesTokenCount", "candidates_token_count"];
const CACHE_READ_KEYS = ["cache_read_input_tokens", "cached_tokens", "cache_read_tokens", "cache_read", "cached_input_tokens", "cached_content_token_count", "cachedContentTokenCount"];
const CACHE_WRITE_KEYS = ["cache_creation_input_tokens", "cache_write_tokens", "cache_write", "cache_creation_tokens"];
const CACHE_WRITE_1H_KEYS = ["ephemeral_1h_input_tokens", "ephemeral1hInputTokens"];
const REASONING_KEYS = ["reasoning_tokens", "thinking_tokens", "reasoning", "thoughtsTokenCount", "thoughts_token_count"];

function flatUsage(usage) {
  const flat = {};
  for (const [k, v] of Object.entries(usage || {})) {
    if (v && typeof v === "object" && !Array.isArray(v)) { for (const [ik, iv] of Object.entries(v)) if (!(ik in flat)) flat[ik] = iv; }
    else if (!(k in flat)) flat[k] = v;
  }
  return flat;
}
function pickTokens(usage, keys) {
  // Clamped at zero to match _to_int in pricing.py: a negative count would yield a negative
  // cost, which subtracts from projected spend and can carry a session back under a cap.
  for (const k of keys) if (usage[k] !== undefined && usage[k] !== null) { const n = parseInt(String(usage[k]).trim(), 10); return Number.isNaN(n) ? 0 : Math.max(0, n); }
  return 0;
}
function estimateCost(model, usage) {
  const name = String(model || "").toLowerCase();
  let price = null, bestLen = -1;
  for (const [key, p] of Object.entries(JS_PRICES)) if (name.includes(key) && key.length > bestLen) { price = p; bestLen = key.length; }
  if (!price) return 0;
  const u = flatUsage(usage);
  const tin = pickTokens(u, IN_KEYS), tout = pickTokens(u, OUT_KEYS);
  const cr = pickTokens(u, CACHE_READ_KEYS), cw = pickTokens(u, CACHE_WRITE_KEYS);
  const reasoning = pickTokens(u, REASONING_KEYS);
  const uncached = price.incl ? Math.max(0, tin - cr) : tin;
  const billableWrite = price.incl ? 0 : cw;
  // The higher tier applies to the whole call, not only to the tokens above the threshold.
  const tiered = price.tierAt !== undefined && tin > price.tierAt;
  const pin = tiered && price.tierIn !== undefined ? price.tierIn : price.in;
  const pout = tiered && price.tierOut !== undefined ? price.tierOut : price.out;
  const crRate = price.cr === null || price.cr === undefined ? pin : price.cr;
  const cwRate = price.cw === null || price.cw === undefined ? pin : price.cw;
  // The 1h portion is INSIDE the reported write total, so split it out and reprice it rather
  // than adding it, or the same tokens are billed twice.
  const w1h = price.cw1h === undefined ? 0 : Math.min(pickTokens(u, CACHE_WRITE_1H_KEYS), billableWrite);
  const w5m = billableWrite - w1h;
  const w1hRate = price.cw1h === undefined ? cwRate : price.cw1h;
  // Reasoning tokens sit inside the output count everywhere except Google, where they are
  // additive and billed at the output rate.
  const billableReasoning = price.radd ? reasoning : 0;
  const cost = (uncached * pin + (tout + billableReasoning) * pout + cr * crRate
                + w5m * cwRate + w1h * w1hRate) / 1e6;
  return round6(cost);
}

// Python's round() is round-half-to-EVEN, and Math.round is round-half-UP. On a cost landing
// exactly on a half-microdollar the two verifiers then disagree by 1e-6, and the whole point
// of a second implementation is that it reaches the same verdict. The CLI is the reference,
// so this mirrors its rule rather than the language default.
function round6(x) {
  const scaled = x * 1e6;
  const floor = Math.floor(scaled);
  const frac = scaled - floor;
  if (Math.abs(frac - 0.5) < 1e-9) return (floor % 2 === 0 ? floor : floor + 1) / 1e6;
  return Math.round(scaled) / 1e6;
}

function policyDecide(policy, eventType, ctx, state) {
  // Budgets first, mirroring Policy.decide. Only session-scoped budgets reach here: a day or
  // total cap was evaluated against spend in OTHER sessions, which this bundle does not
  // contain, so replaying it would manufacture findings out of missing history.
  if (eventType === "model_call") {
    const cost = estimateCost(ctx.model, ctx.usage);
    for (const b of policy.budgets) {
      const projected = state.spend + cost;
      if (projected > b.limit + 1e-9) return { effect: "deny", ruleId: b.id, reason: `${b.scope} spend cap exceeded` };
    }
  }
  for (const rule of policy.rules) {
    if (rule.event_type !== "*" && rule.event_type !== eventType) continue;
    if (!globMatch(rule.tool, ctx.tool)) continue;
    if (!globMatch(rule.resource, ctx.resource)) continue;
    if (!globMatch(rule.provider, ctx.provider)) continue;
    if (rule.effect === "deny") return { effect: "deny", ruleId: rule.id, reason: rule.reason || "denied by policy" };
    if (rule.effect === "require_oversight" && !(state.oversightRules.has(rule.id) || state.oversight))
      return { effect: "deny", ruleId: rule.id, reason: rule.reason || "requires recorded human oversight" };
    if (rule.effect === "limit") {
      state.counts[rule.id] = (state.counts[rule.id] || 0) + 1;
      if (rule.max_per_session !== null && rule.max_per_session !== undefined && state.counts[rule.id] > rule.max_per_session)
        return { effect: "deny", ruleId: rule.id, reason: rule.reason || "per-session limit exceeded" };
      return { effect: "allow", ruleId: rule.id, reason: "within the per-session limit" };
    }
    if (rule.effect === "require_oversight") return { effect: "allow", ruleId: rule.id, reason: "oversight present" };
  }
  return { effect: "allow", ruleId: null, reason: "no rule matched" };
}

// The committed hash is taken over `Policy.to_dict()`, NOT over whatever dict happens to sit
// in the bundle. Hashing the raw dict here made the two verifiers disagree about tampering on
// any policy that was not already in exactly that shape: an explicit `"budgets": []`, a rule
// that omitted an optional field, or any extra key. Python normalized those away and passed;
// the browser hashed them literally and called a genuine bundle tampered. This mirrors
// `Policy.to_dict()` field for field so both sides hash the same bytes.
const _RULE_FIELDS = ["id", "effect", "event_type", "tool", "resource", "provider",
                      "arg_contains", "max_per_session", "reason"];
const _RULE_DEFAULTS = { effect: "", event_type: "*", tool: "*", resource: "*", provider: "*",
                         arg_contains: "", max_per_session: null, reason: "", id: "" };

export function policyCanonicalForm(dict) {
  const d = dict && typeof dict === "object" ? dict : {};
  const rules = (Array.isArray(d.rules) ? d.rules : []).map(r => {
    const out = {};
    // Only the known fields, always all of them: Rule.from_dict drops anything unrecognised
    // and Rule.to_dict emits every field including the defaults.
    for (const f of _RULE_FIELDS) out[f] = (r && r[f] !== undefined) ? r[f] : _RULE_DEFAULTS[f];
    return out;
  });
  const cap = d.session_spend_cap_usd;
  // Python writes the cap as a fixed 6-decimal STRING, because the canonicalizer forbids
  // floats in a record. Number formatting is where a lockstep quietly dies, so it is explicit.
  const out = { rules, session_spend_cap_usd: (cap === null || cap === undefined) ? null : fixed6(cap) };
  const budgets = Array.isArray(d.budgets) ? d.budgets : [];
  if (budgets.length) {
    out.budgets = budgets.map(b => ({
      id: b.id || `budget.${String(b.scope || "session").toLowerCase()}`,
      scope: String(b.scope || "session").toLowerCase(),
      limit_usd: fixed6(b.limit_usd ?? 0),
      // 4 decimals, and clamped to [0, 1], exactly as Budget.__post_init__ and Budget.to_dict
      // do it. A fraction written with the wrong precision hashes differently.
      warn_at: clamp01(b.warn_at === undefined ? 0.8 : b.warn_at).toFixed(4),
    }));
  }
  const onUnpriced = String(d.on_unpriced || "warn").toLowerCase();
  if (onUnpriced !== "warn") out.on_unpriced = onUnpriced;
  return out;
}

function fixed6(v) {
  const n = typeof v === "number" ? v : parseFloat(String(v));
  return Number.isFinite(n) ? n.toFixed(6) : "0.000000";
}

function clamp01(v) {
  const n = typeof v === "number" ? v : parseFloat(String(v));
  return Number.isFinite(n) ? Math.max(0, Math.min(1, n)) : 0;
}

function normalizePolicy(dict) {
  const rules = (dict.rules || []).map(r => ({
    id: r.id, effect: r.effect, event_type: r.event_type ?? "*", tool: r.tool ?? "*",
    resource: r.resource ?? "*", provider: r.provider ?? "*", arg_contains: r.arg_contains ?? "",
    max_per_session: r.max_per_session ?? null, reason: r.reason ?? "",
  }));
  const budgets = (dict.budgets || []).map(b => ({
    id: b.id || `budget.${b.scope || "session"}`, scope: (b.scope || "session").toLowerCase(),
    limit: parseFloat(b.limit_usd), warn_at: parseFloat(b.warn_at ?? "0.8"),
  }));
  const cap = dict.session_spend_cap_usd;
  if (cap !== null && cap !== undefined && !budgets.some(b => b.scope === "session"))
    budgets.push({ id: "session_spend_cap", scope: "session", limit: parseFloat(cap), warn_at: 0.8 });
  return { rules, budgets };
}

async function verifyPolicy(sessions, rep) {
  for (const sess of sessions) {
    if (!sess.length || sess[0].action_type !== GENESIS) continue;
    const meta = ((sess[0].payload || {}).meta) || {};
    const policyDict = meta.policy;
    if (policyDict === undefined || policyDict === null) continue;
    const committed = meta.policy_sha256;
    const recomputed = await hashValue(policyCanonicalForm(policyDict));
    if (committed !== undefined && committed !== null && recomputed !== committed) {
      rep.add("fail", "policy_commit_mismatch",
        "the committed policy hash does not match the embedded policy (the recorded guardrails were altered after the session started)");
      continue;
    }
    const full = normalizePolicy(policyDict);
    const contentRules = full.rules.filter(r => r.arg_contains).length;
    const crossSession = full.budgets.filter(b => b.scope !== "session").length;
    const oversized = full.rules.filter(r => !r.arg_contains && oversizedGlob(r)).length;
    // A content gate matches on argument text, which is hashed out of the bundle, and a
    // cross-session budget needs history this bundle does not hold. Both are reported as
    // enforced-but-not-re-checkable rather than silently trusted or silently dropped. An
    // over-long glob is the third case, and it must be dropped HERE and reported, exactly as
    // the CLI does. Leaving globMatch to quietly return false instead made this verifier call
    // a bundle fully verified while the CLI reported the same rule as unenforced.
    const reverifiable = {
      rules: full.rules.filter(r => !r.arg_contains && !oversizedGlob(r)),
      budgets: full.budgets.filter(b => b.scope === "session"),
    };
    if (oversized) {
      rep.add("warn", "policy_rule_not_rechecked",
        `${oversized} rule(s) carry a glob longer than ${MAX_GLOB_PATTERN} characters and were NOT re-evaluated. Enforcement at record time is unaffected; this verdict simply does not cover them`);
    }
    const state = { spend: 0, oversight: false, oversightRules: new Set(), counts: {} };
    let checked = 0, violations = 0, recordedDenies = 0;
    for (const rec of sess) {
      if (rec.action_type === "policy.decision" && String((rec.payload || {}).effect).toLowerCase() === "deny") recordedDenies++;
    }
    for (const rec of sess) {
      if (rec.action_type === HUMAN_OVERSIGHT) {
        // Rule-scoped sign-off unlocks that rule only; an unnamed one is the blanket kind.
        const r = (rec.payload || {}).rule;
        if (r) state.oversightRules.add(String(r)); else state.oversight = true;
        continue;
      }
      const ev = POLICY_MEANINGFUL[rec.action_type];
      if (!ev) continue;
      const payload = rec.payload || {};
      const ctx = { provider: payload.provider || "", model: payload.model || "", usage: payload.usage, tool: payload.tool || "", resource: payload.resource || "" };
      const decision = policyDecide(reverifiable, ev, ctx, state);
      checked++;
      if (decision.effect !== "allow") {
        violations++;
        rep.add("warn", "policy_not_enforced",
          `seq ${rec.seq}: an executed ${rec.action_type} matches policy rule ${JSON.stringify(decision.ruleId)} which would deny it (${decision.reason}); the committed policy was not enforced for this call`);
      }
      if (rec.action_type === "model_call") state.spend += estimateCost(ctx.model, ctx.usage);
    }
    if (violations === 0) {
      let detail = `committed policy ${committed ? String(committed).slice(0, 12) : "present"} verified: ${checked} re-verifiable events consistent with the guardrails, ${recordedDenies} recorded enforcement denials`;
      if (contentRules) detail += `; ${contentRules} content-gate rule(s) were enforced but cannot be re-checked offline because arguments are hashed`;
      if (crossSession) detail += `; ${crossSession} cross-session budget(s) were enforced but cannot be re-checked from this bundle alone, which covers one session`;
      rep.add("info", "policy_verified", detail);
    }
  }
}

// ---- report ----
// Failures that mean "a trust anchor the verifier supplied does not match this bundle" (a
// key-identity mismatch: wrong/stale key, or a proof from a different log/witness) rather than
// "the recorded data was altered". The record's own chain/signatures/inclusion are checked
// independently, so these must never read as tampering. Mirrors ATTESTATION_FAIL_CODES in
// verify.py (kept in lockstep per SPEC).
const ATTESTATION_FAIL_CODES = new Set([
  "tlog_log_key_id_mismatch",
  "tlog_cosig_key_id_mismatch",
  "scitt_key_mismatch",
]);

// "this is not a Provenrail bundle" (wrong file / wrong JSON shape), not a failed real bundle.
const FORMAT_ERROR_CODES = new Set(["not_a_bundle", "bad_format"]);

class Report {
  constructor() { this.findings = []; }
  add(severity, code, detail) { this.findings.push({ severity, code, detail }); }
  get ok() { return !this.findings.some(f => f.severity === "fail"); }
  // Three-way verdict, finer than ok: "verified" | "unconfirmed" | "tampered".
  get result() {
    const fails = this.findings.filter(f => f.severity === "fail").map(f => f.code);
    if (!fails.length) return "verified";
    if (fails.some(c => FORMAT_ERROR_CODES.has(c))) return "malformed";
    if (fails.length === 1 && fails[0] === "empty") return "empty";  // nothing recorded, not tampering
    if (fails.every(c => ATTESTATION_FAIL_CODES.has(c))) return "unconfirmed";
    return "tampered";
  }
  toDict() {
    return {
      ok: this.ok,
      result: this.result,
      fail: this.findings.filter(f => f.severity === "fail").length,
      warn: this.findings.filter(f => f.severity === "warn").length,
      findings: this.findings,
    };
  }
}

// ---- selective-disclosure redaction (matches redaction.py) ----
const REDACT_MARKER = "__fr_redacted__";

function isCommitment(o) {
  return !!o && typeof o === "object" && !Array.isArray(o)
    && Object.keys(o).length === 1 && o[REDACT_MARKER]
    && typeof o[REDACT_MARKER].commit === "string";
}

export async function commitFor(value, saltHex) {
  // commit = SHA-256(salt || canonicalize(value)), identical to redaction.commit in Python.
  return sha256Hex(concatBytes(fromHex(saltHex), enc.encode(canon(value))));
}

function walkCommitments(payload, out = []) {
  if (isCommitment(payload)) { out.push(payload[REDACT_MARKER].commit); return out; }
  if (Array.isArray(payload)) { for (const v of payload) walkCommitments(v, out); }
  else if (payload && typeof payload === "object") {
    for (const k of Object.keys(payload)) walkCommitments(payload[k], out);
  }
  return out;
}

async function verifyRedactions(records, rep, openings) {
  let total = 0, disclosed = 0, invalid = 0;
  for (const rec of records) {
    for (const c of walkCommitments(rec.payload || {})) {
      total++;
      const op = openings ? openings[c] : undefined;
      if (!op) continue;
      const recomputed = await commitFor(op.value, op.salt || "");
      if (recomputed === c) disclosed++;
      else {
        invalid++;
        rep.add("fail", "redaction_disclosure_invalid",
          `a supplied opening does not match its commitment ${c.slice(0, 16)}`);
      }
    }
  }
  if (total) {
    const withheld = total - disclosed - invalid;
    let detail = `${total} redactable field(s): ${disclosed} disclosed and verified, ${withheld} withheld or erased`;
    if (invalid) detail += `, ${invalid} INVALID disclosure(s)`;
    rep.add("info", "redaction_summary", detail);
  }
}

export async function verifyBundle(bundle, pin = null, opts = {}) {
  const rep = new Report();
  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle)) {
    rep.add("fail", "not_a_bundle",
      `this file is valid JSON but ${Array.isArray(bundle) ? "an array" : "a " + typeof bundle}, not a Provenrail bundle (a JSON object). Check you pointed at the right file.`);
    return rep.toDict();
  }
  if (bundle.format !== "flightrecorder.bundle/1") {
    rep.add("fail", "bad_format", `unexpected bundle format ${bundle.format}`);
    return rep.toDict();
  }
  const server = bundle.records || [];
  if (!server.length) { rep.add("fail", "empty", "bundle has no records"); return rep.toDict(); }

  if (pin) await verifyPin(bundle, server, pin, rep);

  // 1. server receipt chain, independently recomputed
  let prev = GENESIS_PREV_HASH;
  const srh = [];
  for (let i = 0; i < server.length; i++) {
    const sr = server[i];
    if (sr.recv_seq !== i) rep.add("fail", "recv_gap", `recv_seq gap at index ${i}`);
    const recvHash = await hashValue(sr.record);
    if (recvHash !== sr.recv_hash) rep.add("fail", "recv_hash_mismatch", `recv_seq ${sr.recv_seq}: bytes do not match recv_hash`);
    const link = await hashValue({ recv_seq: sr.recv_seq, recv_ts: sr.recv_ts, recv_hash: recvHash, server_prev_hash: prev });
    if (link !== sr.server_record_hash) rep.add("fail", "server_chain_break", `recv_seq ${sr.recv_seq}: server receipt chain broken`);
    srh.push(link);
    prev = link;
  }

  // 2. client chain: one genesis-rooted chain per session (a stream reused across runs
  //    holds several sessions; that is the normal quickstart shape, not tampering)
  const bySid = new Map();
  for (const sr of server) {
    const sid = sr.record.session_id;
    if (!bySid.has(sid)) bySid.set(sid, []);
    bySid.get(sid).push(sr.record);
  }
  const sessions = [...bySid.values()].map(s => s.slice().sort((a, b) => (a.seq ?? 1e18) - (b.seq ?? 1e18)));
  const multi = sessions.length > 1;
  for (const sess of sessions) {
    const label = multi ? `session ${sess[0].session_id}: ` : "";
    await verifyClientChain(sess, rep, label);
  }
  const client = sessions.flat();

  // 3. arrival order matches emission order, per session (sessions may interleave)
  for (const [sid, recs] of bySid) {
    const label = multi ? `session ${sid}: ` : "";
    const seqs = recs.map(r => r.seq);
    if (JSON.stringify(seqs) !== JSON.stringify([...seqs].sort((a, b) => a - b)))
      rep.add("fail", "arrival_reorder", `${label}records did not arrive in emission order`);
    if (new Set(seqs).size !== seqs.length) rep.add("fail", "duplicate_seq", `${label}duplicate client seq values`);
  }

  // 4. anchors
  const anchors = bundle.anchors || [];
  if (!anchors.length) rep.add("warn", "no_anchor", "no external anchor present");
  else if (anchors.every(a => (a.receipt || {}).kind === "local"))
    rep.add("warn", "local_anchor_only", "only LOCAL anchors present; no independent third-party time proof");
  for (const a of anchors) {
    const receipt = a.receipt || {};
    const covers = a.covers_up_to ?? -1;
    const leaves = server.filter(sr => sr.recv_seq <= covers && sr.recv_seq < srh.length).map(sr => srh[sr.recv_seq]);
    const root = await merkleRoot(leaves);
    if (root !== receipt.merkle_root) { rep.add("fail", "anchor_root_mismatch", `anchor ${a.anchor_seq}: Merkle root does not cover the receipt chain`); continue; }
    if (receipt.kind === "local") {
      const ok = await verifySig(receipt.anchor_pubkey || "", enc.encode((receipt.merkle_root || "") + "|" + (receipt.gen_time || "")), receipt.signature || "");
      if (!ok) rep.add("fail", "anchor_bad_sig", `anchor ${a.anchor_seq}: local anchor signature invalid`);
      else rep.add("warn", "anchor_local_only", `anchor ${a.anchor_seq}: LOCAL anchor only, time is self-asserted`);
    } else if (receipt.kind === "rfc3161") {
      rep.add("info", "anchor_rfc3161_unchecked", `anchor ${a.anchor_seq}: RFC 3161 timestamp present; CMS not validated in this verifier, use pr verify for full timestamp validation`);
    } else {
      rep.add("fail", "anchor_unknown_kind", `anchor ${a.anchor_seq}: unknown anchor kind`);
    }
  }

  // 7 + 8. transparency log (inclusion + consistency), if present
  await verifyTlog(bundle, rep, opts);

  // 10. committed policy: prove the guardrails in force were actually applied
  await verifyPolicy(sessions, rep);

  // 11. coherence signals (heuristics, never a verdict)
  detectCoherence(client, rep);

  // 12. selective-disclosure redaction: validate any supplied openings against commitments
  await verifyRedactions(client, rep, opts.openings || null);

  // 13. SCITT COSE receipts (standards-aligned re-expression of the tlog inclusion)
  await verifyScitt(bundle, rep, opts);

  // 14. OpenTimestamps (Bitcoin) proofs over checkpoint roots
  await verifyOts(bundle, rep, opts);

  // 5. completeness signals, per session
  for (const sess of sessions) {
    if (!sess.length || sess[sess.length - 1].action_type !== SEAL) {
      const label = multi && sess.length ? `session ${sess[0].session_id}: ` : "";
      rep.add("warn", "unsealed", `${label}session is not sealed; completeness unknown`);
    }
  }
  return rep.toDict();
}

async function verifyClientChain(records, rep, label = "") {
  if (!records.length) { rep.add("fail", "client_empty", `${label}no records`); return; }
  let expectedPrev = GENESIS_PREV_HASH, expectedSeq = 0;
  const pub0 = records[0].pubkey;
  const hashes = [];
  for (const rec of records) {
    const content = recordContent(rec);
    const canonBytes = enc.encode(canon(content));
    const recomputed = await sha256Hex(canonBytes);
    if (recomputed !== rec.record_hash) rep.add("fail", "client_hash_mismatch", `${label}seq=${rec.seq}: record_hash does not match content`);
    if (!await verifySig(rec.pubkey || "", canonBytes, rec.record_sig || "")) rep.add("fail", "client_bad_signature", `${label}seq=${rec.seq}: signature invalid`);
    if (rec.pubkey !== pub0) rep.add("fail", "client_key_changed", `${label}seq=${rec.seq}: device pubkey changed mid-stream`);
    if (rec.seq !== expectedSeq) rep.add("fail", "client_seq_gap", `${label}expected seq ${expectedSeq}, got ${rec.seq}`);
    if (rec.prev_hash !== expectedPrev) rep.add("fail", "client_broken_link", `${label}seq=${rec.seq}: prev_hash does not match previous record_hash`);
    expectedPrev = rec.record_hash;
    expectedSeq = (Number.isInteger(rec.seq) ? rec.seq : expectedSeq) + 1;
    hashes.push(rec.record_hash);
  }
  if (records[0].action_type !== GENESIS) rep.add("fail", "client_no_genesis", `${label}first record is not a session_start`);
  const seals = records.filter(r => r.action_type === SEAL);
  if (seals.length) {
    const seal = seals[seals.length - 1];
    if (Number.isInteger(seal.seq)) {
      const covered = records.filter(r => Number.isInteger(r.seq) && r.seq < seal.seq).map(r => r.record_hash);
      const expect = await hashValue(covered);
      if ((seal.payload || {}).session_hash !== expect) rep.add("fail", "client_bad_session_hash", `${label}seal session_hash does not cover the record set`);
    }
  }
}

async function verifyPin(bundle, server, pin, rep) {
  const body = {};
  for (const k of Object.keys(pin)) if (k !== "pin_sig") body[k] = pin[k];
  if (!await verifySig(pin.pubkey || "", enc.encode(canon(body)), pin.pin_sig || "")) {
    rep.add("fail", "pin_bad_signature", "pin signature invalid"); return;
  }
  if (pin.stream_id !== bundle.stream_id) { rep.add("fail", "pin_wrong_stream", "pin is for a different stream"); return; }
  const match = server.find(r => r.recv_seq === pin.recv_seq);
  if (!match) { rep.add("fail", "pin_truncated", `export is missing pinned recv_seq ${pin.recv_seq}`); return; }
  if (match.server_record_hash !== pin.server_record_hash) { rep.add("fail", "pin_forked", `recv_seq ${pin.recv_seq} hash differs from pin`); return; }
  rep.add("info", "pin_ok", `client pin confirmed up to recv_seq ${pin.recv_seq}`);
}

export default { verifyBundle, CanonicalError };
