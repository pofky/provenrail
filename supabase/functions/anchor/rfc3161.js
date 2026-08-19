// RFC 3161 in about as little code as it can be done in.
//
// Why hand-rolled: the hosted anchor service runs on Deno at the edge, and the two Python
// libraries that do this (rfc3161-client, asn1crypto) are not available there. What is actually
// needed is small and completely specified: encode a timestamp request for one SHA-256 digest,
// post it, check the authority accepted it, and read the signed time back out.
//
// What this file deliberately does NOT do is validate the token. It does not check the CMS
// signature or the certificate chain. That is not an oversight and it is not a weakness: the
// token is opaque evidence that gets stored and handed to an auditor, and the auditor's verifier
// (`pr anchor-verify`, which validates the chain against a bundled TSA root) is the thing whose
// opinion counts. A service that pronounced its own evidence valid would be adding no assurance
// and inviting the reader to trust the wrong party.
//
// Written as .js rather than .ts so tests/test_rfc3161_der.py can run this exact file under Node
// and compare its answer with Python's on a real token. A test against a copy of this code would
// prove nothing about what the service actually does.

// ---- minimal DER ----------------------------------------------------------------------------

function derLen(n) {
  if (n < 0x80) return Uint8Array.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, value) {
  const len = derLen(value.length);
  const out = new Uint8Array(1 + len.length + value.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(value, 1 + len.length);
  return out;
}

function cat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** Read one DER element at `pos`. Returns tag, the value slice, and where the next one starts. */
export function readTLV(buf, pos) {
  const tag = buf[pos];
  let i = pos + 1;
  let len = buf[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    // A 5-byte length would mean a token larger than any TSA emits; refusing is cheaper than
    // carrying a 32-bit overflow into a slice index.
    if (n === 0 || n > 4) throw new Error("unsupported DER length");
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++];
  }
  if (i + len > buf.length) throw new Error("DER element runs past the end of the buffer");
  return { tag, value: buf.subarray(i, i + len), next: i + len };
}

/** The elements directly inside a constructed element's value. */
export function children(value) {
  const out = [];
  let pos = 0;
  while (pos < value.length) {
    const el = readTLV(value, pos);
    out.push(el);
    pos = el.next;
  }
  return out;
}

// SEQUENCE { OID 2.16.840.1.101.3.4.2.3 (sha512), NULL }
//
// SHA-512 rather than SHA-256 because that is what the Python anchor sends (rfc3161-client's
// default), and one imprint algorithm across both implementations means one thing to test and
// one thing to explain. The verifier reads the algorithm out of the token either way, so this is
// about the two halves of the product behaving the same, not about what it can check.
const SHA512_ALG_ID = Uint8Array.from([
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
]);

// ---- request --------------------------------------------------------------------------------

/**
 * Encode arbitrary bytes as a positive DER INTEGER.
 *
 * Two rules, and getting either wrong produces a request that most authorities accept and some
 * reject with "bad request format", which is the worst kind of bug: it depends on random bytes,
 * so it fails perhaps one time in two hundred and looks like the authority being flaky. DER
 * INTEGERs are minimal (no leading 0x00 unless it is needed) and signed (a high bit in the first
 * byte means negative, so a 0x00 must be added). Prepending 0x00 unconditionally, which is the
 * obvious thing to write, breaks the first rule whenever the random value starts with a zero
 * byte. FreeTSA rejects exactly that.
 */
export function derInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const trimmed = bytes.subarray(start);
  if (trimmed[0] & 0x80) return cat(Uint8Array.from([0x00]), trimmed);
  return trimmed;
}

/**
 * TimeStampReq for one SHA-512 digest.
 *
 * certReq is TRUE so the authority embeds its signing certificate in the token. Without it the
 * auditor cannot build a chain to the bundled root and the timestamp degrades to "present but
 * unvalidated", which is the exact outcome this whole path exists to avoid.
 */
export function timestampRequest(digest, nonce) {
  if (digest.length !== 64) throw new Error("a SHA-512 digest is 64 bytes");
  const version = Uint8Array.from([0x02, 0x01, 0x01]);
  const imprint = tlv(0x30, cat(SHA512_ALG_ID, tlv(0x04, digest)));
  const nonceDer = tlv(0x02, derInteger(nonce));
  const certReq = Uint8Array.from([0x01, 0x01, 0xff]);
  return tlv(0x30, cat(version, imprint, nonceDer, certReq));
}

// ---- response -------------------------------------------------------------------------------

const OID_SIGNED_DATA = "2a864886f70d010702";   // 1.2.840.113549.1.7.2
const OID_TST_INFO = "2a864886f70d0109100104";   // 1.2.840.113549.1.9.16.1.4

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Pull the signed TSTInfo out of a TimeStampResp.
 *
 * The path is fixed by RFC 3161 and RFC 5652:
 *   TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo }
 *   ContentInfo   ::= SEQUENCE { contentType OID(signedData), [0] SignedData }
 *   SignedData    ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
 *   encapContentInfo ::= SEQUENCE { eContentType OID(id-ct-TSTInfo), [0] OCTET STRING }
 */
export function parseTimestampResponse(der) {
  const resp = children(readTLV(der, 0).value);
  if (!resp.length) throw new Error("empty timestamp response");

  const statusInfo = children(resp[0].value);
  const status = statusInfo.length ? statusInfo[0].value[statusInfo[0].value.length - 1] : 255;
  // 0 granted, 1 granted with modifications. Anything else is a refusal, and storing the body of
  // a refusal as though it were a timestamp is how a service ends up holding evidence of nothing.
  if (status !== 0 && status !== 1) {
    const text = statusInfo.length > 1 ? new TextDecoder().decode(statusInfo[1].value) : "";
    throw new Error(`the timestamp authority refused the request (status ${status}) ${text}`.trim());
  }
  if (resp.length < 2) throw new Error("the response carries no timestamp token");

  const contentInfo = children(resp[1].value);
  if (hex(contentInfo[0].value) !== OID_SIGNED_DATA) throw new Error("token is not a SignedData");
  const signedData = children(children(contentInfo[1].value)[0].value);
  // version, digestAlgorithms, encapContentInfo
  const encap = children(signedData[2].value);
  if (hex(encap[0].value) !== OID_TST_INFO) throw new Error("token does not encapsulate a TSTInfo");
  const tstInfoDer = children(encap[1].value)[0].value;

  // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
  const tst = children(readTLV(tstInfoDer, 0).value);
  // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }
  const imprint = children(tst[2].value);
  return {
    genTime: generalizedTimeToIso(new TextDecoder().decode(tst[4].value)),
    imprintHex: hex(imprint[1].value),
  };
}

/** "20260819054417Z" or "20260819054417.5Z" to the microsecond form Python writes. */
export function generalizedTimeToIso(gt) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d+))?Z$/.exec(gt.trim());
  if (!m) throw new Error(`not a DER GeneralizedTime: ${gt}`);
  const [, y, mo, d, h, mi, s, frac] = m;
  const micros = (frac || "").padEnd(6, "0").slice(0, 6);
  return `${y}-${mo}-${d}T${h}:${mi}:${s}.${micros}Z`;
}

// ---- the one call the service makes ---------------------------------------------------------

/**
 * Timestamp `rootBytes` with a public authority and return the receipt fields.
 *
 * Throws if the authority is unreachable, refuses, or returns a token for a different digest.
 * The caller falls back to a self-signed receipt rather than failing the anchor: a customer whose
 * chain is anchored with a weaker, honestly-labelled time is better off than one whose chain is
 * not anchored at all because a third party was having an outage.
 */
export async function trustedTimestamp(rootBytes, tsaUrl, fetchImpl = fetch) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", rootBytes));
  const nonce = crypto.getRandomValues(new Uint8Array(8));
  const req = timestampRequest(digest, nonce);

  const resp = await fetchImpl(tsaUrl, {
    method: "POST",
    body: req,
    headers: { "content-type": "application/timestamp-query" },
  });
  if (!resp.ok) throw new Error(`the timestamp authority answered ${resp.status}`);
  const der = new Uint8Array(await resp.arrayBuffer());
  const parsed = parseTimestampResponse(der);

  // The imprint is what ties the signed time to this specific chain. A token that covers a
  // different digest is worthless here and must never be stored as if it covered ours.
  if (parsed.imprintHex !== hex(digest)) {
    throw new Error("the timestamp covers a different digest than the one we sent");
  }
  return { genTime: parsed.genTime, tokenB64: b64(der) };
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
