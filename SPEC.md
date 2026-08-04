# Provenrail evidence format and verification protocol, v1

This specifies the wire format and the exact verification algorithm so that anyone can
build an independent verifier and confirm a record without trusting the agent, the Flight
Recorder server, or this implementation. All hashes are SHA-256 unless stated. All
signatures are Ed25519. All canonicalization is the subset of RFC 8785 (JCS) defined below.

Two reference implementations exist and are conformance-tested against each other on clean
and tampered bundles: the Python verifier (`pr verify`, full including RFC 3161 timestamp
validation) and a JavaScript verifier (`web/verify.js`, browser and Node via WebCrypto;
validates the chains, signatures, and Merkle anchors, and defers RFC 3161 CMS validation).
The hosted `/verify` page uses the JavaScript verifier to check fully client-side.

## 1. Canonicalization (JCS subset)

To hash or sign any structure, serialize it as follows:
1. Every string (object keys and string values) is Unicode NFC-normalized first. RFC 8785
   assumes already-normalized input; an independent verifier MUST apply NFC before
   serializing so that the same logical text (for example precomposed U+00E9 vs decomposed
   "e" + U+0301) produces one canonical byte sequence and one hash.
2. Object keys sorted by Unicode code point (ASCII field names only, so this equals JCS).
3. No insignificant whitespace; separators are `,` and `:`.
4. UTF-8 output. Non-ASCII string values are preserved raw (not escaped), per JCS.
5. Floating-point numbers are forbidden. Integers outside the range
   [-(2^53-1), 2^53-1] must be encoded as strings. This keeps hashing identical across
   language implementations.

`H(x)` below means `SHA-256(canonicalize(x))`, hex-encoded.

## 2. Client record

A record's signed content is every field except `record_hash` and `record_sig`:

```
content = {
  v: "1", stream_id, session_id, record_id, seq, prev_hash, ts_utc,
  pubkey,            // Ed25519 public key, raw 32 bytes, hex
  action_type, payload
}
record_hash = H(content)                       // hex
record_sig  = Ed25519_sign(privkey, canonicalize(content))   // hex
```

- `seq` is a monotonic integer starting at 0 within a stream.
- `prev_hash` is the previous record's `record_hash`, or 64 zeros for the genesis record.
- `ts_utc` is client-asserted and untrusted (its integrity is protected by the hash and
  signature, but its truthfulness relative to real time is only bounded by anchors).

Lifecycle records:
- genesis: `action_type = "lifecycle.session_start"`, `seq = 0`, `prev_hash = 0*64`.
- seal: `action_type = "lifecycle.session_end"`, `payload.session_hash = H([record_hash of
  every record with seq < seal.seq, in order])`.
- heartbeat: `action_type = "lifecycle.heartbeat"`.

## 3. Server receipt chain

When the sink receives a record it appends an independent receipt, keyed only on data the
sink controls:

```
recv_hash          = H(received_record)        // the full record as received, incl hash+sig
server_record_hash = H({ recv_seq, recv_ts, recv_hash, server_prev_hash })
```

- `recv_seq` is a monotonic integer from 0 per stream (arrival order).
- `server_prev_hash` is the previous `server_record_hash`, or 64 zeros for the first.
- Duplicates (same `recv_hash` already stored) are not re-appended; the original receipt
  is returned.

## 4. Anchor

A Merkle tree (RFC 6962) is built over the ordered list of `server_record_hash` leaves:
`leaf = SHA-256(0x00 || h)`, `node = SHA-256(0x01 || left || right)`, an odd final node is
promoted unchanged. The root is hex-encoded as `merkle_root`.

An anchor receipt is one of:
- `kind: "rfc3161"`: an RFC 3161 timestamp over `bytes.fromhex(merkle_root)`. Fields:
  `merkle_root`, `gen_time` (ISO UTC), `token_b64` (base64 of the TimeStampResp), `tsa_url`.
- `kind: "local"`: an offline anchor with no third-party trust. Fields: `merkle_root`,
  `gen_time`, `signature` (Ed25519 over `merkle_root + "|" + gen_time`), `anchor_pubkey`.

## 5. Client pin (optional)

A pin is a client-held, signed checkpoint of the sink head, used to detect a malicious
sink truncating the tail:

```
body    = { stream_id, recv_seq, server_record_hash, pinned_at, pubkey }
pin_sig = Ed25519_sign(privkey, canonicalize(body))
```

## 6. Bundle

```
{ format: "flightrecorder.bundle/1", stream_id, server_head,
  records: [ { recv_seq, recv_ts, recv_hash, server_prev_hash, server_record_hash, record } ],
  anchors: [ { anchor_seq, covers_up_to, receipt } ] }
```

## 7. Verification algorithm

A conforming verifier MUST recompute every value below from scratch and MUST NOT trust any
derived field present in the bundle. It reports VERIFIED only if no step fails.

1. Server receipt chain. For each record in `records` ordered by `recv_seq`:
   a. assert `recv_seq` equals its index (no gaps).
   b. recompute `recv_hash = H(record)`; assert it equals the stored `recv_hash`.
   c. recompute `server_record_hash = H({recv_seq, recv_ts, recv_hash, server_prev_hash})`
      using the previous record's `server_record_hash` (or 64 zeros); assert equality.
2. Client chain. A stream MAY hold multiple sessions (one per run; stream reuse across
   runs is the normal shape). Group client records by `session_id`, in order of first
   arrival; each session is an independent chain. Within each session, order by `seq`
   and for each record:
   a. recompute `record_hash`; assert equality (detects content edits).
   b. verify `record_sig` over `canonicalize(content)` with `pubkey` (detects forgery).
   c. assert one stable `pubkey` across the session (the key MAY differ between
      sessions: a device can rotate or be replaced between runs).
   d. assert `seq` is contiguous from 0 (gap = deletion/insertion).
   e. assert `prev_hash` equals the previous record's `record_hash` (broken link),
      with the session's first record linking to 64 zeros.
   f. assert the session's first record is a genesis; if a seal exists, recompute its
      `session_hash` and assert equality (detects interior truncation).
3. Arrival order. Per session, assert that session's client `seq` values appear in
   `records` in non-decreasing order with no duplicates (detects replay/reorder at the
   sink). Sessions themselves MAY interleave (two writers on one stream).
4. Anchors. For each anchor: rebuild the Merkle root over leaves with
   `recv_seq <= covers_up_to`; assert it equals `receipt.merkle_root`. Then:
   - rfc3161: assert the token's messageImprint equals the TSA-digest of
     `bytes.fromhex(merkle_root)`, and verify the CMS signature and certificate chain to a
     trusted TSA root. If the root is unknown, downgrade to a warning, do not pass it as
     trusted.
   - local: verify the Ed25519 signature with `anchor_pubkey`; report it as carrying no
     third-party trust.
5. Time. For records covered by a trusted anchor, treat the anchor `gen_time` as the
   authoritative upper bound. Flag (warning, since the hash already protects integrity)
   any `ts_utc` more than a small tolerance after that time.
6. Pin (if supplied). Verify `pin_sig`; assert the pinned `recv_seq` is present with the
   pinned `server_record_hash`. Absence is a truncation failure; a different hash is a fork.

### 7.1 Verdict classification (normative)

A verifier MUST report one of four results, derived only from the set of `fail` findings.
This separates "the recorded data was altered" from "the verifier was given the wrong inputs",
because conflating them produces false accusations of tampering against intact records.

- `verified`: no `fail` findings.
- `malformed`: at least one `fail` is a FORMAT-ERROR code. The input is not a Provenrail
  bundle (wrong file or wrong JSON shape), so no integrity claim is made either way.
  Format-error codes: `not_a_bundle` (the JSON is not an object), `bad_format` (an object
  without the recognized `format`).
- `empty`: not malformed, and the only `fail` is `empty` (a well-formed bundle with zero
  records). Nothing was recorded, or every record was stripped; there is nothing to have
  tampered with. Reported distinctly so an export-before-recording slip does not read as
  tampering.
- `unconfirmed`: not malformed, and EVERY `fail` is an ATTESTATION-MISMATCH code. The
  record's own chain, signatures, and inclusion proofs are intact, but a trust anchor the
  verifier supplied (a key) does not match the bundle: a wrong/stale key, or a proof from a
  different log or witness. This is NOT evidence of tampering. Attestation-mismatch codes are
  exactly the key-IDENTITY mismatches: `tlog_log_key_id_mismatch`, `tlog_cosig_key_id_mismatch`,
  `scitt_key_mismatch`.
- `tampered`: any other `fail` is present. The recorded data itself does not verify.

A key-identity mismatch is distinguishable from a forgery: the key id embedded in the proof
differs from the key id derived from the key the verifier supplied. A forgery keeps the
original key id and fails only the signature, which remains a `tampered`-class fail
(`tlog_log_key_invalid`, `tlog_cosig_invalid`, `scitt_receipt_invalid`). The CLI exit code is
0 for `verified` and non-zero for the other three.

## 8. Guarantees and limits

A clean VERIFIED result attests that the recorded client chain is internally consistent
and signed by one device key, that the sink received exactly those bytes in a consistent
order with no deletion or insertion, and that anchored records existed no later than the
anchor's trusted time. It does NOT attest completeness: a hostile agent can refuse to emit
an event before it is ever recorded, and no verifier can detect what was never written.
Defense against a sink that truncates the unanchored tail requires either frequent
anchoring or a client pin (step 6).

## 9. Transparency log (witness layer)

The anchor (section 4) bounds one stream's tamper window with a trusted timestamp. The
transparency log adds the layer above it: a per-account, append-only Merkle log whose
leaves are commitments to anchor receipts. Its purpose is to make a dishonest sink unable
to equivocate (present one anchor history to a customer and a different one to a regulator)
or to silently drop anchors it already published, without the customer trusting the sink.
That property comes from two RFC 6962 proofs an offline verifier recomputes (inclusion and
consistency) plus independent witness cosignatures on the log head.

Wire formats are the C2SP transparency-log specifications (tlog-checkpoint, signed-note,
tlog-cosignature) adopted verbatim for ecosystem interoperability. Only the leaf content
diverges: a Provenrail leaf commits to an anchor receipt, not to an artifact signature.

### 9.1 Leaf value

For each anchor compute:

```
anchor_commit  = SHA-256(canonicalize({stream_id, anchor_seq, covers_up_to, merkle_root,
                                        gen_time, kind, token_b64_or_sig}))
tlog_leaf_hash = SHA-256(0x00 || "flightrecorder.io/v1/tlog-leaf:" || anchor_commit)
```

`token_b64_or_sig` is `receipt.token_b64` when `kind == "rfc3161"`, else `receipt.signature`.
The domain label `flightrecorder.io/v1/tlog-leaf:` (UTF-8, no null terminator) makes tlog
leaf hashes structurally distinct from per-stream anchor Merkle leaf hashes even though both
use the RFC 6962 `0x00` leaf prefix, so a leaf can never be confused for or substituted by an
anchor leaf. Committing the full receipt (not just its Merkle root) binds each witness
cosignature to the exact receipt a verifier later checks, defeating receipt substitution.

### 9.2 Empty tree root

For an empty log the Merkle root is `SHA-256("")` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, never 64 zeros.

### 9.3 Origin

The origin line for an account-scoped log is `flightrecorder.io/v1/anchors/{account_id}`.
Self-hosted instances replace `flightrecorder.io` with their own FQDN. The origin string is
stable for the life of a log shard. A new shard (a different origin, starting at tree size 0)
is required only on log-key compromise or corruption.

### 9.4 Checkpoint body (C2SP tlog-checkpoint, verbatim)

```
{origin}\n{tree_size_decimal}\n{base64_standard(sha256_root_32_bytes)}\n
```

Standard RFC 4648 section 4 Base64.

### 9.5 Signed note wrapper (C2SP signed-note, verbatim)

The signature line marker is U+2014 followed by one space. Key id derivation:

```
key_id = SHA-256(key_name_utf8 || 0x0A || alg || ed25519_pubkey)[:4]
```

The log key signs the checkpoint body with `alg = 0x01`. A witness cosignature uses
`alg = 0x04` and signs the bytes
`"cosignature/v1\ntime " || posix_ts_decimal || "\n" || body`. The cosignature payload is
`key_id (4) || posix_ts_big_endian (8) || ed25519_sig (64)` = 76 bytes. Key lookup during
verification MUST use `key_name` as the primary identifier; a `key_id` that does not match
the pubkey found by name is a hard fail, never a silent skip. A verifier MUST skip (not fail)
a signature line whose algorithm byte it does not recognize, for forward compatibility.

### 9.6 Inclusion proof (bundle and API)

```json
{"kind":"tlog_inclusion","log_origin":"...","leaf_index":<int>,"tree_size":<int>,
 "proof_hashes":["<base64>", ...],"checkpoint":"<signed note UTF-8>"}
```

`proof_hashes` are the RFC 6962 PATH(leaf_index, tree_size) siblings, leaf to root,
base64-encoded 32-byte hashes.

### 9.7 Consistency proof

```json
{"old_size":<int>,"new_size":<int>,"proof_hashes":["<base64>", ...]}
```

The RFC 6962 PROOF(old_size, new_size) hashes (section 2.1.2).

### 9.8 Non-guarantees (normative)

A witnessed checkpoint DOES NOT guarantee, and this product MUST NOT claim:

1. Completeness. Records the sink never committed to any anchor are invisible to the entire
   witness system. No witness can detect what was never written.
2. Semantic correctness. Witnesses verify tree structure only, not the meaning of events.
3. Liveness. Anchoring latency and omission at ingestion are out of scope.
4. Absolute independence. Non-collusion of the configured witness quorum is an irreducible
   assumption; the customer must choose witnesses organizationally and jurisdictionally
   independent of the sink operator.
5. The unanchored tail. Events between the last cosigned checkpoint and now are covered by
   the per-stream client pin (section 5), not by witnesses.

### 9.9 Shard policy

Log-key compromise requires a new origin string (a new shard from tree size 0). Routine key
rotation is out of scope for v1 and also requires a new shard. A verifier receiving a bundle
that references multiple shards MUST verify each shard independently. The `--tlog-pubkey`
flag is mandatory when the origin is not the canonical `flightrecorder.io` prefix.

### 9.10 Algorithm agility

A verifier MUST skip cosignature lines with unknown algorithm bytes so future signature
algorithms (for example ML-DSA) can be added without breaking existing verifiers.

## 10. Bundle format extensions (bundle/1, additive)

The bundle format stays `flightrecorder.bundle/1`. New optional fields:

- `tlog_schema_version`: integer, present and equal to `1` on bundles produced after tlog
  support shipped. Its ABSENCE marks a legacy bundle; a verifier MUST NOT warn about missing
  tlog fields when it is absent.
- `anchors[i].tlog_inclusion`: an inclusion proof object (section 9.6), or absent.
- `tlog_consistency_proofs`: an array of consistency proof objects (section 9.7) over
  consecutive checkpoint sizes, or absent.

## 11. Verification algorithm extensions

### Step 7. Transparency-log inclusion

For each anchor carrying a `tlog_inclusion` field:

a. Recompute `anchor_commit` from the bundle's own anchor fields. If any required field is
   missing, fail with `tlog_inclusion_fail`.
b. Verify the inclusion proof against the root in the checkpoint body. Failure:
   `tlog_inclusion_fail`.
c. Parse the checkpoint note. Verify the log-key signature by `key_name` lookup then `key_id`
   consistency. Key id differs from the supplied key: `tlog_log_key_id_mismatch`
   (attestation-mismatch fail, verdict `unconfirmed`, see 7.1). Key id matches but the
   signature is bad: `tlog_log_key_invalid` (tampered-class fail). No configured log key:
   `tlog_log_key_unknown` (warn).
d. For each cosignature: look up `key_name` in the configured witness set. Unknown name:
   `tlog_cosig_unrecognized` (info, not counted). Known name but the supplied key's id does
   not match the cosignature: `tlog_cosig_key_id_mismatch` (attestation-mismatch fail, verdict
   `unconfirmed`, this is a wrong/stale verifier key, not a forgery). Known name, matching key
   id, bad signature: `tlog_cosig_invalid` (fail). Valid but `cosig_ts < anchor.gen_time`:
   `tlog_cosig_stale`
   (warn). Valid but `cosig_ts > verification_time + 300s`: `tlog_cosig_invalid` (fail). Valid
   and within bounds (and `cosig_ts >= verification_time - max_cosig_age`, default 30 days):
   `tlog_cosig_valid` (info).
e. Zero valid cosignatures from known keys: `tlog_inclusion_unwitnessed` (warn). At least one:
   `tlog_inclusion_witnessed_ok` (info).

### Step 8. Transparency-log consistency

For each entry in `tlog_consistency_proofs`, verify consistency between the two checkpoint
sizes. Any break is `tlog_consistency_fail` (fail).

### Badge mapping (normative)

- red: verdict `tampered` (see 7.1).
- amber (not a bundle): verdict `malformed`.
- amber (not confirmed): verdict `unconfirmed` (record intact, a supplied key did not match).
- amber: no fail and no tlog inclusion present (RFC 3161 or local anchor only).
- amber-proofs: no fail and `tlog_inclusion_unwitnessed` present (valid proof, zero witnesses).
- green: no fail and `tlog_inclusion_witnessed_ok` present (at least one valid cosignature
  from a configured witness key).

A bundle produced for an Audit Trail plan MUST carry `tlog_schema_version: 1` and a
`tlog_inclusion` on every anchor; for that tier the verifier treats
`tlog_inclusion_unwitnessed` as a fail, and the scheduler refuses to finalize an un-cosigned
checkpoint when a witness threshold of one or more is configured.

## 12. Agent identity registry (Know Your Agent)

The base verifier confirms records are signed by one consistent device key. Section 12 binds
that key to a named agent so a verifier can confirm "signed by the key registered for agent X",
not merely "signed by some key".

### 12.1 Assertion

```
body      = {account_id, agent_id, pubkey, status, registered_at, revoked_at}
assertion = {...body, sig}    where sig = Ed25519(registry_key, canonicalize(body))
```

`pubkey` is the hex Ed25519 device key. `status` is `active` or `revoked`. The assertion is
self-contained and travels in the bundle under `agent_registry` (an array, one entry per
device key present). The registry key is the registry operator's signing key; its public key
is published (the verifier is given it as `--registry-pubkey`).

### 12.2 Verification (step 9)

If the bundle has no `agent_registry`, or no registry public key is supplied, this step is
skipped (it reports `kya_registry_unchecked` info when assertions are present but unverifiable).
Otherwise, for each assertion: verify `sig` over `canonicalize(body)` with the registry key
(`kya_assertion_invalid`, fail, on failure). Then for each distinct device `pubkey` in the
client records: if a valid active assertion covers it, report `kya_registered` (info); if a
valid assertion covers it but is `revoked`, report `kya_key_revoked` (warn, since older records
may legitimately predate revocation); if no valid assertion covers it, report
`kya_key_unregistered` or `kya_unregistered` (warn). The registry never turns a clean bundle
red on absence; only a forged assertion is a hard fail.

### 12.3 Boundary

The registry proves a key was registered to an agent name by the holder of the registry key.
It does NOT prove the agent behaved correctly, nor that the operator named the agent truthfully.
It upgrades "signed by some key" to "signed by the key registered for agent X", and no more.

## 13. Committed policy (active guardrails)

When a session runs under an active policy, the policy is committed into the signed
session-start (`lifecycle.session_start`) record so a verifier can prove which guardrails were
in force and that the run is consistent with them.

### 13.1 Commitment

The session-start `payload.meta` carries:

```
meta.policy        = the policy object, canonicalizable (the spend cap is a decimal STRING,
                     since record canonicalization forbids floats)
meta.policy_sha256 = sha256_hex(canonicalize(meta.policy))
```

Because the session-start record is hash-chained and signed by the device key, any later edit to
the committed guardrails breaks the record signature AND the `policy_sha256` match.

### 13.2 Policy object

```
policy = {rules: [rule, ...], session_spend_cap_usd: <decimal string|null>,
          budgets?: [budget, ...]}
rule   = {id, effect, event_type, tool, resource, provider, arg_contains, max_per_session, reason}
budget = {id, scope, limit_usd: <decimal string>, warn_at: <decimal string>}
effect in {deny, require_oversight, limit}
scope  in {session, day, total}
```

`arg_contains` is a regex over the call's argument text and is a CONTENT gate. `max_per_session`
bounds how many matching events a `limit` rule permits per session.

`budgets` is OMITTED when empty, so a policy written before budgets existed hashes identically.
A budget denies a `model_call` whose estimated cost would push spend past `limit_usd` at its
scope; `session_spend_cap_usd` is the legacy shorthand for a session-scoped budget. `warn_at` is
a fraction of the limit at which an allowed call additionally carries a `warning` (recorded in
the `policy.decision` payload); it never changes the verdict. Costs are estimates derived from
recorded `usage` and a price table, and are display values only: they are never inputs to a hash
or a signature.

### 13.3 Verification (step 10)

If no `meta.policy` is present, the step is skipped. Otherwise:

a. Recompute `sha256_hex(canonicalize(meta.policy))`. If it differs from `meta.policy_sha256`,
   fail with `policy_commit_mismatch`.
b. Build a re-verifiable policy by dropping rules with a non-empty `arg_contains` (their input,
   the argument text, is hashed out of the bundle) AND budgets whose scope is not `session` (a
   `day` or `total` budget was evaluated against spend recorded in other sessions, which this
   bundle does not contain; replaying it here would manufacture false findings out of missing
   history). Replay the committed deny/limit/spend rules
   over the recorded events in emission order, maintaining spend and per-rule counts and treating
   a `human_oversight` record as satisfying `require_oversight`.
c. For each EXECUTED enforceable record (`model_call`, `tool_call`, `mcp_call`, `data_access`)
   that the re-verifiable policy would have denied, report `policy_not_enforced` (warn): a stated
   guardrail did not actually block a recorded action.
d. With zero such violations, report `policy_verified` (info), noting the count of content-gate
   rules and cross-session budgets that were enforced live but cannot be re-checked offline.

### 13.4 Boundary

This proves the recorded run is consistent with the committed, re-verifiable guardrails. It does
NOT prove completeness (a bypassed dispatch is not constrained), and content-gate rules are
attested as enforced, not re-verified. Like the rest of the product, it is a checkable property
framed without overclaiming.

## 14. Coherence signals (non-normative)

A verifier MAY emit heuristic `warn`/`info` signals that point a reviewer at structural oddities:
`nonmonotonic_ts`, `time_gap`, `duplicate_record_id`, `usage_missing`, `no_governance`,
`seal_count_mismatch`. These are review prompts only. They MUST NOT change the cryptographic
verdict (a clean bundle stays clean, a tampered bundle stays failed); they never constitute a
`fail`. The authentic/untampered decision rests solely on sections 1 to 13.

## 15. Conformance vectors (normative for interoperability)

`tests/vectors/` holds frozen golden bundles and a `manifest.json`. For each vector the manifest
records `expect_ok` (boolean). A conformant verifier MUST agree with `expect_ok` on every vector:
a clean result on the untampered vectors and a rejection on every tampered one. The manifest also
records a `defining_code` (the reference verifier's canonical finding for that case); emitting it
is RECOMMENDED but not required for interoperability. The vectors are the portable conformance
test any independent verifier implementation should pass. See `tests/vectors/README.md`.

## 16. Trusted-time roots (operational)

A TSA token is only trusted when the verifier holds the TSA's root certificate. Provenrail
bundles the roots of the TSAs it anchors against. Operators MAY register additional roots
(`trust.add_root(host_substring, cert)` or `pr verify --tsa-root host=cert.pem`) to verify tokens
from a TSA that is not bundled; registered roots take precedence over bundled ones. A
`MultiTSAAnchor` MAY anchor against several TSAs with first-success failover; this is an
availability property and does not change verification, which still validates exactly one trusted
timestamp per anchor. Multi-token (quorum) anchoring is out of scope for v1.

## 17. Selective-disclosure redaction

Reconciles an immutable audit trail with the right to erasure / minimum-necessary disclosure. A
field MAY be recorded as a salted commitment instead of cleartext.

### 17.1 Commitment

```
commit = SHA-256( salt_bytes || canonicalize(value) ),  salt = 32 random bytes
```

It appears in the record payload, in place of the value, as:

```
{ "__fr_redacted__": { "v": 1, "alg": "sha256", "commit": <hex> } }
```

The commitment is part of the signed, hash-chained record, so steps 1 to 2 already prove it is
authentic and untampered. The cleartext is NEVER sent to the sink. The opening (the value and its
salt) is held only by the operator, in a keystore of shape
`{ "format": "flightrecorder.openings/1", "openings": { <commit>: { "alg", "salt", "value" } } }`.
Under store-hash-not-content, a content field that contains a commitment is stored as a skeleton
that keeps the commitments in place and drops the non-redacted leaves (no sibling cleartext),
while the record hash is still computed over the full value.

### 17.2 Verification (step 12)

For every commitment found in the records: if the supplied openings contain a matching opening,
recompute `SHA-256(salt || canonicalize(value))` and compare to `commit`. A match counts as a
verified disclosure; a mismatch is `redaction_disclosure_invalid` (fail: a forged disclosure). A
commitment with no opening is withheld or erased and is NOT an error. A `redaction_summary` (info)
reports the totals. Both the Python verifier and `web/verify.js` implement this identically and
are conformance-tested (`commitFor` agreeing byte for byte, including on non-ASCII values).

### 17.3 Disclosure and erasure

To DISCLOSE, reveal the opening; any verifier confirms it opens the commitment. To ERASE, destroy
the opening: the high-entropy secret salt makes the commitment non-reversible even for a
low-entropy value, so the field becomes permanently unrecoverable while the record stays complete
and verifiable.

### 17.4 Boundary

Erasure is cryptographic, not a promise that no copy was ever made elsewhere: a party who already
saw a disclosed value still knows it. What is guaranteed: the sink never held the cleartext, and
once the opening is destroyed the record itself no longer reveals the value, with the audit trail
remaining tamper-evident and verifiable throughout.

## 18. SCITT-aligned COSE receipts (standards interop)

Each transparency-log inclusion MAY also be expressed as a COSE_Sign1 receipt so that a Provenrail
proof is verifiable by the broader IETF SCITT / COSE ecosystem, not only by this verifier. This is
a faithful PROFILE of the in-progress drafts `draft-ietf-scitt-architecture` (Transparency Service +
Receipt) and `draft-ietf-cose-merkle-tree-proofs` (the RFC9162_SHA256 verifiable data structure),
frozen here; it is not a claim of conformance to a finished RFC. CBOR is canonical per RFC 8949
section 4.2.1 (the codec in `cbor.py` is conformance-tested byte-for-byte against the reference
`cbor2` library).

### 18.1 Receipt structure

A receipt is a tagged `COSE_Sign1` (CBOR tag 18) signed by the Transparency Service key (the same
Ed25519 tlog/identity key that signs checkpoints, SPEC section 9):

```
COSE_Sign1 = [ protected: bstr, unprotected: map, payload: bstr, signature: bstr ]
protected (a CBOR map, bstr-wrapped) = {
   1: -8,                       ; alg = EdDSA (Ed25519)
   4: <TS public key, 32 bytes>,; kid
 -111: 1,                       ; verifiable data structure = RFC9162_SHA256
   15: { 1: "provenrail.io",    ; CWT claims: iss
         2: <stream_id> }       ;             sub
}
payload  = <Merkle tree head / root, 32 bytes>    ; the signed tree head
unprotected = { -222: { -1: [ <inclusion_proof_bstr> ] } }   ; verifiable proofs / inclusion
inclusion_proof_bstr = CBOR([ tree_size, leaf_index, [ <path hash bstr> ... ] ])
```

The signature is Ed25519 over `Sig_structure = CBOR([ "Signature1", protected_bstr, h'' , payload ])`
(RFC 9052). The leaf committed to is the RFC 6962 tlog leaf for the anchor commit of SPEC section 9.

### 18.2 Verification (step 13)

For every anchor carrying a `scitt_receipt`: (1) confirm it is a `COSE_Sign1` with `alg = -8` and the
RFC9162_SHA256 VDS; (2) verify the EdDSA signature over `Sig_structure` against the TS public key
(supplied as `--tlog-pubkey`); (3) recompute the RFC 6962 root from the anchor-commit leaf and the
embedded inclusion proof and confirm it equals the signed `payload`. A present-but-forged receipt is
a hard fail (`scitt_receipt_invalid`); a present receipt with no known TS key is surfaced as info
(`scitt_receipt_present`); verified receipts report `scitt_receipt_ok`. A receipt whose inclusion
proof recomputes but whose COSE signature fails ONLY because the supplied `--tlog-pubkey` key id
differs from the receipt's key id is `scitt_key_mismatch` (attestation-mismatch fail, verdict
`unconfirmed`, see 7.1): a wrong/stale verifier key, not a forgery. A forged receipt keeps its key
id and stays `scitt_receipt_invalid`. The receipt carries no trust beyond the tlog it re-expresses;
it is an interoperability surface, not a new guarantee.

## 19. Bitcoin anchoring via OpenTimestamps (public, party-independent time)

A transparency-log checkpoint root MAY additionally be anchored in Bitcoin via OpenTimestamps. This
binds the log's state to proof-of-work history that depends on no party Provenrail controls and that
a latecomer cannot manufacture: a confirmed proof shows the stamped digest existed before a specific
Bitcoin block was mined (proof of existence / anti-backdating). It does not prove completeness, and a
proof carrying only pending calendar attestations is not yet confirmed in Bitcoin.

### 19.1 Proof format

A detached OpenTimestamps proof (`.ots`) is parsed exactly per the OpenTimestamps serialization
(magic `\x00OpenTimestamps\x00\x00Proof\x00` + 8 magic bytes, varuint major version 1, the file hash
op + digest, then a tree of operations). Supported operations: crypto `sha1` (0x02), `ripemd160`
(0x03), `sha256` (0x08); binary `append` (0xf0), `prepend` (0xf1); unary `reverse` (0xf2), `hexlify`
(0xf3). Attestations: Bitcoin block header (tag `0588960d73d71901`, payload = varuint block height),
pending calendar (tag `83dfe30d2ef90c8e`, payload = varbytes URI). The parser in `ots.py` is
dependency-free and is conformance-tested against the reference `opentimestamps` library
(`tests/test_ots.py`), with a frozen real proof locked as a vector.

### 19.2 Verification

Replay the operations from the stamped digest (which MUST equal the SHA-256 of the anchored data).
At each Bitcoin attestation, the value reached is that block's Merkle root (internal byte order; the
verifier also accepts the reversed/explorer order). A Bitcoin attestation is **confirmed** only when
the replayed root matches a Bitcoin block header the verifier is given (`--block-root
height=merkle_root`, from your own node or a pinned header). With no header supplied, the proof is
reported as structurally valid and Bitcoin-attested but NOT `ok`: the verifier will not assert a
Bitcoin fact it did not check. `pr ots-verify` performs this offline.

### 19.3 Bundle integration (step 14)

A bundle MAY carry `ots_proofs`: a list of `{tree_size, root_hex, ots_b64}`, each an OpenTimestamps
proof whose stamped file is the raw checkpoint Merkle root (so the proof's file digest equals
`SHA-256(root)`). `verify_bundle` (and `web/verify.js`) verify each offline against an optional
`bitcoin_headers` map (`--bitcoin-header height=merkle_root`): a proof that does not commit to the
stated root (`ots_wrong_target`) or that contradicts a supplied header (`ots_block_mismatch`) is a
hard fail; a header-confirmed proof reports `ots_bitcoin_confirmed`; an attested-but-unchecked proof
reports `ots_bitcoin_attested`; a still-pending proof reports `ots_pending`. None of the non-confirmed
states fail the bundle, because Bitcoin confirmation legitimately lags by hours. Both the Python and
JavaScript verifiers implement this identically and are conformance-tested to agree
(`tests/test_js_verifier.py::test_js_verifier_ots_conformance`), keeping Bitcoin verification inside
the two-implementation lockstep.

### 19.4 Status and scope

Shipped: offline `.ots` parsing and verification in both verifiers (`ots.py`, `web/verify.js`,
`pr ots-verify`), and bundle integration (step 14). Planned (sequenced): calendar submission and proof
upgrade (network), and server-side emission of `ots_proofs` once a checkpoint root is stamped via
standard OpenTimestamps tooling.
