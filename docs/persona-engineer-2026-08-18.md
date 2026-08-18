# Provenrail Technical Evaluation - Staff Engineer Persona
**Date:** 2026-08-18  
**Evaluator:** Dev (fictional), staff engineer, AI platform team  
**Repo:** /Volumes/T7/Projects/AgenticTools/flightrecorder  
**Stance:** hostile-productive; looking for the hole

---

## Narrative

I read SPEC.md before the landing page. That already tells me something: the spec exists,
is version-numbered, and the wire format is actually specifiable. Most audit-log products
cannot say that. The canonicalization section (JCS subset with explicit NFC normalization,
floats forbidden, integers outside 2^53 as strings) is the kind of detail that only comes
from someone who actually tried to make two implementations agree. That is a good sign.

The threat model in README.md and section 8 of SPEC.md is stated honestly: the adversary
is the agent or a prompt-injection of it. Completeness is listed as "No, never claimed" in
a table directly alongside the things that ARE guaranteed. Machine-owner protection is "No"
with the reason in the table. That is not a disclaimer buried in a footnote; it is the
second row from the bottom. Good.

I then went looking for where it overstates. There is one real one. Everything else is
honest or better than expected.

---

## Walk-through Findings

### 1. Spec completeness: can a third party build a second verifier?

Yes, with effort. The spec covers canonicalization byte-for-byte (section 1), the exact
hashing and signing contract (section 2), the server re-chain algorithm (section 3), the
Merkle anchor construction with RFC 6962 leaf/node formulas explicit (section 4), the
transparency-log wire format in C2SP signed-note and tlog-checkpoint verbatim (section 9),
SCITT COSE layout (section 18), and OTS verification (section 19). The verification
algorithm (section 7) is step-by-step and normative.

What is missing from the spec itself: no formal grammar for the JSON fields (a strict
implementer has to read the Python source to know the exact field names), no statement of
whether extra unknown fields are ignored or rejected (the Python verifier ignores them, but
this is not stated), and no test-vector format explanation outside tests/vectors/README.md
(which is not linked from SPEC.md). These are nits, not blockers.

The conformance vector suite (tests/vectors/, 13 vectors in manifest.json, matching what
conformance.html claims) covers: clean chain, payload tamper, record deletion, reorder,
bad signature, no anchor, multi-session, witnessed tlog, SCITT valid/forged, redacted
disclosed/forged, and a legacy backward-compatibility vector. A third-party verifier can
be validated against them. This is real.

**Finding:** Spec is specifiable. A second implementation is possible. The missing formal
grammar is an inconvenience, not a correctness gap.

### 2. Device key: what it buys and what it does not

The device key (Ed25519, client-held, raw bytes in `.provenrail.key`) signs every record.
The server chains independently, hashing the full received bytes including the client
signature. These are two independent chains over the same data.

What the device key buys: the server cannot forge client records, because the server does
not hold the private key. A malicious sink can truncate the tail or refuse to export, but
cannot silently insert or alter records that were already received and re-chained.

What it does not buy:

**Key compromise.** If the private key file is exfiltrated (it lives in the project root,
gitignored, but plaintext on disk), an attacker with key + network access to the sink can
sign arbitrary records that will verify as authentic. The KYA registry (SPEC section 12)
supports revocation: a revoked assertion yields `kya_key_revoked` on verification, which
is a warn not a fail, and a human reviewer sees it. But revocation is a registry operation,
and the registry key is held by "the registry operator" (Provenrail in the hosted case,
whoever holds it in self-hosted), so key-compromise response requires an out-of-band
registry update. The spec is honest: section 12.3 says "It upgrades 'signed by some key'
to 'signed by the key registered for agent X', and no more." No overclaim here.

**Key rotation.** SPEC section 9.9: "Routine key rotation is out of scope for v1 and also
requires a new shard." A new shard means a new log origin, starting from tree size 0, which
breaks the continuous witnessed history. For an enterprise that cares about a multi-year
verified chain, this is a real operational gap. The key MAY differ between sessions (section
7, step 2c), so an uncompromised key swap is survivable at the per-stream level. It is the
transparency-log shard (the per-account append-only Merkle log over anchors) that requires
continuity and breaks on rotation.

**A signing agent.** Nothing prevents the SDK from signing whatever payload the agent
constructs before calling `record()`. The audit trail is of what the agent told the SDK,
not of what the agent actually did. The sidecar (capturing model API egress at the proxy
layer) is the answer to this, and it is described honestly: "its strength equals the egress
control around it."

**Assessment:** The device-key architecture is correctly designed for the stated threat
model. The gap is operational (rotation is a shard break) and the README table names it
(machine-owner = No). No overclaim.

### 3. Completeness gap: where is it stated vs. where are the strong claims?

SPEC section 8: "It does NOT attest completeness: a hostile agent can refuse to emit an
event before it is ever recorded, and no verifier can detect what was never written."

README table (directly beside the tamper guarantee): "Completeness: No, never claimed."

index.html line 198: "record is immutable and verifiable once it reaches the sink.
Completeness is never claimed."

FAQ answer (index.html): "However, a hostile agent that simply does not call the SDK at
all will not appear in the record... This limitation is a documented part of the threat
model, not fine print."

security.html: The Limitations section is its own heading. "Completeness" is a named card.

This is the most transparent I have seen a product be about the single most important
limitation of in-process capture. I have read products that bury this in a 6-point tooltip.
This one puts it in a bolded table row, in the FAQ, in the spec, and in its own security
page section.

**Finding:** Completeness gap is stated plainly where the strong claims are made. No
overclaim.

### 4. Sink trust: what does a malicious sink survive?

**Malicious sink (truncate tail):** The unanchored tail (events after the last cosigned
checkpoint) is vulnerable to truncation. Defense: client pin (section 5), which the
verifier checks in step 6 - a missing pinned recv_seq is a truncation failure. With pin +
frequent anchoring this attack window is bounded.

**Malicious sink (equivocate on anchor history):** Defended by the transparency log and
witness cosignatures. A witness refuses to cosign any checkpoint that is not a
consistency-proved extension of the last one it cosigned. A sink cannot get two divergent
histories both cosigned without compromising the witnesses. SPEC section 9.8 is explicit:
"Non-collusion of the configured witness quorum is an irreducible assumption."

**Malicious sink (forge records):** Cannot, because the server does not hold the device key.

**Malicious client (compromised key + sink access):** Can sign arbitrary records that will
verify as authentic. The server receipt chain re-chains whatever it receives, so a coherent
fake session signed by the compromised key would verify. KYA revocation is the defense;
see finding 2 above.

**Assessment:** The model is internally consistent. The trust assumptions are named
(sections 8 and 9.8). No overclaim.

### 5. Witness layer: real or theater?

This is the strongest finding.

The code exists: `LocalWitness` (in-process, for demos), `WitnessClient` (C2SP
tlog-witness HTTP protocol, for real remote witnesses), and `StandaloneWitnessApp` (a
FastAPI witness server you can run on separate infrastructure). The witness logic is
correct: it verifies the consistency proof before cosigning, refuses a fork or a rollback,
and persists seen state so it cannot be reset.

The demo (`pr demo`) runs an in-process LocalWitness explicitly labeled as "purely to
demonstrate." The `PersistentWitness` class (witness.py:212) carries the comment: "An
UNPINNED witness accepts any note and therefore provides no real protection; production
witnesses MUST pin their logs."

The problem: for the hosted service, security.html says "cosigned by independent witnesses"
on Builder and higher plans. The docker-compose.yml has no witness configured. The server
`create_app()` accepts `tlog_witnesses: list | None = None`. The hosted deployment would
configure this, but there is no evidence in the repo of what that witness is or who
operates it.

If the "independent witness" for the hosted service is a second process on separate
infrastructure still operated by Provenrail (same legal entity, same cloud account), the
anti-equivocation property is much weaker than the phrase "independent witnesses" implies.
SPEC section 9.8 says the customer "must choose witnesses organizationally and
jurisdictionally independent of the sink operator." The product cannot make that choice for
the customer and then also call the result "independent."

The honest statement would be: "We run a reference witness on separate infrastructure. You
can point a second verifier you control at the tlog checkpoint endpoint independently. For
true organizational independence, run your own witness or use a community witness network."

**Finding (SEVERITY: MEDIUM, not a bug but a marketing-precision gap).**  
File: web/security.html, the "Witnessed" card.  
Current: "cosigned by independent witnesses."  
More accurate: "cosigned by a witness on separate infrastructure; for organizational
independence, the SPEC and tooling support third-party witnesses."  
Legal exposure: calling a first-party-operated process "independent" in a marketing context
is a misrepresentation claim waiting for an enterprise buyer's legal team to notice.

### 6. Anchor-only service vs RFC 3161 / OpenTimestamps

The question a competent evaluator will ask immediately: "You ask me to POST you a hash
root and you sign it. Why do I need you rather than a free RFC 3161 TSA (freetsa.org, DFN,
DigiStamp) or OpenTimestamps?"

**Honest answer:**

A bare RFC 3161 call gives you: a TSA signature on your hash at time T. Nothing else. You
get no history, no append-only audit of the anchor sequence, and no equivocation
protection. If you send the same hash to the same TSA twice with different timestamps, both
tokens are valid; there is nothing to tell you one was produced later by someone who
rewound the clock on your audit trail.

Provenrail's anchor-only service (/v1/anchors) gives you: (1) RFC 3161 trusted timestamp
(same), plus (2) that anchor is added to a per-account, append-only RFC 6962 Merkle log
over all your anchors, with inclusion and consistency proofs that let you or a third party
verify the anchor history was not silently modified, and (3) witness cosignatures on the
log head so the history cannot be silently forked or rolled back without compromising the
witnesses, and (4) SCITT COSE receipts for standards-ecosystem interoperability.

**OpenTimestamps** adds Bitcoin block anchoring (accumulating public history) but gives you
none of the per-anchor append-only log, no equivocation protection, and requires waiting
for Bitcoin block confirmation (minutes to hours vs. seconds for RFC 3161).

The real value proposition is items 2 and 3: the witnessed append-only anchor history. A
free RFC 3161 TSA does not provide that. Provenrail's service provides it, with the caveat
that the "independence" of the witness is subject to finding 5 above.

**Assessment:** The value is real but the honest pitch is narrower than the marketing
implies. The anchor-only service is not primarily about timestamps (RFC 3161 is
commoditized); it is about the witnessed append-only log over anchor history. That is a
legitimate differentiator vs. bare RFC 3161 or OTS, and the MOAT.md document says so
honestly (section 1: "Our sharpest message, 'trust no one, not even us,' is a real wedge
but a temporary one"). The internal documents are more honest than the marketing. No legal
exposure here, but a sharp evaluator will see through the framing quickly.

### 7. Two-implementation lockstep: verified

Ran: `python -m pytest tests/test_js_verifier.py -v`

Result: 21 passed, 1 skipped. The skipped test is `test_js_verifier_ots_conformance`,
skipped because it requires a network call to retrieve a Bitcoin block header (it is an
offline-vector test, but the header fetch is live). This is correctly skipped in a CI
environment; the vector fixture exists and is tested against the reference OTS library
elsewhere.

The passing tests cover: clean bundle, tlog conformance, SCITT conformance, redaction
conformance, wrong-key cases (unconfirmed not tampered), every frozen vector in the
manifest, policy replay, policy edit detection, unenforced policy detection, spend cap
agreement, cost estimation parity between Python and JS, float-in-record handling,
coherence signals, null anchors handling, finding-code agreement on clean bundles, every
malformed shape, browser-verifier never-throws, and contradictory server_head detection.

This is a real two-implementation contract, not a self-check. The lockstep claim is true.

Ran: `python -m pytest tests/ -x -q`  
Result: 896 passed, 2 skipped.

### 8. Conformance vectors: frozen, real, count correct

The conformance.html page claims "13 frozen vectors." The manifest.json has 13 entries.
The vectors directory has 14 JSON files (the 14th is `legacy_0_1_0.json`, which IS in the
manifest as the backward-compatibility vector). Count is correct.

The vector generator (`tests/vectors/_generate.py`) asserts each vector reaches its
expected verdict before writing the file, so regeneration fails loudly on any verification
behavior change. The vectors are derived from a single clean bundle by single, explicit
mutations (not from re-running the SDK), so they are stable across implementation changes
that do not change verification behavior.

**Finding:** Vectors are real and frozen. The backward-compat vector for v0.1.0 is a
genuine forward-compatibility test, not padding.

### 9. API docs vs actual endpoints

Checked docs.html references against app.py routes:

- `/v1/streams/{id}/export.ndjson` - present at app.py:1027
- `/v1/anchors` (POST) - present at app.py:568
- `/v1/streams/{id}/export` - present at app.py:656
- `/v1/members` - present at app.py:1165
- `/v1/sso/config` - present at app.py:1274
- `/v1/sso/login` - present at app.py:1303
- `/v1/tlog/{account_id}/checkpoint` - present at app.py:1391
- `/v1/tlog/{account_id}/inclusion/{leaf_index}` - present at app.py:1404
- `/v1/tlog/{account_id}/consistency/{old_size}/{new_size}` - present at app.py:1420
- `/v1/verify` (POST) - present at app.py:1092

No endpoints documented but missing. No routes present but undocumented that would create
a surprise surface.

**Finding:** API docs match the code. No gap.

### 10. Legal exposure for a sole proprietor

The COMPLIANCE.md disclaimer is correct: "Provenrail is evidence tooling, not a compliance
certification." The index.html and security.html both carry the disclaimer that this is not
legal advice or a compliance guarantee.

The EU AI Act FAQ answer on the page is accurate as of today's date (2026-08-18): Art. 12
deferred to 2027-12-02 by Regulation (EU) 2026/1744. Art. 50 transparency obligations from
2026-08-02 are correctly noted as not deferred.

The HIPAA claim ("maps evidence to 164.312(b); you remain the covered entity") is correctly
structured to avoid BAA exposure: it makes a technical mapping claim, not a certification
claim, and explicitly states the operator owns compliance.

**Finding:** No overclaim into certification territory. The EU AI Act timeline is correctly
stated. The HIPAA mapping claim is correctly scoped. Legal exposure is low.

One nuance: the "independent witnesses" language on security.html (finding 5) is the only
line that could become a misrepresentation claim if a buyer relied on it for a compliance
audit and then discovered the witness was first-party operated.

---

## Summary Table

| Finding | Severity | File:Line | Nature |
|---|---|---|---|
| Witness "independent" language overstates operational reality | Medium | web/security.html "Witnessed" card | Marketing precision gap; correctible |
| Device key rotation requires shard break (no key rotation in v1) | Low-medium | SPEC.md:292 | Documented limitation, not hidden |
| Anchor-only service pitch leads with timestamps, not append-only log history (actual differentiator) | Low | web/docs.html, index.html | Framing issue; not false |
| OTS test skipped (network dependency) | Info | tests/test_js_verifier.py:test_js_verifier_ots_conformance | Skip is correct; not a bug |
| Missing formal JSON field grammar in SPEC | Info | SPEC.md | Nit for third-party implementers |

---

## Verdict

### (a) Adopt, build in-house, or walk?

**Adopt the library and verifier. Do not rely solely on the hosted service for witness independence.**

Two sprints to build the base chain is accurate for the hash chain + RFC 3161 anchor. But
the SCITT COSE receipts, the C2SP tlog-checkpoint and signed-note protocol, the consistency
proof verification, the two-implementation lockstep, and the frozen conformance suite are
not two sprints. They are two months and a non-trivial amount of protocol archaeology. The
SPEC is specific enough that a second implementation is possible, which means I would not
be locked in, but the build cost is real.

The code itself is clean. 896 tests pass. The verifier finds what it claims to find. The
spec matches the implementation. I am not worried about the crypto being sloppy.

What I would do: adopt the open-source Python library and verifier for our own
infrastructure. Self-host the sink (it is Apache 2 / AGPL, we can run it). Point it at a
real RFC 3161 TSA. For witnesses, run our own `pr witness` instance on separate
infrastructure we control, plus point at a community witness if one becomes available in
the transparency.dev ecosystem. I would not pay for the hosted service primarily for
witness "independence" until that witness is organizationally external.

### (b) Single claim I trust least

**"Cosigned by independent witnesses" (security.html).**

Every other claim I checked was either exactly true or conservatively stated. This one
conflates "on separate infrastructure" with "independent," and the SPEC itself says the
right thing (section 9.8 tells the customer they must choose organizationally independent
witnesses). The product page does not. For a sole proprietor with no LLC, if an enterprise
buyer's legal team reads "independent witnesses" into a compliance story and later discovers
the witness is first-party operated, that is the exposure.

### (c) What would flip to full adopt including hosted service

Three things, in order:

1. **Name the witnesses.** Publish who the Builder-tier witnesses are, their key IDs, and
   how they are organizationally separated from Provenrail. If they are genuinely
   independent entities with separate legal and operational structures, say so explicitly.
   If they are currently first-party (separate process, same operator), say that too and
   give a timeline for community witnesses. The SPEC and tooling support this; the
   marketing just needs to catch up.

2. **Key rotation without a shard break.** This is a v1 limitation that matters for
   long-running enterprise deployments. A log rotation ceremony (transition period where
   both shards' endpoints are served) would remove the operational anxiety. SPEC section
   9.9 documents this is out of scope; it needs to be a v2 priority.

3. **A public anchor-log endpoint.** Let anyone fetch the tlog checkpoint for my account
   without authentication (`/v1/tlog/{account_id}/checkpoint` currently requires... let me
   check: it does not seem to require auth in app.py:1391). If this endpoint is genuinely
   public, document it explicitly as the "external monitor" URL so a customer's auditor can
   independently poll the checkpoint and compare it to their local bundle. That would close
   the organizational-independence argument without needing a third party to operate a
   witness.

---

*This evaluation is a persona exercise. All code readings and test runs are from the actual
repository. Findings are based on direct inspection of SPEC.md, README.md, MOAT.md,
web/conformance.html, web/security.html, web/docs.html, web/index.html,
src/provenrail/server/app.py, src/provenrail/server/witness.py,
tests/test_js_verifier.py, and tests/vectors/. Test suite executed against the live
repository at /Volumes/T7/Projects/AgenticTools/flightrecorder.*
