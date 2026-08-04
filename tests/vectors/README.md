# Provenrail conformance vectors

Frozen golden bundles for validating any Provenrail verifier, ours or a third party's.
Each `<name>.json` is a complete `flightrecorder.bundle/1`. `manifest.json` records, per vector:

- `expect_ok` (boolean): the **portable contract**. Every conformant verifier MUST agree on this
  pass/fail verdict. This is the only guarantee required for interoperability.
- `defining_code` (string or null): the canonical finding code for the case. Our reference
  verifier always emits it; a third-party verifier SHOULD surface an equivalent signal, but the
  exact code is not part of the portable contract.
- `verify` (object, optional): verification **context** the vector needs. Base-chain vectors need
  none. Full-spec vectors carry the transparency-log public key (`tlog_log_key`), the witness
  public keys (`witness_pubkeys`), a fixed verification clock (`now_utc`, so cosignature freshness
  is deterministic), and/or selective-disclosure `openings`. A verifier MUST apply this context.
- `description`: what the vector exercises.

Both reference implementations (`pr verify` in Python and `web/verify.js` in JavaScript) are
tested against every vector here, so the suite is a two-implementation contract, not one
verifier's self-check.

## The vectors

| Vector | expect_ok | Exercises |
|---|---|---|
| `clean` | true | an untampered, anchored run verifies clean |
| `tamper_payload` | false | a record payload edited after signing (hash mismatch) |
| `delete_record` | false | a record removed mid-stream (server receipt chain breaks) |
| `reorder` | false | two records swapped (arrival order diverges from emission order) |
| `bad_signature` | false | a corrupted device-key signature |
| `strip_anchor` | true | valid records with no external anchor (weaker, not tampered) |
| `tlog_witnessed` | true | a transparency-log inclusion proof cosigned by an independent witness |
| `scitt_valid` | true | a SCITT COSE receipt that verifies against the transparency-service key |
| `scitt_forged` | false | a SCITT receipt with an altered COSE signature (hard fail) |
| `redacted_disclosed` | true | a redactable field disclosed with valid openings (commitments recompute) |
| `redacted_forged` | false | a redactable field with a forged opening (commitment mismatch) |

## Running against your verifier

Load each bundle, run your verification, and assert your pass/fail matches `expect_ok`. A clean
result on `clean` and a rejection on every `tamper_*` / `delete_*` / `reorder` / `bad_*` vector is
the minimum bar. The verification algorithm is specified in `../../SPEC.md`.

## Regenerating

The vectors are derived from one clean bundle by single, well-understood edits. To regenerate
(for example after an intentional, spec-versioned change to verification), run:

```
python tests/vectors/_generate.py
```

The generator asserts each vector reaches its expected verdict before writing, so a regeneration
that would change the contract fails loudly.
