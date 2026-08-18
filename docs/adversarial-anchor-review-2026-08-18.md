# Adversarial Anchor Service Review, 2026-08-18

Reviewer: independent audit fork. All findings below were reproduced by running code against
`/Volumes/T7/Projects/AgenticTools/.venv/bin/python`. Every attack that failed is recorded
explicitly. Nothing here is speculation.

---

## CRITICAL

### C1: `pr anchor-verify` accepts a forged local receipt -- signature is verified against the wrong root

**File:** `src/provenrail/cli.py:295-322`
**Product promise violated:** "a third party can verify a receipt against a bundle offline without
trusting either party."

**Mechanism.** The verifier reads the root to check against the bundle from `att.get("merkle_root")`,
but verifies the Ed25519 signature against `receipt.get("merkle_root")` -- the inner field inside the
`receipt` sub-object. These two fields are never compared to each other. The result: a valid signature
over *any* root passes verification of *any* bundle, provided the outer `att.merkle_root` is set to
match the bundle.

```python
# cli.py ~295-322 (abbreviated)
claimed_root = att.get("merkle_root") or receipt.get("merkle_root")
# ... checks claimed_root == actual_root (bundle hash) ...
if receipt.get("kind") == "local":
    signed = (receipt.get("merkle_root", "") + "|" + receipt.get("gen_time", ""))
    if not verify_signature(receipt.get("anchor_pubkey", ""), signed.encode("utf-8"),
                            receipt.get("signature", "")):
        problems.append("...")
```

`receipt.get("merkle_root")` is the *inner* field. If an attacker sets `att["merkle_root"]` to the
target bundle's real root, and `receipt["merkle_root"]` to any root they have a valid signature for,
both checks pass independently.

**Reproduction:**

```python
from provenrail.anchor import merkle_root, LocalAnchor
from provenrail.cli import main as cli_main
import hashlib, json, tempfile
from pathlib import Path
import io, contextlib
from dataclasses import asdict

def hashes(n): return [hashlib.sha256(f'r{i}'.encode()).hexdigest() for i in range(n)]

anchor = LocalAnchor()
target_leaves = hashes(100)
target_root = merkle_root(target_leaves)

# A real signature over a completely unrelated root
unrelated_root = 'deadbeef' * 8
real_receipt = anchor.anchor_root(unrelated_root)

forged_att = {
    'anchor_id': 'anc_forged',
    'stream_id': 'victim-stream',
    'merkle_root': target_root,          # matches the bundle -> root check passes
    'covers_up_to': 100,
    'receipt': {
        'kind': 'local',
        'merkle_root': unrelated_root,   # what was actually signed
        'gen_time': real_receipt.gen_time,
        'signature': real_receipt.signature,  # valid sig over unrelated_root
        'anchor_pubkey': real_receipt.anchor_pubkey,
    }
}
bundle = {
    'format': 'provenrail/1', 'stream_id': 'victim-stream',
    'records': [{'recv_seq': i, 'server_record_hash': h} for i, h in enumerate(target_leaves)],
    'anchors': [],
}
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    (td / 'bundle.json').write_text(json.dumps(bundle))
    (td / 'forged.json').write_text(json.dumps(forged_att))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli_main(['anchor-verify', str(td/'bundle.json'), str(td/'forged.json')])
    assert rc == 0  # VERIFIED -- forged receipt accepted
    assert "RESULT: VERIFIED" in out.getvalue()
```

Confirmed: `rc=0`, output `RESULT: VERIFIED. These records existed in this order at that time.`

**Impact:** Anyone who has ever received a valid local anchor receipt for *any* bundle can forge a
receipt for a completely different bundle. The auditor's check proves nothing. The product promise,
independent third-party verification, is broken for all local anchor receipts.

**Fix:** Before the signature check, assert `receipt.get("merkle_root") == claimed_root`. The signed
string is `receipt.merkle_root + "|" + gen_time`, so the receipt's inner merkle_root must equal the
root the verifier computed from the bundle:

```python
if receipt.get("kind") == "local":
    if receipt.get("merkle_root") != actual:   # ADD THIS
        problems.append("receipt.merkle_root does not match the bundle's actual root")
    signed = (receipt.get("merkle_root", "") + "|" + receipt.get("gen_time", ""))
    if not verify_signature(...):
        ...
```

---

### C2: `pr anchor-verify` accepts an RFC 3161 receipt with any garbage token -- token is never validated

**File:** `src/provenrail/cli.py:316-319`
**Product promise violated:** "a third party can verify a receipt against a bundle offline without
trusting either party."

**Mechanism.** For `kind == "rfc3161"`, the verifier only checks that `token_b64` is present:

```python
elif receipt.get("kind") == "rfc3161":
    if not receipt.get("token_b64"):
        problems.append("this claims to be an RFC 3161 anchor but carries no token")
```

It never decodes the token, never checks the TSA signature, and never verifies that the token's
`messageImprint` matches `SHA-512(bytes.fromhex(merkle_root))`.

**Reproduction:**

```python
forged_rfc_att = {
    'anchor_id': 'anc_rfc',
    'stream_id': 's',
    'merkle_root': merkle_root(target_leaves),
    'covers_up_to': 100,
    'receipt': {
        'kind': 'rfc3161',
        'merkle_root': merkle_root(target_leaves),
        'gen_time': '2020-01-01T00:00:00.000000Z',  # fake timestamp
        'token_b64': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',  # garbage but present
        'tsa_url': 'https://freetsa.org/tsr',
    }
}
# rc=0, VERIFIED
```

Confirmed: `rc=0`, output `RESULT: VERIFIED. These records existed in this order at that time.`

**Impact:** An attacker can claim any timestamp for any bundle using a completely fabricated RFC 3161
receipt. The timestamp evidence the product sells is unverifiable by `pr anchor-verify`. This is
critical for a product whose core value proposition is independent timestamped attestation.

Note: the server-side receipt returned by `POST /v1/anchors` is authentic. FreeTSA was tested directly:
it responds in 1 to 2 seconds, returns a valid DER-encoded token, and uses SHA-512 over the root bytes
as the message imprint (confirmed by inspection of `tst.tst_info.message_imprint.message`). The
vulnerability is only in the verifier, not the issuer.

**Fix:** Decode and verify the token offline. The `rfc3161_client` library is already a dependency.
At minimum:

```python
import base64, hashlib
from rfc3161_client import decode_timestamp_response
token_bytes = base64.b64decode(receipt["token_b64"])
tst = decode_timestamp_response(token_bytes)
msg = bytes(tst.tst_info.message_imprint.message)
expected = hashlib.sha512(bytes.fromhex(actual)).digest()
if msg != expected:
    problems.append("RFC 3161 token messageImprint does not match this bundle's root")
```

Full certificate chain validation against a bundled CA is the complete fix; the above is the minimum.

---

## HIGH

### H1: `covers_up_to >= 2^63` causes an unhandled 500 after TSA round-trip

**File:** `src/provenrail/server/storage.py:1042`, `src/provenrail/server/app.py:595-608`

**Mechanism.** Pydantic accepts any Python `int` for `covers_up_to`. SQLite's INTEGER column is
signed 64-bit (max `9223372036854775807`). A value of `9223372036854775808` (`2^63`) passes Pydantic,
passes all explicit guards (`>= 1`, length check), triggers a live TSA round-trip (the receipt is
minted before the insert is attempted), then raises an unhandled `OverflowError` at the `INSERT`,
returning a raw 500 to the caller.

**Reproduction:**

```python
import json
body = json.dumps({'stream_id': 's', 'merkle_root': 'a'*64,
                   'covers_up_to': 9223372036854775808})
# POST with Content-Type: application/json
# -> OverflowError: Python int too large to convert to SQLite INTEGER
# -> 500 Internal Server Error (TSA receipt was already minted and discarded)
```

Confirmed by traceback at `storage.py:265`.

**Impact:** Any authenticated caller can trigger repeated 500s. Each request wastes a TSA call before
failing. If FreeTSA has rate limits, this is also a TSA resource exhaustion vector.

**Fix:** Add a validator to `AnchorRootIn`:

```python
from pydantic import field_validator

class AnchorRootIn(BaseModel):
    stream_id: str
    merkle_root: str
    covers_up_to: int

    @field_validator("covers_up_to")
    @classmethod
    def _valid_range(cls, v: int) -> int:
        if v > 9_223_372_036_854_775_807:
            raise ValueError("covers_up_to exceeds maximum supported value")
        return v
```

Capping at `2^53` (JavaScript safe integer) is a reasonable tighter bound since no real record chain
would ever exceed it.

---

### H2: Duplicate anchors allowed for identical (account, stream, root, coverage)

**File:** `src/provenrail/server/storage.py:1023-1050`

**Mechanism.** The `CoverageWentBackwards` check fires only when coverage shrinks OR when the same
coverage has a different root. Repeated requests with the same (stream_id, covers_up_to, merkle_root)
all succeed and each produces a new anchor_id. The check+insert is atomic under `self._lock`, but the
idempotency case has no guard.

**Reproduction:**

```python
for _ in range(5):
    c.post('/v1/anchors', headers=h, json={
        'stream_id': 'dup-stream', 'merkle_root': root, 'covers_up_to': 200,
    })
anchors = c.get('/v1/anchors?stream_id=dup-stream', headers=h).json()['anchors']
assert len(anchors) == 5  # five distinct anchor_ids for identical commitment
```

Confirmed: 5 anchor_ids created, all pointing to the same (root, covers_up_to).

**Impact:** A caller can inflate their anchor quota by resubmitting the same anchor repeatedly. An
auditor seeing the history for a stream sees five distinct receipts for the same coverage, which is
misleading about the anchoring cadence. A retry-on-failure pattern (which is reasonable for network
errors) produces duplicate records rather than returning the existing one.

**Fix:** Return the existing anchor if (account_id, stream_id, covers_up_to, merkle_root) already
exists rather than inserting a new row. This makes the endpoint idempotent:

```python
if (prev is not None
        and covers_up_to == prev["covers_up_to"]
        and merkle_root == prev["merkle_root"]):
    # Idempotent re-submission: return the existing record, do not insert.
    row = self._db.execute(
        "SELECT anchor_id, stream_id, merkle_root, covers_up_to, receipt, created_at "
        "FROM external_anchors WHERE account_id=? AND stream_id=? AND covers_up_to=? AND merkle_root=?",
        (account_id, stream_id, covers_up_to, merkle_root)).fetchone()
    return {... row data ...}
```

---

### H3: TSA round-trip fires before coverage check -- 409 requests each waste one TSA call

**File:** `src/provenrail/server/app.py:595` (`receipt = backend.anchor_root(root)`)

**Mechanism.** The code calls `backend.anchor_root(root)` (network call to FreeTSA or local signing)
before calling `store.append_external_anchor()`. When the store raises `CoverageWentBackwards` (409),
the receipt is discarded. The comment on the code acknowledges this.

Confirmed: 409 does not consume quota (correct behavior), but does consume one TSA request and incurs
1 to 2 seconds of latency.

**Impact:** A buggy or adversarial caller repeatedly sending stale coverage claims can exhaust FreeTSA's
per-IP rate limit on behalf of the service. Each 409 wastes a TSA call that contributes nothing.

**Fix:** Read the current maximum coverage before calling `backend.anchor_root()` and reject the
obvious cases early. The lock-protected insert still handles the race; the pre-check just avoids the
TSA call for the clearly-rejected cases:

```python
# Before calling backend.anchor_root:
existing_max = store.get_max_coverage(account_id or "open", stream_id)
if existing_max is not None and body.covers_up_to < existing_max:
    raise HTTPException(409, "...")
receipt = backend.anchor_root(root)  # only now
```

---

## MEDIUM

### M1: `stream_id` returned in unauthenticated GET -- PII risk undocumented, control characters accepted

**File:** `src/provenrail/server/storage.py:1052-1063`, `src/provenrail/server/app.py:617-623`

**Mechanism.** The public GET (`GET /v1/anchors/{anchor_id}`) returns `stream_id` to any caller.
The `stream_id` is customer-chosen and stored verbatim. A customer who uses a human-identifiable
string as their stream_id (an email address, user ID, account number, or name) exposes it to any
caller who knows the anchor_id.

Additional input issues found:
- Null bytes accepted: `'stream\x00null'` stored as-is (SQLite TEXT allows null bytes; downstream
  consumers may truncate or misbehave).
- Newlines accepted: `'stream\nnewline'` stored as-is.
- No character class restriction beyond length and strip.

**Reproduction:**

```python
r = c.post('/v1/anchors', headers=h, json={
    'stream_id': 'john.doe@megacorp.com',  # PII
    'merkle_root': root, 'covers_up_to': 5,
})
public = c.get(f'/v1/anchors/{r.json()["anchor_id"]}').json()
assert public['stream_id'] == 'john.doe@megacorp.com'  # visible to any caller
```

Confirmed.

**Impact:** The PRD's "SHA-256 root over hashes is not personal data" argument does not extend to
`stream_id`. If a customer uses PII as a stream label, it becomes public. The PRD acknowledges this
risk in passing but the endpoint documentation and API response do not warn callers.

**Fix (short-term):** Document in the API and on the pricing page that `stream_id` is returned
publicly and must not contain personally identifiable information.

**Fix (long-term):** Omit `stream_id` from the unauthenticated public GET response. An auditor needs
only the root, timestamp, and receipt; the customer's internal label adds nothing for them.

**Also fix:** Reject control characters in `stream_id` at validation time:

```python
stream_id = (body.stream_id or "").strip()
if any(ord(c) < 32 for c in stream_id):
    raise HTTPException(422, "stream_id must not contain control characters")
```

---

### M2: Open/dev mode -- all unauthenticated anchors share one namespace with no isolation

**File:** `src/provenrail/server/app.py:599` (`account_id=account_id or "open"`)

**Mechanism.** In open mode (`require_account=False`), `_principal()` returns `None`, and
`account_id` falls back to the hardcoded string `"open"`. `GET /v1/anchors` in open mode lists from
the same `"open"` bucket. Any client on the same server can list all anchors posted by any other
client in open mode.

**Reproduction:**

```python
c = TestClient(create_app(':memory:', require_account=False))
c.post('/v1/anchors', json={'stream_id': 'user-a-private', 'merkle_root': root, 'covers_up_to': 5})
c.post('/v1/anchors', json={'stream_id': 'user-b-secret', 'merkle_root': root, 'covers_up_to': 5})
all_anchors = c.get('/v1/anchors').json()['anchors']
assert len(all_anchors) == 2  # both visible; no isolation
```

Confirmed.

**Impact:** A self-hosted development server with multiple developers or processes exposes all anchors
to all callers. Streams in active development become visible to other developers on the same server.

**Fix:** Document that open mode is single-user only. Alternatively, require a developer-specific
header or token to bucket anchors separately even without full account enforcement.

---

### M3: Test suite does not cover RFC 3161 token validation or the C1/C2 forgery paths

**File:** `tests/test_anchor_only.py`

**Mechanism.** The end-to-end CLI test uses a `LocalAnchor` (the default in `create_app(':memory:')`).
No test creates an rfc3161 receipt and passes it through `pr anchor-verify`. The token presence-only
check (C2 above) is not covered. `test_a_local_receipt_is_signed_by_a_key_the_customer_can_check`
has `if receipt["kind"] == "local":` that silently skips rfc3161 receipts rather than failing.

No test for C1 (forged inner `receipt.merkle_root`), C2 (garbage `token_b64`), or any case where the
auditor is given a tampered receipt whose outer and inner roots disagree.

**Impact:** Both critical findings existed undetected because there are no tests for them. The tests
claim to prove the end-to-end product promise but do not exercise the two most important paths: rfc3161
token validity and the receipt-to-bundle binding in the local signature check.

**Fix:** Add:

```python
def test_anchor_verify_rejects_garbage_rfc3161_token(tmp_path):
    # ...forge a receipt with kind=rfc3161 and token_b64='AAAA...'
    # assert cli_main(['anchor-verify', ...]) == 1

def test_anchor_verify_rejects_local_sig_over_wrong_root(tmp_path):
    # ...forge a receipt where receipt.merkle_root != att.merkle_root
    # assert cli_main(['anchor-verify', ...]) == 1
```

---

### M4: Pydantic coerces string `"5"` to int for `covers_up_to` -- strict mode not set

**File:** `src/provenrail/server/app.py:62`

**Mechanism.** Pydantic v2 coerces `"5"` (a JSON string) to `5` (int) in lax mode. A caller sending
`covers_up_to: "5"` receives a 200 rather than a 422.

**Reproduction:**

```python
r = c.post('/v1/anchors', headers=h, json={
    'stream_id': 'ss', 'merkle_root': root, 'covers_up_to': '5'
})
assert r.status_code == 200
assert r.json()['covers_up_to'] == 5
```

Confirmed: `"5"` -> `5`, stored correctly as integer.

**Impact:** Low direct security risk (the coerced value is a valid integer). But the schema is the
privacy guarantee and accepting unexpected types weakens that claim. `5.9` (float) is correctly
rejected with 422; the inconsistency is unexpected.

**Fix:**

```python
from pydantic import Field
from typing import Annotated

class AnchorRootIn(BaseModel):
    stream_id: str
    merkle_root: str
    covers_up_to: Annotated[int, Field(strict=True)]
```

---

## LOW

### L1: `filterwarnings` in `cli.py` is redundant and misplaced

**File:** `src/provenrail/cli.py:18-19`

```python
warnings.filterwarnings("ignore", message=r".*starlette\.testclient.*")
warnings.filterwarnings("ignore", module=r"starlette\.testclient")
```

These suppress Starlette TestClient deprecation warnings at production CLI import time. The correct
suppression is already in `pyproject.toml` under `[tool.pytest.ini_options].filterwarnings`. These
lines are inert in production (starlette.testclient is never imported outside tests) but add noise.
The regex itself is correct (`\.` in a raw string is an escaped dot that matches a literal period).

**Fix:** Remove lines 18 to 19 from `cli.py`. The pytest config in `pyproject.toml` handles the test
context.

---

### L2: `stream_id` in public GET enables stream correlation across receipts

**File:** `src/provenrail/server/storage.py:1052-1063`

Even when stream_id is not PII, the public endpoint exposes it. An entity that holds two anchor_ids
(legitimately, as an auditor) can confirm whether two receipts came from the same customer stream.
This links activity across time without requiring any account knowledge. The anchor_id itself is
unguessable (~122 bits entropy), so the only exposure is to callers who legitimately hold the id.

**Impact:** Low risk given unguessable ids. Worth documenting in the privacy notice.

---

## Attacks That Held

- **Extra fields reach storage:** NO. Pydantic drops all extra fields before they touch storage.
  `prompt`, `records`, nested objects -- silently discarded. The schema is an effective privacy
  boundary.

- **Coverage cannot go backwards:** HOLDS. A 409 is returned for `covers_up_to < current max` and
  for `covers_up_to == current max` with a different root (fork). Both checks are inside
  `with self._lock:` and are atomic.

- **Different accounts sharing a stream_id:** HOLDS. Coverage enforcement is per `(account_id,
  stream_id)`. Account B can anchor `stream_id='shared-name'` at coverage 10 even if account A is
  at 1000. They are fully isolated.

- **Concurrent true fork:** HOLDS. The lock serializes check+insert. Same coverage, different root,
  concurrent: correctly rejected 409.

- **401 without auth (key mode):** HOLDS. `POST /v1/anchors` without a bearer token returns 401.

- **Public GET exposes account_id:** HOLDS. `account_id` is omitted from `GET /v1/anchors/{id}` by
  explicit selection in the SQL query.

- **One account listing another's anchors:** HOLDS. `GET /v1/anchors` scopes to the caller's
  `account_id`. Cross-account listing returns an empty list.

- **Anchor_id guessability:** HOLDS. `new_anchor_id()` uses UUID4 (~122 bits entropy). Brute-force
  enumeration is not feasible.

- **Unknown receipt kind:** HOLDS. `kind == "quantum_notary"` returns `rc=1`, message "unknown
  anchor receipt kind".

- **Malformed root rejected before TSA call:** HOLDS. `_checked_root()` fires before
  `backend.anchor_root()`.

- **RFC 3161 path against real TSA:** CONFIRMED WORKING. FreeTSA at `https://freetsa.org/tsr`
  responds in 1 to 2 seconds, returns a valid DER token, uses SHA-512 over the root bytes (confirmed
  by `tst.tst_info.message_imprint.message`), and the timestamp matches the server clock. The
  vulnerability is in the verifier, not the issuer.

---

## Four Fixes from Today

**`_checked_root` validation in `verifier/verify.py`'s `main()`**

The `_bad_key()` helper validates `--tlog-pubkey`, `--registry-pubkey`, and witness pubkeys before
use, preventing a silently-skipped bad key from printing VERIFIED without performing the check.
Correct fix. No issue found.

**`LicenseInfo.__bool__`**

The `__bool__` method returns `self.valid`. Before the fix, `if verify_license(token):` was always
`True` (dataclass instance is truthy). Confirmed by test:

```python
assert not LicenseInfo(valid=False)
assert LicenseInfo(valid=True)
assert not verify_license('bad_token')
```

Correct fix.

**`FlightRecorder.session_id`**

The property reads `self.chain.session_id` dynamically rather than caching at construction. If the
chain is replaced on reconnect, the property returns the new session_id. Correct fix. Confirmed by
replacing `fr.chain` and verifying `fr.session_id` updates.

**`pytest filterwarnings` entry**

The entry in `pyproject.toml` is the correct location. Correct fix. The duplicate
`warnings.filterwarnings` calls in `cli.py:18-19` were not removed as part of the fix and remain as
harmless clutter (see L1 above).

---

## Summary Table

| ID | Severity | File | Description |
|----|----------|------|-------------|
| C1 | CRITICAL | `cli.py:316` | Local receipt: sig verified against inner `receipt.merkle_root`, not bundle root -- any valid sig forges any receipt |
| C2 | CRITICAL | `cli.py:316-319` | RFC 3161: token never decoded or validated -- garbage token passes as VERIFIED |
| H1 | HIGH | `app.py:595`, `storage.py:1042` | `covers_up_to >= 2^63` causes unhandled 500 after wasting a TSA call |
| H2 | HIGH | `storage.py:1023-1050` | Identical (root, coverage) re-submissions create duplicate anchor rows |
| H3 | HIGH | `app.py:595` | TSA called before coverage check: 409 requests each waste one TSA call |
| M1 | MEDIUM | `storage.py:1052`, `app.py:617` | `stream_id` in public GET, PII risk; null bytes and newlines accepted |
| M2 | MEDIUM | `app.py:599` | Open mode: all anchors share `account_id="open"`, no inter-user isolation |
| M3 | MEDIUM | `tests/test_anchor_only.py` | No test covers rfc3161 token validation or the C1/C2 forgery vectors |
| M4 | MEDIUM | `app.py:62` | Pydantic coerces string `"5"` to int; `strict=True` not set |
| L1 | LOW | `cli.py:18-19` | Redundant `filterwarnings` in production CLI module |
| L2 | LOW | `storage.py:1052` | `stream_id` in public GET enables stream correlation across receipts |
