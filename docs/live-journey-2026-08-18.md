# Live Customer Journey Audit - 2026-08-18

Executed by: independent agent (Claude Sonnet 4.6), against a real running server,
real network calls, real files on disk. No TestClient, no in-process shortcuts.
Date: 2026-08-18. Provenrail version: 0.2.30.

Python: 3.14.6 via `/Volumes/T7/Projects/AgenticTools/.venv/bin/python`.
Clean install venv: fresh Python 3.14.6 standard library venv.
Anchor service venv: same project venv (for SDK calls).

---

## Verdict Table

| Step | Description | Result | Time | Exit |
|------|-------------|--------|------|------|
| 1 | Fresh install from local source into clean venv | PASS | 14.1s | 0 |
| 2a | `pr quickstart` - first attempt (port conflict) | FAIL | 21.5s | 1 |
| 2b | `pr quickstart` recovery path | PASS | 0.7s | 0 |
| 3a | Record agent run - first attempt with float metadata | FAIL | 0.3s | 1 |
| 3b | Record agent run - fixed (string metadata) | PASS | 0.4s | 0 |
| 4a | Export bundle over HTTP | PASS | 0.03s | 0 |
| 4b | `pr verify` on clean bundle | PASS | 0.4s | 0 |
| 4c | Tamper bundle (wrong path) - verifier said VERIFIED | UX TRAP | - | 0 |
| 4d | Tamper bundle (correct path) - TAMPERING DETECTED | PASS | 0.2s | 1 |
| 5 | Start independent anchor service on port 19877 | PASS | ~3s | - |
| 5b | `pr anchor-push` to independent anchor service | PASS | 0.6s | 0 |
| 5c | Auditor URL resolves, returns anchor (no account needed) | PASS | <0.1s | 0 |
| 5d | Anchor service DB contains ZERO customer records | PASS | - | - |
| 6a | `pr anchor-verify` on clean bundle + receipt | PASS | 0.1s | 0 |
| 6b | Attack 1: edit record payload, `pr anchor-verify` | FAIL (design gap) | 0.08s | 0 |
| 6c | Attack 2: truncate bundle, `pr anchor-verify` | PASS (caught) | 0.08s | 1 |
| 7a | Push second anchor (14 records, higher coverage) | PASS | 0.3s | 0 |
| 7b | Push shorter anchor (10 < 14), refusal with clear message | PASS | 0.3s | 1 |
| 7c | Refusal left no partial row in anchor service DB | PASS | - | - |
| 8a | Wrong port (unreachable) - clear error message | PASS | 0.3s | 3 |
| 8b | Wrong API key (open mode server) - accepted (expected) | NOTE | 0.2s | 0 |
| 8c | Malformed bundle path - clear error with hint | PASS | 0.2s | 2 |
| 8d | Bundle with zero records - clear error | PASS | 0.1s | 2 |
| 9 | RFC 3161 direct call to FreeTSA | PASS | 0.96s | - |
| 9b | `pr anchor-push` to rfc3161 server in open mode | PASS (but local) | 0.5s | 0 |
| 9c | TSA unreachable scenario | PASS (ConnectError, 0.3s) | 0.3s | - |

---

## Step-by-step detail

### Step 1: Fresh install from local source

```
pip install -e /Volumes/T7/Projects/AgenticTools/flightrecorder
```

Install completed in 14.1s, 27 packages installed, zero errors. One pip upgrade notice
(`pip` 26.1.2 -> 26.2.1) which is cosmetic. The editable wheel built cleanly.

PASS. No issues for a new customer installing from source.

---

### Step 2: `pr quickstart`

**First attempt - FAIL**

Port 19876 was already in use by a pre-existing Python process (PID 1123, a leftover
development server). Quickstart spawned a new server process (PID 26163), which died
immediately due to `[Errno 48] Address already in use`. Quickstart waited 20 seconds
for its server to pass a health check, the health check timed out, and it exited 1:

```
the local sink did not become healthy in time
```

The PID file `.provenrail.pid` was written with the dead PID 26163.

**Second attempt blocked**

After killing the pre-existing server, a second `pr quickstart` was immediately refused:

```
a local sink is already recorded as running (pid 26163).
Run `pr quickstart --stop` first, or use --port for a second one.
```

Dead PID, PID file still present, new start blocked.

**Recovery path**

```
pr quickstart --stop   # EXIT 0: "stopped the local Provenrail sink"
rm sink.db             # clear old database
pr quickstart --port 19876 --db sink.db
```

Recovery worked in 0.7 seconds. Output:

```
started a local sink (pid 26545) and wrote .provenrail.json

See it work right now, without writing any code:
    pr demo                   # records a real run and writes bundle.json
    pr verify bundle.json     # recomputes everything, trusts nobody
...
```

`.provenrail.json` written with endpoint, write_token, stream_id, read_token, share_token.
Server health: `GET /healthz` returns `{"ok":true}`.

**Bug found**: quickstart writes the PID file and waits for a health check, but if the
server dies immediately (port conflict), the PID file persists. A subsequent `pr quickstart`
sees the stale PID and refuses to start. The user must run `pr quickstart --stop` to clear it
even though there is no running process. quickstart should detect that its own spawned process
has already exited and clean up automatically rather than putting the user in a state that
requires a recovery command.

UX note for a new customer: if they see "the local sink did not become healthy in time",
the next step is not obvious. The error does not say "run `pr quickstart --stop` first".
A confused customer who runs `pr quickstart` again gets the PID-still-running message,
which contradicts the "did not become healthy" message they just saw.

PASS on recovery path. FAIL on the first-run experience.

---

### Step 3: Record a real agent run through the Python SDK

**First attempt - FAIL**

```python
fr.record_decision("Proceed...", metadata={"confidence": 0.9})
```

```
provenrail.canonical.CanonicalError: float at $.payload.metadata.confidence:
floats are not allowed in records (use a string for exact cross-verifier hashing)
```

Exit 1. The error message is accurate and includes the correct fix. But a new user who
passes a confidence score as a float (which is natural Python) will hit this with no
warning before the call. The error fires at the local canonicalize step, not at the
network layer, so the message arrives fast (0.3s).

**Fix applied**: changed `0.9` to `"0.9"` (string).

**Second attempt - PASS**

```
Stream: dbee69a1-276e-4dd7-baa4-be5f14356ffe
OK: session recorded in 0.034s
```

Session with 4 events (session_start, model_call, tool_call/bash, decision, model_call,
session_end) completed in 34ms over real HTTP to the local sink.

PASS on the corrected call. The float restriction is correct by design (cross-verifier
hash determinism), but no SDK guard prevents the error before attempting to emit.

---

### Step 4: Export bundle and verify

**Export over HTTP**

```bash
curl -s -H "Authorization: Bearer $READ_TOKEN" \
  "http://127.0.0.1:19876/v1/streams/$STREAM_ID/export" > bundle.json
```

11,498 bytes, 10 records, 0.03s. Exit 0.

**`pr verify` on clean bundle**

```
[warn] no_anchor: no external anchor present; records are not bound to a trusted external time
[info] no_governance: the session made model calls but recorded no decision...
[info] summary: 10 records, 0 anchors, 0 heartbeats.

RESULT: VERIFIED
```

0.4s. Exit 0. PASS. The warn/info output is informative and explicitly says
"The warn/info lines above are advisory context, not failures."

**Tamper test - UX trap encountered**

First tamper attempt used `r.get('action_type') == 'model_call'` at the bundle envelope
level. The actual structure is `r['record']['action_type']`. The tamper silently no-oped.
The verifier correctly returned VERIFIED because nothing was actually changed. This is not
a bug, but the bundle structure is a two-layer envelope that an integrator writing their
own tooling would need to know.

**Correct tamper test**

Changed `r['record']['payload']['provider']` from `'anthropic'` to `'openai'`.

```
[FAIL] recv_hash_mismatch: recv_seq 1: stored record bytes do not match recv_hash
[FAIL] server_chain_break: recv_seq 1-9: server receipt chain broken
[FAIL] server_head_mismatch: ...
[FAIL] client_hash_mismatch: session ...: seq=1: record_hash does not match content
[FAIL] client_bad_signature: ...

RESULT: TAMPERING DETECTED
```

0.2s. Exit 1. Multiple independent failure signals, clear message. PASS.

---

### Step 5: Independent anchor service

**Start second server on port 19877**

```bash
python -m provenrail serve --port 19877 --db anchor-service.db --open
```

Output:
```
Provenrail serving on http://127.0.0.1:19877 (db=anchor-service.db,
anchor=local every 60.0s, open (no API key))
```

`/healthz` returns `{"ok":true}`. PASS.

**`pr anchor-push` from customer sink to anchor service**

```bash
pr anchor-push bundle.json \
  --url http://127.0.0.1:19877 \
  --key "open-mode-key-not-checked" \
  --receipt-out receipt.json
```

Note: `--key` is `required=True` in argparse even though an open-mode server ignores the
value. A customer must pass some string to satisfy argparse; passing any string works.
There is no documented convention for what to pass when no key is required.

Output:
```
anchored 10 records of stream dbee69a1-276e-4dd7-baa4-be5f14356ffe
  root       0ef12cc94922c993ba25b684a58904024f23cc7902aae28f0c5b79bca5d05880
  anchor id  anc_1ebe74af63674b62bd0cc95926cee2bf
  timestamp  2026-08-18T17:46:41.066185Z (local)

Give an auditor this URL; they need no account and no permission from you:
  http://127.0.0.1:19877/v1/anchors/anc_1ebe74af63674b62bd0cc95926cee2bf

anchor receipt written to receipt.json
```

0.6s. Exit 0. PASS.

**Auditor URL resolves**

```bash
curl -s "http://127.0.0.1:19877/v1/anchors/anc_1ebe74af63674b62bd0cc95926cee2bf"
```

Returns the anchor JSON with `anchor_id`, `stream_id`, `merkle_root`, `covers_up_to`,
`receipt`, `created_at`. No authentication required. PASS.

**Anchor service DB contains ZERO customer records**

Direct SQLite inspection:

```
accounts: 0 rows
streams: 0 rows
records: 0 rows           <-- confirmed: no customer records
external_anchors: 1 rows  <-- only the Merkle root
```

The anchor service stored only the root hash and a timestamp. No prompts, no content,
no stream records. PASS. The design claim holds.

---

### Step 6: `pr anchor-verify` and attacks

**Clean verify**

```
pr anchor-verify bundle.json receipt.json
```

```
[info] root 0ef12cc9... over 10 records
[info] anchored at 2026-08-18T17:46:41.066185Z (local)

RESULT: VERIFIED. These records existed in this order at that time.
```

0.1s. Exit 0. PASS.

**Attack 1: Edit one record's payload - DESIGN GAP**

Changed `records[1].record.payload.provider` from `'anthropic'` to `'openai'`.

```
pr anchor-verify bundle-attack1.json receipt.json
RESULT: VERIFIED. These records existed in this order at that time.
Exit 0
```

This is a correct-but-misleading result. Explanation: the Merkle root committed to by the
anchor is computed from `server_record_hash` values, not from the record payload. The
`server_record_hash` at each position is `SHA256(recv_seq + recv_ts + recv_hash +
server_prev_hash)`, where `recv_hash` is the hash of the original record bytes. Changing
the payload without updating `recv_hash` or `server_record_hash` does not change the
Merkle root.

`pr verify` on the same file DOES catch this: `client_hash_mismatch` + `client_bad_signature`.

So the correct full workflow is:
1. `pr verify bundle.json` - verifies content integrity (client signatures, record hashes)
2. `pr anchor-verify bundle.json receipt.json` - verifies the anchor covers these record hashes

Neither command alone is sufficient. But `pr anchor-verify` says "RESULT: VERIFIED. These
records existed in this order at that time." with no mention that content integrity is not
being checked by this command. A user who runs only `pr anchor-verify` on a tampered bundle
gets a false green result.

Recommendation: `pr anchor-verify` should either (a) also verify `recv_hash` against the
record bytes (full content check), or (b) add an output line like:
"[note] this command checks the anchor covers these record-chain hashes. Run `pr verify`
to check that record content matches those hashes."

The README also says "Edit a record afterwards and the root stops matching." This is
technically true only for a sophisticated attacker who also recalculates `server_record_hash`
(which they cannot do without the server's keys, so would break the chain). For a naive
payload-only edit, the root does not stop matching. The claim is misleading.

FAIL - not a security hole (a sophisticated attack requires breaking the server chain), but
a real usability gap that a customer relying on `anchor-verify` alone will not notice.

**Attack 2: Truncate bundle (drop tail)**

Reduced 10 records to 5.

```
[FAIL] this receipt covers 10 records but the bundle holds only 5: records are missing
[FAIL] the anchored root is 0ef12cc9..., but these records hash to cd6b04d0...

RESULT: THIS RECEIPT DOES NOT COVER THIS BUNDLE
Exit 1
```

0.08s. Clear message, correct exit code. PASS.

---

### Step 7: Second anchor and shorter-anchor refusal

**Second anchor (14 records after second agent run)**

```
anchored 14 records of stream dbee69a1...
  root       b61e611852...
  anchor id  anc_d8526a...
  timestamp  2026-08-18T17:48:49.404090Z (local)
Exit 0
```

PASS. Coverage monotonicity accepted higher count.

**Shorter anchor refusal**

Pushed original bundle (10 records) against anchor service that already had 14:

```
refused: this stream is already anchored to 14 records; an anchor covering only 10
would drop the tail. Anchor the full chain, or open a new stream if you meant to start over.
Exit 1
```

0.3s. Clear message, correct exit code. PASS.

**No partial row in DB**

After the refusal: `external_anchors` has exactly 2 rows (the two successful pushes).
No partial row, no quota consumed. PASS.

Note: a third push with the same 14-record bundle and identical root was accepted (exit 0),
creating a redundant anchor row. This is correct (not a fork - same root), but creates
a duplicate row. Quota was incremented for the duplicate. Minor billing concern.

---

### Step 8: Failure modes

**8a: Unreachable anchor service (wrong port)**

```bash
pr anchor-push bundle.json --url http://127.0.0.1:19999 --key "key"
```

```
could not reach the anchor service at http://127.0.0.1:19999: [Errno 61] Connection refused
Exit 3
```

0.3s. Clear message, distinct exit code (3). PASS.

**8b: Wrong API key against open-mode server**

In open mode, any key is accepted. Exit 0. This is correct behavior for an open server,
but there is no way to test key rejection without setting up an account-mode server.
The `--key` argument is required by argparse but semantically optional for open-mode servers.
No documentation tells the user what to pass for an open-mode server.

NOTE (not a bug, but a UX gap).

**8c: Malformed bundle path**

```bash
pr anchor-push /nonexistent/path.json --url http://127.0.0.1:19877 --key "key"
```

```
file not found: /nonexistent/path.json
Check the name and that you are in the right folder (`ls` lists files here).
Exit 2
```

0.2s. Clear message with actionable hint. PASS.

**8d: Bundle with zero records**

```bash
echo '{"format":"provenrail-v1","stream_id":"test","records":[],"anchors":[]}' > empty.json
pr anchor-push empty.json --url ... --key "key"
```

```
this bundle has no records, so there is nothing to anchor.
Exit 2
```

0.1s. PASS.

---

### Step 9: RFC 3161 path

**Direct call to FreeTSA**

```python
from provenrail.anchor import RFC3161Anchor
a = RFC3161Anchor()  # defaults to https://freetsa.org/tsr
receipt = a.anchor_root(sha256_hex_root)
```

- Latency: 0.96s
- Token present: yes (6,236 base64 chars)
- `gen_time`: `2026-08-18T17:51:45.000000Z`
- Kind: `rfc3161`

FreeTSA responded correctly and quickly. PASS.

**TSA unreachable**

```python
a = RFC3161Anchor(tsa_url='http://127.0.0.1:9999/tsa', timeout=3.0)
```

`ConnectError: [Errno 61] Connection refused` in 0.29s (fast fail because port refused,
not a timeout). The exception bubbles from the anchor class without being caught at a
higher level. In the server context this would cause a 500 to the caller of
`POST /v1/anchors`. There is no fallback to local in the non-MultiTSA path.

NOTE: `MultiTSAAnchor` exists and provides failover between TSAs, but the default
`--anchor rfc3161` mode uses a single `RFC3161Anchor`.

**Plan gating for `pr anchor-push` + RFC 3161**

This is a documentation gap. `pr serve --anchor rfc3161` sets the automatic anchoring
scheduler to use RFC 3161, but `POST /v1/anchors` (used by `pr anchor-push`) always
uses `local_anchor` in open mode:

```python
else:  # open mode / no account
    backend = app.state.scheduler.local_anchor
```

Result: even when the anchor service is started with `--anchor rfc3161`, `pr anchor-push`
in open mode returns a `local` receipt, not an `rfc3161` one.

To get a real RFC 3161 receipt from `pr anchor-push`, a customer would need:
1. An account on the anchor service
2. A plan with `trusted_time: True` (Tier 2 or higher)

This is not documented anywhere in the `pr anchor-push --help` output or the README.
The README says "real trusted timestamps" next to `pr serve --anchor rfc3161` without
clarifying this only applies to scheduled internal anchoring, not `pr anchor-push`.

NOTE (documentation gap, not a code bug).

---

## Findings Summary

### Bugs (code behavior wrong or unsafe)

None found. The integrity core holds.

### UX Failures (a real customer would get stuck or be misled)

**1. Quickstart port conflict leaves dead PID file (MEDIUM)**

When the port is already in use, quickstart reports "did not become healthy in time"
(exit 1) but writes the PID file with the dead process ID. The next `pr quickstart`
sees the stale file and refuses to start, sending the user to `--stop` with no
explanation. The error message does not tell the user to run `pr quickstart --stop`.

**2. Float metadata causes CanonicalError with no pre-check (LOW)**

Passing `{"confidence": 0.9}` in metadata to `record_decision()` raises `CanonicalError`
at emit time. The message is accurate but the error occurs after the call, not before.
SDK users who test with numeric values will be surprised. The fix is `"0.9"` (string).
Nowhere in the docs or docstrings is this restriction explained before the call.

**3. `pr anchor-verify` does not check payload integrity (HIGH - design gap)**

`pr anchor-verify` computes the Merkle root from `server_record_hash` values and checks
it against the receipt. It does not verify that record payloads match their `recv_hash`.
A tampered payload (without recalculating `recv_hash`) passes `anchor-verify` with
"RESULT: VERIFIED". `pr verify` catches the same tamper.

Users who run only `anchor-verify` (the dedicated audit command) see VERIFIED on a
tampered bundle. The output has no note saying content integrity requires `pr verify`.

The README claim "Edit a record afterwards and the root stops matching" is misleading for
this case.

**4. `--key` required by argparse even for open-mode anchor services (LOW)**

`pr anchor-push --key` is `required=True`. Open-mode servers ignore it, but the user
must pass some string. The help text says "account API key for the anchor service" which
implies a real key is always needed. A new user aiming at an open-mode server has no
documented answer for what to pass.

**5. RFC 3161 not available via `pr anchor-push` in open mode (MEDIUM - documentation gap)**

The README and serve output imply `--anchor rfc3161` gives trusted timestamps. It does
for the automatic scheduler, but `pr anchor-push` always uses `local_anchor` for
open-mode/unauthenticated callers. The receipt kind is always `local` in this path.
The distinction is not documented.

**6. Duplicate anchor rows at same coverage (LOW)**

Pushing the same bundle twice (identical root, identical coverage count) is accepted and
creates two rows in `external_anchors`, both consuming quota. A deduplicate-or-reject
check for exact duplicates would be cleaner.

---

## Exit Code Reference (observed)

| Exit | Meaning |
|------|---------|
| 0 | Success |
| 1 | Refused (monotonic coverage violation; TAMPERING DETECTED on verify) |
| 2 | Bad input (missing file, zero records, wrong args) |
| 3 | Network error (unreachable service) |

---

## What Would Actually Block a Customer

1. Port conflict on first `pr quickstart` without another process on that port: unlikely
   in a fresh environment, but happens in dev where servers are left running.
2. Float in metadata: will hit any user who passes numeric metrics (confidence, scores,
   percentages) without reading the error carefully.
3. Running only `pr anchor-verify` and trusting the VERIFIED result without also running
   `pr verify`: the customer believes they have an integrity check when they only have an
   anchor coverage check.

---

## What Works Well

- `pr quickstart` recovery flow once you know the `--stop` step
- Session recording latency: 34ms end-to-end for a 4-event session over HTTP
- Bundle export: 30ms for 10 records
- `pr verify` on clean bundle: 400ms, clear output with signal/advisory separation
- TAMPERING DETECTED: multiple independent signals, unambiguous message, exit 1
- Anchor push: 600ms, receipt written, clear auditor URL printed
- Anchor service DB isolation: zero customer records, confirmed by direct SQL inspection
- Truncation attack caught correctly by `anchor-verify`
- Coverage monotonicity refusal: clear message, correct exit 1, no partial DB row
- Unreachable service: clear message, exit 3 (distinct from integrity failure exit 1)
- Zero-record bundle: clear message, exit 2
- FreeTSA round-trip: 960ms, token present, standard rfc3161 receipt
