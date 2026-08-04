# Provenrail

**Guardrails for AI agents, with a receipt.** Destructive tool calls are blocked before
they run, and every decision is signed into an off-box, hash-chained record that anyone
can verify, trusting neither the agent nor the sink.

### 30 seconds, no code: guard Claude Code

Inside Claude Code:

```
/plugin marketplace add pofky/provenrail
/plugin install provenrail-guard@provenrail
```

Then once per project:

```bash
uv tool install provenrail   # or: pip install provenrail
pr quickstart                # local sink, no account, nothing leaves your machine
pr guard install             # arms destructive + secrets + production + access
```

`rm -rf`, `terraform destroy`, `git push --force`, `DROP TABLE`, `chmod 777` and leaked
API keys are now denied at the tool boundary, and the agent is told which rule fired.
Actions that need a human (touching `.env`, deploying, migrating) become a permission
prompt instead of a hard block, and the approval is recorded as human oversight. Run
`pr guard receipt` and `pr verify guard-receipt.json` to check the record yourself.
Full guide: <https://provenrail.com/claude-code-guardrails>

### The record underneath

Install the SDK, capture model calls and tool calls, and every record is pushed to an
append-only sink where it cannot be silently altered, reordered, deleted, or back-dated.
Anyone can verify the record with the open-source `pr-verify` tool.

This is the self-serve **Provenrail** SKU. It is a forensic black box, not a
compliance certifier. The regulated **Audit Trail** SKU (cross-account WORM, witnessed
anchors, TEE-backed keys, regime attestation reports) is a separate, sales-assisted tier.

## What it guarantees, and what it does not

Read this before trusting it. Honesty about the boundary is the product.

| Property | Guaranteed? | Mechanism |
|---|---|---|
| A flushed record cannot be altered without detection | Yes | client Ed25519 signature + hash chain; server re-chains on receipt |
| Records cannot be reordered or deleted mid-stream without detection | Yes | dual chain (client `prev_hash` links + server receipt chain) |
| Records existed no later than a trusted time | Yes, when anchored | RFC 3161 trusted timestamp over a Merkle root of the receipt chain |
| The sink cannot fabricate agent actions | Yes | only the device key can sign; the sink does not hold it |
| **Completeness** (a hostile agent cannot skip recording) | **No, never claimed** | an in-process logger can refuse to emit; the out-of-process sidecar narrows this (see below) but only egress control makes capture mandatory |
| The sink cannot equivocate (show two anchor histories) or drop published anchors | Yes, when witnessed | per-account RFC 6962 transparency log + independent witness cosignatures (SPEC.md section 9) |
| Tail records after the last anchor cannot be truncated | Bounded | anchor frequency for the unanchored tail, plus client pin; published anchors are witness-protected |
| Protection against the machine owner (B2C single host) | **No** | the owner holds the key and can choose not to flush |

The honest one-line claim: **"Anything your agent did, once it reaches the sink, is
immutable and verifiable. Completeness is never claimed."**

### Threat model
The adversary is the **agent** (or a prompt-injection of it). The agent can refuse to log,
but it cannot forge, alter, reorder, or delete anything that already reached the sink, nor
back-date it past a trusted timestamp, without `pr-verify` reporting it. Defense against a
**malicious sink operator** (who could truncate the tail or show different histories to
different parties) is the **transparency / witness log**: a per-account append-only RFC 6962
Merkle log over the anchor receipts, with inclusion and consistency proofs an auditor checks
offline and independent witness cosignatures on each head. A witness will not cosign a fork or
a rollback, so a sink cannot equivocate without compromising a quorum of witnesses. Honest
boundary: witnessing proves append-only-ness and anti-equivocation, never completeness; an
un-cosigned checkpoint is reported amber, not green (SPEC.md section 9.8). The client pin still
covers the unanchored tail between the last cosigned checkpoint and now.

**Capture topology and the completeness gap.** In-process capture (the SDK and the drop-in
instrumenters) is the easiest to adopt but shares the agent's address space, so a hostile agent
can skip the logger. The **capture sidecar** (`pr sidecar`) is a recording reverse proxy: the
agent points its model client at the proxy, which forwards to the real provider and records each
call from a separate process the agent does not control. To dodge recording the agent must then
avoid the proxy entirely, which means getting no model response when egress is locked to the
proxy. The sidecar does not by itself prove completeness; its strength equals the egress control
around it. The deployment contract is "force all model egress through the sidecar" (network
policy / firewall). With that, capture is mandatory; without it, the sidecar is a strong default,
not a proof. We never overstate this.

## Architecture

```
agent process            off-box sink                     auditor
-------------            ------------                     -------
SDK (capture)            ingest API (append-only)         pr-verify
  model calls    --->    server receipt chain    --->     recompute every
  tool dispatch          (re-chains on arrival)           hash, signature,
  hash-not-content       RFC 3161 anchor over             chain link, Merkle
  sign + chain           Merkle(receipt heads)            root, timestamp
```

Two independent chains: the client signs and links each record (`prev_hash`), and the
server independently re-chains records in arrival order. A coherent re-chain by a malicious
sink is still caught by the client chain; a client edit is caught by the server's stored
bytes. Anchoring binds the whole thing to a trusted external time.

## Quick start: guard your coding agent (30 seconds, no code)

Repeated from the top for readers who arrived here from the table of contents. Either install
the [Claude Code plugin](plugins/provenrail-guard/) (`/plugin marketplace add pofky/provenrail`,
then `/plugin install provenrail-guard@provenrail`), or wire the hooks directly:

```bash
uv tool install provenrail
pr quickstart        # local sink, no account, nothing leaves your machine
pr guard install     # arms destructive + secrets + production + access, installs the hooks
```

From your next Claude Code session in that folder:

- `rm -rf`, `terraform destroy`, `git push --force`, `DROP TABLE`, `chmod 777` and leaked
  API keys are **blocked before they run**, with the rule that fired shown to the agent.
- An action that needs a human (touching `.env`, a deploy, a migration) becomes a permission
  prompt, and your approval is recorded as human oversight rather than being blocked outright.
- Every decision is Ed25519-signed and hash-chained.

```bash
pr guard status      # what is armed, and what it blocked
pr guard receipt     # export the proof, then verify it yourself
```

The verdict is computed offline, before anything touches the network, so a sink that is down
can never turn a deny into an allow. If a decision cannot be recorded it is journalled locally
and reported as unsigned and pending, never as proof.

Honest scope: this covers tool calls Claude Code routes through its hooks. It cannot constrain
a process that never calls them. Other agent hosts are not claimed until their hook contract
has been read and tested.

## Quick start: record your own agent

Simplest possible: one command to set up, two lines in your code.

```bash
pip install -e ".[anchor]"
pr quickstart        # starts a local sink and writes .provenrail.json (no tokens to copy)
```

```python
import provenrail as fr

with fr.record("my-agent"):
    ...   # your agent runs; model and tool calls are captured automatically
```

That is the whole setup. `fr.record(...)` provisions a stream, builds the recorder, opens a
signed session, and seals + drains it off-box on exit. Connection details come from
`.provenrail.json` (or env vars, or `fr.configure(...)`), so your code carries no URLs or
tokens. A decorator form exists too: `@fr.recorded("nightly-job")`. Stop the local sink with
`pr quickstart --stop`. Point at your own or a hosted sink with `pr quickstart --url <URL>`.

Run your agent as many times as you like: each run becomes its own sealed session on the same
stream, and one export verifies them all. The first run creates `.provenrail.key`, the device
signing key reused by every later run; keep it out of version control (gitignore it next to
`.provenrail.json`). Losing it only means future runs sign under a new identity.

### TypeScript / Node

The same capture is available for TypeScript agents (Node 20+), in `sdk-js/`:

```bash
npm install provenrail
```

```ts
import { record } from "provenrail";

await record("my-agent", async (pr) => {
  await pr.recordModelCall("openai", "gpt-5", { prompt }, out, { usage });
});
```

A run recorded in TypeScript is byte-for-byte compatible with one recorded in Python: the same sink
accepts it and the same two verifiers (`pr verify` and the in-browser `verify.js`) prove it. This is
enforced by a cross-language test (`tests/test_js_sdk.py`): records signed by the JS SDK are verified
by the Python verifier and the JavaScript verifier, and tampering is caught by both.

Other entry points:

```bash
pr demo              # self-contained: records a session, anchors it, writes bundle.json + pin.json
pr verify bundle.json --pin pin.json     # verify, trusting neither agent nor sink
pr report --regime eu-ai-act bundle.json --md   # regulatory attestation
pr diff run-a.json run-b.json            # diff two runs with provable fidelity
fr serve --anchor rfc3161                # run the sink yourself (real trusted timestamps)
pr sidecar --upstream https://api.openai.com   # out-of-process capture proxy (point base_url here)
pr witness --log <origin>=<pubkey>       # run an independent witness on separate infrastructure
# or: docker compose up
```

### Out-of-process capture (harder to skip)

```bash
pr sidecar --upstream https://api.openai.com --port 8788
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8788")  # the only change in your code
```

Every model call now flows through a recorder in a separate process. Lock outbound model egress
to the sidecar (firewall / network policy) and capture becomes mandatory rather than a default.
Add `--fail-closed` to refuse any call that cannot be recorded.

### Drop-in capture (one line per SDK)

```python
from provenrail.integrations import instrument_openai, instrument_anthropic, instrument_mcp
instrument_openai(openai_client, fr)      # every model call now captured automatically
instrument_anthropic(anthropic_client, fr)
instrument_mcp(mcp_session, fr)           # every MCP call_tool captured as an mcp_call
```

```python
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder

prov = provision_stream("http://127.0.0.1:8000", label="my-agent")
fr = FlightRecorder("http://127.0.0.1:8000", prov["write_token"], prov["stream_id"])

@fr.tool("search")
def search(q): ...

with fr.session({"agent": "demo"}):
    fr.record_model_call("anthropic", "claude", request="...", response="...")
    search("hello")                       # captured at the tool-dispatch boundary
    fr.record_decision("ship it")
```

Share a read-only proof: `GET /share/<share_token>`. Export + verify:

```bash
curl -H "Authorization: Bearer $READ_TOKEN" \
  http://127.0.0.1:8000/v1/streams/$STREAM/export > bundle.json
pr verify bundle.json
```

Privacy default is **store-hash-not-content**: prompts and outputs are SHA-256 hashed, not
stored, unless you pass `capture_content=True`. Tokens are scoped strictly: `write` can only
append, `read` can only read, `share` is public read-only, and no delete scope exists.

## What is in the box

Integrity core
- Capture SDK with sessions, heartbeats, store-hash-not-content default, a `@tool`
  decorator for the local tool-dispatch boundary a network proxy never sees, and a
  non-blocking async transport (background batched flush with retry and an ordered drain
  on session close, so capture never slows the agent).
- Drop-in auto-instrumentation for the OpenAI and Anthropic SDKs (sync and async), a
  LangChain / LangGraph callback handler, Agno tool hooks, Claude Agent SDK hooks, and MCP
  (Model Context Protocol) `call_tool` capture so tool use through MCP is recorded at the
  dispatch boundary.
- Append-only sink with an independent server receipt chain, account API keys, strictly
  scoped per-stream tokens (no delete scope), per-stream and signup rate limits, DoS caps,
  idempotent ingest, WAL concurrency, and automatic anchoring on a schedule.
- Client-side pin: a signed checkpoint the agent keeps, so `pr verify --pin` detects a
  malicious sink truncating the tail.
- RFC 3161 trusted-timestamp anchoring with full verification: the standalone `pr verify`
  checks the CMS signature and certificate chain against a bundled TSA root, trusting
  neither the agent nor the sink.

Daily-use surface (the dashboard makes the integrity worth opening every day)
- Run Explorer at `/app`: an authenticated dashboard over every stream, session, and event,
  with live integrity verdicts, token and estimated-cost analytics rolled up from captured
  usage, an expandable per-event timeline, and a live-session indicator. Mobile-first.
- Integrity alerting: subscribe webhooks (`/v1/webhooks`, or the Alerts tab) and get an
  HMAC-signed POST the moment a stream stops verifying (`integrity.tampered`), recovers, or
  lands its first trusted anchor.

Trust and compliance surface
- Hosted verifier at `/verify`: anyone can drop a bundle and re-run verification with no
  install and no account. It verifies FULLY CLIENT-SIDE using a second, independent
  JavaScript verifier (`web/verify.js`, WebCrypto), so you trust not even our server; it is
  conformance-tested to agree byte-for-byte with `pr verify`. The lockstep covers enforcement
  as well as integrity: the browser verifier replays the committed policy, including spend
  caps, and its cost arithmetic is parity-tested against `pricing.py` so a budget can never
  replay differently in the browser than on the CLI.
- Embeddable live badge: `<img src=".../badge/<share_token>.svg">` re-verifies on every load
  and turns amber or red if the record ever stops verifying.
- One-click evidence pack (`fr pack`, or `/v1/streams/{id}/evidence`): a self-contained,
  reproducible ZIP with the bundle, a regime attestation (EU AI Act Art. 12 / HIPAA
  164.312(b) / generic), a verification guide, and a SHA-256 manifest, for an auditor.
- SIEM export (`/v1/streams/{id}/export.ndjson`): one flattened, hash-linked record per line
  for Splunk / Elastic / Datadog, content-hashed by default so it does not leak prompts.
- Premium, mobile-first, shareable proof page with a live verified badge.
- `fr` CLI (serve / demo / verify / report / pack), Dockerfile, CI, ruff-clean source, a
  marketing site in `web/`, and a formal `SPEC.md` so anyone can build an independent verifier.

## Specification
The evidence format and the exact verification algorithm are in `SPEC.md`. A clean
`pr verify` recomputes every hash, signature, chain link, Merkle root, and timestamp from
scratch; it never trusts a derived field in the bundle.

## Status
244 tests passing including hermetic real-RFC-3161 verification with tamper cases
(content edit, deletion, coherent malicious re-chain, backdating, tail truncation),
accounts/auth, token revocation and expiry, rate limiting, auto-anchoring, async transport,
Unicode NFC canonicalization, the Run Explorer dashboard and analytics, cost estimation,
integrity alerting, the hosted verifier and embeddable badge, evidence packs, SIEM NDJSON
export, MCP capture, and a JavaScript verifier conformance-tested against the Python one.
Plus committed-policy verification (the active guardrails are signed into the session and
re-checked offline), richer guardrail rules (content gates and per-session limits), and heuristic
coherence signals in both the verifier and the dashboard. The **public transparency / witness
log** is shipped: per-account RFC 6962 Merkle log over
the anchor receipts, inclusion and consistency proofs, C2SP checkpoint / signed-note /
cosignature wire formats, a reference witness plus a C2SP witness HTTP client with split-view
and rollback alarms, public `/v1/tlog/{account}/checkpoint|inclusion|consistency` endpoints,
verifier steps 7 to 8 in both Python and JavaScript (conformance-tested on witnessed,
unwitnessed, and forged-proof bundles), and a green-witnessed / amber-proofs badge axis.
Enterprise and forward-looking layers are shipped too: RBAC (org members, least-privilege
owner/admin/member/viewer roles, per-member keys), OIDC single sign-on (`server/sso.py`, strict
RS256/EdDSA ID-token validation with JIT provisioning), a hash-chained tamper-evident access log
(audit-of-the-audit), an agent identity / KYA registry (the verifier confirms the device key is
the one registered for the agent), an active policy / guardrail layer (declarative deny /
require-oversight rules and a per-session spend cap enforced at the dispatch boundary, with the
decision recorded in the signed chain), and run replay/diff with provable fidelity (`pr diff`,
diff computed over verified bundles). Dashboard and pages verified end to end in a real browser
(dark / light / mobile), including fully client-side verification.

**Selective-disclosure redaction** reconciles an immutable trail with the right to erasure: a
sensitive field is recorded as a salted commitment (never cleartext at the sink), the opening is
held only by the operator, and you can later disclose it to an auditor (any verifier confirms it
opens the commitment) or erase it permanently (destroy the opening; the field becomes
unrecoverable while the record stays tamper-evident and verifiable). Wrap a value with
`provenrail.redactable(...)`; check disclosures with `pr verify --openings` or `pr disclose`.
Both the Python and JavaScript verifiers recompute the commitment identically (conformance-tested).
See SPEC section 17.

Independently-verifiable credibility, auditor artifacts, and trust robustness are deeper too:
frozen **conformance vectors** (`tests/vectors/`, with a documented manifest) let anyone validate
their own verifier against the same golden bundles; an **auditor-grade verification report**
(`pr report --html`, also folded into the evidence pack as `report.html`) renders the full verdict,
findings, trusted-time and witness status, committed-policy result, coherence signals, and a
chronological timeline as a printable document; and TSA trust is now operator-extensible
(`pr verify --tsa-root host=cert.pem`, `trust.add_root(...)`) with a `MultiTSAAnchor` that fails
over across timestampers for availability.

Guardrails are configurable without touching agent code and alert in real time: enable
prebuilt rule packs by name (`{"policy": {"use": ["destructive", "secrets", "money"]}}`,
seven packs (35 rules) covering destructive tools, leaked credentials, money movement, production
changes, privilege escalation, exfiltration shapes, and per-session blast-radius caps; list
them with `pr rules`, check which would match your actual tool names with
`pr rules --check bundle.json`), or declare a
`policy` block in `.provenrail.json` (deny / require_oversight / limit rules with glob and regex
matching, plus spend budgets) and the deployment owner sets the rules even if someone else
wrote the agent. A malformed policy is rejected loudly rather than ignored, because a typo that
silently disables a guardrail leaves you believing you are protected when you are not. When a rule
blocks an action, a `policy.denied` webhook fires **at ingest**, in the same moment the record
lands, not on the anchor schedule; delivery is HMAC-signed and runs off the request path so a slow
endpoint of yours can never slow the agent. Review afterwards with `pr risk bundle.json` (exits
non-zero if anything was blocked, so CI can gate on it), the dashboard's Blocked tile and red
timeline rows, or the NDJSON SIEM export. Nothing is suspicious by default: there is no built-in
threat library and no anomaly detection, so with no policy declared nothing is ever blocked.

**Spend budgets** stop the failure everyone actually has: an agent that runs all night across
hundreds of short sessions and is discovered when the invoice arrives. A budget denies the model
call that would cross it, at one of three scopes:

```json
{"policy": {"budgets": [
  {"scope": "session", "limit_usd": 5,   "warn_at": 0.8},
  {"scope": "day",     "limit_usd": 50},
  {"scope": "total",   "limit_usd": 500}
]}}
```

`day` and `total` survive process exit via a local ledger, so they bind across runs where a
session cap cannot. Crossing `warn_at` does not block; it writes a warning into the signed chain
and fires a `budget.warning` webhook while the run can still be stopped, with `budget.exceeded`
when a cap actually bites. The budgets are part of the committed policy hash, so an auditor can
prove which cap was in force. Check spend with `pr spend` (per run from a bundle, per agent from
the ledger) and headroom with `pr guard status`.

**Finance rollups** answer the question a budget owner actually asks. `GET /v1/spend?group_by=`
groups estimated spend by `agent`, `project`, `team`, `model`, `day`, `stream`, or `session`
over any date window, with `&format=csv` for the spreadsheet the conversation happens in. The
grouping keys are your own session metadata, which lives inside the signed record, so a finance
report is derived from the same evidence as everything else instead of a side table someone
could edit. Spend with no `project` set rolls up as `(unattributed)` rather than vanishing: a
report whose rows do not sum to the total makes an underspend look real.

**Reconcile the estimate against the bill.** `pr reconcile run.json --invoice usage.csv` aligns
recorded spend with a provider usage export and reports the drift per model, plus the finding
that matters most: spend on the invoice that no recorded run explains, which means calls
happened outside the recorder. It exits non-zero when it finds any, so a finance cron can gate
on it. The invoice is an untrusted input used to interpret the record, never to amend it.

Costs are **estimates** from reported token usage and a dated public price table, never a
substitute for your provider's invoice, and they are labelled that way everywhere. The estimator
handles what naive ones get wrong: cached tokens priced at the cache rate and not double-counted
(providers disagree about whether the prompt total already includes them), and reasoning tokens
reported but never billed twice. Negotiated or committed-use rates go in
`.provenrail-prices.json` and override the list price. A model with no verified rate is reported
as unpriced rather than silently counted as free.

**Approvals for agents with no human at the keyboard.** Inside Claude Code a
`require_oversight` rule becomes the permission prompt, and the person answering it is the
oversight. A headless agent has no prompt, so the same rule could only deny. Set
`approval_timeout` and the agent instead pauses, opens a request, and an `approval.requested`
webhook delivers a one-click approve and a separate deny link to whoever is on call. An
approval is recorded as a `human_oversight` event in the agent's own signed chain, and the
policy is then re-evaluated: the approval flows *through* the guardrail rather than around it.
It fails closed in every other case, including an unanswered request, an expired link, and an
unreachable sink. The two links are unrelated single-use secrets stored only as hashes, so a
link prefetcher cannot approve anything and a leaked database cannot approve anything. Only
`require_oversight` is ever offered to a human: a hard `deny` and a blown budget are decisions
you already made.

**Replay scrubber.** The session view steps through a run one action at a time (arrow keys, a
scrub track, a detail pane) and will compare it against any other run of the same agent,
marking the steps that diverge and jumping to the first one. That is where debugging actually
starts: the run that broke only means something next to the run that worked. The in-browser
alignment is a display aid; `pr diff` is the version that runs over verified bundles.

The active policy / guardrail layer is deeper now: the policy is committed into the signed
session-start record (so a verifier proves which guardrails were in force and that no executed
action violates a re-verifiable deny / limit / spend rule, SPEC section 13), with content gates
(`arg_contains` regex over argument text, for secret / PII blocking) and per-session call limits
(`max_per_session`). The verifier and dashboard also surface heuristic coherence signals
(clock skew, time gaps, missing usage, no-governance runs, self-inconsistent seal) that point a
reviewer at structural oddities without ever changing the cryptographic verdict (SPEC section 14).

Hosted-readiness and out-of-process layers are shipped too: a persisted server identity (the
transparency-log and KYA-registry keys live in the DB so a sink reboot keeps the same public
keys an auditor pinned), usage metering with per-account monthly plan quotas and a `GET /v1/usage`
billing surface (`server/plans.py`), a standalone **out-of-process witness** (`pr witness`,
`server/witness.py`) that speaks the C2SP add-checkpoint protocol so a hosted sink can earn the
witnessed-green path against a witness on independent infrastructure, and the **capture sidecar**
(`pr sidecar`, `sidecar.py`) that records model calls from a process the agent does not control.
333 tests, ruff clean, zero em/en glyphs.

Not yet shipped: cross-account WORM storage, a Go verifier (no toolchain here yet), SAML and a
browser SSO redirect flow, multi-TSA trust roots, and the actual cloud deployment plus payment
integration (the metering and plan plumbing is in place; wiring a real provider and infra is an
ops step, not code shippable here). Roadmap in `STRATEGY.md`; design in
`../DESIGN-agent-audit-trail.md` section 11.

## License

Open-core, dual-licensed (see `LICENSING.md`):

- **MIT** for the client SDK, the `pr-verify` verifier, the bundle format and `SPEC.md`, and the
  web verifier. Verify any Provenrail record with a permissively-licensed tool, no strings.
- **AGPL-3.0-or-later** for the server / sink (`src/provenrail/server/`). Self-host freely; a
  commercial license is available for proprietary or closed-source-SaaS use
  (`hello@provenrail.com`).

Provenrail is evidence tooling, not legal advice or a compliance guarantee; completeness is never
claimed. See `DISCLAIMER.md`. Business model in `BUSINESS.md`, moat analysis in `MOAT.md`,
regulatory mapping in `COMPLIANCE.md`.
