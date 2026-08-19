# HANDOFF

Last updated 2026-08-19. Branch `main`, in sync with `origin/main` at `1c55c85`.
Site DEPLOYED to provenrail.com, 0.2.32 PUBLISHED to PyPI and tagged `v0.2.32`, and the
**hosted anchor service is LIVE** at `https://provenrail.com/v1/anchors`. All three verified from
a clean `pip install provenrail==0.2.32`: `pr demo`, `pr anchor-push --url https://provenrail.com`,
`pr anchor-verify`, green with a third-party timestamp.
Read this first, then `WORKLOG.md` for history.

## Where things stand

The strategy changed direction this session, deliberately, and the code followed it.

Provenrail no longer sells hosted record storage, because the operator trades as a Lithuanian
`individuali veikla` with no liability shield, and hosting other people's agent records makes him
a GDPR processor personally. `BUSINESS.md` had said so since June; the pricing page was selling it
anyway. What the paid tiers sell now is **independent anchoring**: the customer self-hosts the
AGPL sink, keeps every record, and sends a Merkle root. That is the one thing a self-hoster cannot
manufacture for themselves, and it is sellable today with no company, no certification and no
insurance. See `docs/cost-to-execute-2026-08-18.md` for the liability ladder and where the line
is, and `docs/PRD-anchor-only-service.md` for the design.

Six audits ran this session: CLI/SDK flows, web flows, competitive, cost-to-execute, an
adversarial review of the new anchor code, and a live end-to-end journey against real servers.
The last two found real defects in code that had shipped hours earlier, and they are the reason
to keep running an adversarial pass over anything new: `pr anchor-verify` reported VERIFIED over
bundles it should have refused, three separate ways. All three are fixed and reproduced by tests.

The question that was left to the operator last session, whether to operate a hosted anchor
service, was answered by removing its cost. It runs as a Supabase edge function on the free tier
the project already pays nothing for, so there is no monthly bill to justify before a single
customer exists. `supabase/functions/anchor/`, fronted at `provenrail.com/v1/anchors` by
`functions/v1/anchors.js` so the CLI's `--url` is the product's own domain.

949 tests pass. Ruff clean. `deno check` is now a test.

## Done and verified

- **The hosted anchor service is live and a customer can reach it with no provisioning step.**
  `supabase/functions/anchor/` on the free tier, migration `20260819_anchor_service.sql`,
  fronted on the product's own domain by `functions/v1/anchors.js` and
  `functions/v1/anchors/[id].js`. Authentication is the licence key the Polar webhook already
  mints, verified at the edge with Ed25519, so buying the plan is the entire onboarding.
  Verified live: builder key anchors with no row existing beforehand, free key 403 naming the
  plan, expired key 403 saying renew, malformed and absent keys 401.
- **Every hosted anchor carries an RFC 3161 timestamp** from FreeTSA, whose root is already in
  the verifier's trust store, so `pr anchor-verify` validates the certificate chain with no
  flags and reports "the time is proved by a third party". Falls back to a self-signed receipt
  only when the authority is unreachable, and the fallback cannot wear the stronger label.
- **The auditor page renders at the edge**, `functions/v1/anchors/[id].js`, so it works with
  JavaScript off, and it says what an anchor does *not* prove in the same words as the page the
  self-hosted sink serves. `tests/test_anchor_page_lockstep.py` holds the two together.
- **Three defects found by driving the real thing**, none visible by reading the source:
  the RFC 3161 nonce was non-minimal DER whenever its random bytes began with a zero, so roughly
  one anchor in 250 was silently refused by the authority and fell back to self-signed;
  `pr anchor-verify` printed its strongest result under `[warn]`; and the verifier reported the
  `gen_time` written *beside* an RFC 3161 token rather than the one signed *inside* it, so a
  receipt could display any date it liked while every cryptographic check passed.


- **Anchor-only trust service.** `POST /v1/anchors` (root + coverage only), `GET /v1/anchors/{id}`
  (public, unauthenticated, never names the account), `GET /v1/anchors` (per account).
  `src/provenrail/server/app.py`, storage in `server/storage.py`, `anchor_root()` on all three
  backends in `anchor.py`. Coverage is monotonic per stream and a fork at equal coverage is
  refused. Driven end to end through the CLI in `tests/test_anchor_only.py`, including the two
  attacks that matter: an edited record and a dropped tail both stop matching the receipt.
- **Released as 0.2.31** and tagged `v0.2.31`. PyPI, the wheel, the plugin manifest and
  `provenrail.__version__` all agree.
- **`pr anchor-push` / `pr anchor-verify`.** Verify is deliberately offline and never calls the
  issuing service. It calls `_verify_anchor_receipt`, the same code `pr verify` uses, and also
  runs the bundle's own chain check. It did neither at first, and each omission was a hole: a
  signature over any other root passed for any bundle, a garbage RFC 3161 token counted as a
  trusted timestamp, and editing a payload under its unchanged hash read as VERIFIED. See
  `docs/adversarial-anchor-review-2026-08-18.md`.
- **Anchor conflicts and duplicates settle before the timestamp is minted**, so a refusal costs
  no TSA round-trip, and an identical retry returns the existing anchor instead of a new id.
- **Pricing repositioned** away from hosted storage, HIPAA claim removed, "hosted convenience"
  contradiction fixed. Pinned by two tests in `tests/test_claims_hygiene.py`.
- **The word "attestation" is gone** from shipped copy and CLI output. It names a licensed
  practitioner's opinion under ISAE 3000. The codebase's own word, "anchor receipt", is used.
- **`web/for-agencies.html` and `web/vs-microsoft-agt.html`** shipped, linked from the footer of
  all 20 pages and from the compare page body, in the sitemap. Verified in a browser at 375px and
  1280px.
- **Four flow-audit fixes**: a bad `--tlog-pubkey` no longer reports TAMPERING DETECTED (it was
  exit 1 on a shell typo), `LicenseInfo` is falsy when invalid, `FlightRecorder.session_id`
  exists, the starlette/httpx warning is filtered.
- **EU AI Act page** no longer says Article 50 is "three days away" 16 days after it took force.
- **`/start` no longer says Provenrail can host the record**, which contradicted the whole
  liability position in the guide aimed at the least experienced reader. Homepage plan copy and
  its JSON-LD now match `/pricing`.
- **A dead sink no longer wedges the next `pr quickstart`**: the pid is checked for liveness and
  a stale file is cleared with a line saying so.

## Open, and why

- **The nav carries 12 items on the homepage**, where Linear ships 5 and Stripe 6, and five of
  them are `/#anchor` links that jump back to the homepage from every other page. Cutting it is
  an information-architecture decision across 20 pages, so it was left for a deliberate pass
  rather than folded into a fix-up commit. `docs/ux-audit-2026-08-18.md` finding 4.
- **DM Sans is a widely used free Google font.** Optical sizing and its stylistic alternates are
  now on, which fixes the flatness, but the design research asks for a typeface that is not one
  click away for everyone. Evaluate Satoshi, General Sans or Clash Display for display headings.
- **Server auth and RBAC have never been verified against live Supabase**, only in-process.
- **RFC 3161 through `pr anchor-push` is solved for the hosted service and still open for the
  self-hosted sink**: the Python server falls back to a local anchor in open mode, and
  `--anchor rfc3161` on the server only affects the scheduler. The hosted path is unaffected.
- **The positive licence-key path was proven against the real module, not the real secret.**
  `PROVENRAIL_LICENSE_SECRET` is a Supabase secret and cannot be read back, so the end-to-end run
  used a test issuer via `LICENSE_PUBLIC_KEY` against the live database. The first real purchase
  is still the first production key this code will ever see.
- **Float metadata raises `CanonicalError` at emit time** with no pre-check and no mention in the
  docstrings or the quickstart, so anyone passing a confidence score hits it on their first run.

## Next in order

1. **Get the first paying customer.** The offer is now complete and reachable: the service runs,
   the licence key is the only credential, and the pricing page describes what actually happens.
   Nothing else on this list matters until someone has paid. Distribution is still zero.
3. **Publish `/for-agencies` and `/vs-microsoft-agt`** anywhere real people are: Indie Hackers, X,
   the relevant subreddits. Both pages exist; distribution is still zero. See
   `docs/distribution-virality-playbook.md` in engine-agentic.
4. **Go verifier binary.** Auditors do not run Python, and "verify it yourself" is the core claim.
   5 to 10 days per `docs/cost-to-execute-2026-08-18.md`.
5. **21 CFR Part 11 validation pack.** A document sale, legal under `individuali veikla`, and the
   fastest high-value euro.

## Traps

- **`supabase functions deploy` does not type-check.** A genuine type error deploys happily and
  fails at the first request that reaches the line. `deno check` runs as a test now; keep it.
- **The RFC 3161 nonce must be a minimal DER INTEGER.** Prepending `0x00` unconditionally is the
  obvious thing to write and is wrong: it is needed only when the high bit is set. FreeTSA
  rejects the non-minimal form, the service falls back to self-signed, and it reads as the
  authority being flaky rather than as our encoding being wrong. `tests/test_rfc3161_der.py`.
- **The trusted time comes out of the token, never from the field beside it.** That field is not
  covered by the authority's signature. Anything that reports it as "the timestamp" is reporting
  a number the issuer chose.
- **The hosted service must never gain a field a record could arrive in.** That absence is the
  whole reason a sole proprietor can operate it.
  `tests/test_anchor_edge_function.py::test_the_edge_function_cannot_receive_a_record` reads the
  handler and fails if a fourth body field appears.

- **Never write a second verifier.** All three anchor-verify holes came from reimplementing in
  the CLI what `verifier/verify.py` already did correctly. The weaker copy looked right and was
  not. If a check exists, call it.
- **Do not sell hosted record storage.** Tier 5 and 6 on the liability ladder need a company
  first. `tests/test_claims_hygiene.py::test_no_page_sells_a_liability_the_operator_cannot_carry`
  will fail the build if the copy drifts back; do not weaken it to make a page pass.
- **Naming HIPAA 164.312(b) as a control a report maps to is fine.** Selling a mapping is content.
  The banned thing is offering to be a business associate. The test draws that line on purpose.
- **`_checked_root` runs before any timestamp is minted.** Timestamping an unvalidated root would
  produce a receipt that can never match any bundle: an attestation-shaped object that proves
  nothing. Do not move that check later for convenience.
- **The anchor coverage check is the product, not a limitation.** Anyone who proposes relaxing it
  so a customer can "fix" a stream is proposing that we sign a rewritten history.
- **Two pages landed inside unrelated commits** (`abbd278` carries `vs-microsoft-agt.html`)
  because `git add -A` swept in a subagent's in-flight file. Watch for this when agents write
  files while the main session commits.
- The `/pv` 501 console error on a local `python -m http.server` is the analytics beacon, not a
  page defect. It works on Cloudflare, where `functions/pv.js` answers it.

## Environment

- Python venv: `/Volumes/T7/Projects/AgenticTools/.venv` (3.14). Run `pytest -q` from the repo
  root; `--timeout` is not available, pytest-timeout is not installed.
- Lint: `python -m ruff check src tests`.
- Local site: `cd web && python3 -m http.server 8901`. Clean URLs are a Cloudflare Pages feature,
  so `.html` is needed locally but not in production. Do not add `/x /x.html 200` rewrites to
  `web/_redirects`; the header comment there explains the redirect loop it causes.
- Polar credentials at `~/.config/provenrail/polar.env`. Supabase project `provenrail-production`
  (ref `jzgamrptvsdxnwtuascx`, eu-central-1).
- Anchor signing key at `~/.config/provenrail/anchor-key.env`, and the operator's own test
  account key at `~/.config/provenrail/anchor-selftest.env`. Both chmod 600, neither in the repo.
  The public half is `06b41ad8a0ee2860a3e6e0a871fd0966685aa21bb7eec64664674b1afc366f50`; it is in
  every receipt the service self-signs, so rotating it invalidates those and nothing else.
- Deploy the anchor function with `supabase functions deploy anchor --project-ref jzgamrptvsdxnwtuascx`,
  and the site with `npx wrangler pages deploy web --project-name provenrail` from the repo root
  (wrangler bundles `./functions` relative to the working directory, not to `web/`).
