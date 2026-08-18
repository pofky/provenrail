# HANDOFF

Last updated 2026-08-18. Branch `main`, in sync with `origin/main` at `e9996c9`.
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

Three audits ran this session (CLI/SDK flows, web flows, competitive) and the product came out of
them in good shape. The defects found were small and are fixed. The largest problem was not a bug,
it was the pricing page promising something the seller could not carry.

889 tests pass, 2 skipped. Ruff clean.

## Done and verified

- **Anchor-only trust service.** `POST /v1/anchors` (root + coverage only), `GET /v1/anchors/{id}`
  (public, unauthenticated, never names the account), `GET /v1/anchors` (per account).
  `src/provenrail/server/app.py`, storage in `server/storage.py`, `anchor_root()` on all three
  backends in `anchor.py`. Coverage is monotonic per stream and a fork at equal coverage is
  refused. Driven end to end through the CLI in `tests/test_anchor_only.py`, including the two
  attacks that matter: an edited record and a dropped tail both stop matching the receipt.
- **`pr anchor-push` / `pr anchor-verify`.** Verify is deliberately offline and never calls the
  issuing service.
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

## Next in order

1. **Deploy.** The anchor service exists in the code and nowhere else. Nothing converts until
   there is a URL a customer can point `pr anchor-push --url` at. This is the whole game.
2. **Price the anchor tier and wire it to Polar.** The pricing page now describes anchoring but
   the Polar products still describe the old event tiers.
3. **Publish `/for-agencies` and `/vs-microsoft-agt`** anywhere real people are: Indie Hackers, X,
   the relevant subreddits. Both pages exist; distribution is still zero. See
   `docs/distribution-virality-playbook.md` in engine-agentic.
4. **Go verifier binary.** Auditors do not run Python, and "verify it yourself" is the core claim.
   5 to 10 days per `docs/cost-to-execute-2026-08-18.md`.
5. **21 CFR Part 11 validation pack.** A document sale, legal under `individuali veikla`, and the
   fastest high-value euro.

## Traps

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
