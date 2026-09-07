# Provenrail Work Log

## Currently Active

_No active work._ 0.4.2 is shipped: PyPI, tagged, site deployed, and the whole install path
proven from a fresh public clone with no CLI present and with one. The guard was rebuilt this
session around what it screens rather than what it matches, on two measurements: 923
interruptions across 36,977 real commands before, 222 after, and 40 of 40 documented data-loss
commands allowed before, 0 after. **The one thing left is still posting.**
`Marketing/launch-reddit-claudeai.txt` and `Marketing/launch-show-hn.txt` are rewritten around
that measurement and every claim in them is a test in this repo.

## Change History

| Date | Project | Description |
|------|---------|-------------|
| 2026-09-07 | provenrail | 0.4.0 to 0.4.2, the guard rebuilt on measurement. Screened the VERB before: over 36,977 Bash commands from 1,247 real transcripts the 0.3.1 rules interrupted 923 and refused 305, almost all ordinary work, and the two `rm` rules were 687 of them. Meanwhile 40 of 40 commands taken from public Claude Code data-loss issues (#34327, #81508, #45974, #85879, #46444, #80868, #90808 and others, each confirmed via the GitHub API) were ALLOWED. Rules now carry a `predicate` (`src/provenrail/predicates.py`): `delete.catastrophic` resolves targets against the repo root, `git.would_lose_work` runs `git status` and checks for unpushed commits so the git rules are silent on a clean tree. Three new default packs (`git-worktree`, `database`, `cloud`), `not_tool` scoping so command rules stop reading documents and search queries, `command.not_a_rehearsal` for `--dry-run` and `--local`, quote-aware segmentation, and chmod/TRUNCATE/.env.example matcher fixes. After: 222 interruptions and 16 refusals, 15 of the 16 our own fixtures; 0 of 40 data-loss commands allowed. New `/guard-card` with `shell.command_shape`, which drops every operand so a block is postable. Hook matcher widened to `*`, which made three advertised rules reachable for the first time (credential reads, MCP delete methods, edits to the guard's own config). Two silent-disarm bugs found by driving a fresh clone: `pr guard hook` with no config armed nothing, so installing the CLI turned the guard off, and an older `pr` shadowed a newer plugin's rules. `tools/measure_guard.py` ships the measurement. 1274 tests |
| 2026-09-07 | provenrail | Repositioned on measurement, then shipped 0.3.0. Research (`docs/repositioning-research-2026-09-07.md`): 14 referred visits in 17 days and every signup the operator's, so a reach problem, but the compliance buyer needs the processor role we refuse and Art 12 moved to Dec 2027, so the framing had to move to something felt daily and before the incident. Guard plugin now needs nothing installed (stdlib-only `guard_standalone.py`, vendored `rules.json` from `tools/vendor_guard_rules.py`, 39 lockstep cases through both engines, `/guard-status` + `/guard-rules`). New `pr attest` / `attest-verify` / `attest-anchor`: signed AI authorship attestation over git, anchored with a real FreeTSA timestamp against production and rejected four ways when tampered. Homepage, guardrails page, pricing, docs, llms.txt and marketing copy all moved to the new framing; new `/ai-code-attribution`. Five claims-hygiene tests pin the copy to the code, each proven to fail. 1019 tests |
| 2026-08-21 | provenrail | Conversion pass on the whole funnel: homepage leads with the proof (tamper widget moved above the install snippet, hero rewritten for the audit-trail buyer), one free anchor per account (`trial-license` edge fn + allowance gate in `anchor/account.ts`, driven by `tests/deno/anchor_gate_test.ts`), account page gained the five-step first-anchored-run card, `pr anchor-push` defaults its URL, key and receipt path, `pr verify` names the time gap it cannot close, float error says what to pass instead, "sink" became "recording server" in every user-facing string; DISTRIBUTION.md written; 950 tests |
| 2026-08-10 | provenrail | Health check + fixes: verifier runs now counted (`verify_run`/`verify_own`), `/pv` edge proxy so `country` is finally recorded, pricing CTAs carry the plan straight to checkout, nav honest about auth on every page, `pageview` verify_jwt pinned in config.toml after a redeploy 401'd it; 870 tests |
| 2026-08-06 | provenrail | Prod sweep: /pricing page, canonical-host redirects, CSP + HSTS, npm 0.2.30 lockstep, IndexNow submit, live verification |
| 2026-08-06 | provenrail | Audit: 857 tests green, site live, on-page SEO strong; found zero external traffic, no `/pricing` page, npm version drift |
| 2026-08-05 | provenrail | Web polish: footer nav on one row, decorative status dots removed |
| 2026-08-04 | provenrail | 0.2.30 released; repo split into public code + private strategy; own Polar org |

## Notes

- Distribution, not product quality, is the binding constraint. Launch assets are written and unused in `docs/DISTRIBUTION-KIT.md`, `docs/launch-posts.md`, `docs/GTM-2026-08.md`.
- Strategy, GTM and owner runbooks live in the private `provenrail-internal` repo. Never commit them to the public tree.

## 2026-08-19 - Hosted anchor service live, 0.2.32

Opened the hosted anchor service on the Supabase free tier, which removes the monthly cost that
made "should we operate one" an open question. Authentication is the licence key Polar already
mints, so buying the plan is the entire provisioning step. Every anchor now carries an RFC 3161
timestamp from FreeTSA rather than one we asserted ourselves.

Driving it against the live database found three defects that reading the source did not: a
non-minimal DER nonce that made roughly one anchor in 250 fall back to self-signed, a success
finding printed as a warning, and a verifier that reported the date written beside an RFC 3161
token instead of the one signed inside it.

Published 0.2.32, tagged `v0.2.32`, deployed the site, and updated the copy that said the service
was not open. Full flow verified from a clean PyPI install.
