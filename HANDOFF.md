# HANDOFF

Last updated 2026-09-16. Branch `main`, tag `v0.5.0` (one commit behind `main`, see below).
**0.5.0 is built, proven and NOT on PyPI.** The upload is blocked for the agent and is written
up in `Marketing/release-0.5.0-operator-steps.txt`. The site is deployed and current. Read this
first, then `WORKLOG.md` for history.

## Where things stand

The wedge the 0.4.x guard was aimed at closed underneath it. Auto mode is now the default
permission mode for interactive sessions on Pro, Max and Team, it runs `git status` before a
command that would discard uncommitted work, and it refuses a critical-path `rm` even when a
hook says allow. That is most of what the destructive pack sold, given away free by the vendor,
and no amount of rule quality wins it back.

Two things auto mode does not do, and 0.5.0 is built on exactly those two.

**There is no dollar cap anywhere in the permission system.** `/guard-budget 25` prices the
agent's own transcript and refuses the next tool call once the day's estimate crosses the
number. Estimated, and the word appears wherever the figure does, because a transcript carries
tokens, not prices.

**The classifier is simply absent outside an interactive paid session.** `claude -p` and the
Agent SDK start in Manual on every plan, and so do Bedrock, Google Cloud's Agent Platform,
Microsoft Foundry and Claude Platform on AWS. Hooks fire in all of them. That is where the same
policy still buys something, and it is CI, schedules and unattended runs, where nobody approves
a prompt.

**The thing that pays out on day one is `pr report`.** It reads the Claude Code transcripts
already on the machine, prices them per project and per day, and replays every tool call through
the rules to say how many would have been stopped. On this laptop: 942 sessions, 23 projects,
31 days, 79,883 tool calls, an estimated $7,863.51, and 517 calls the armed rules would have
refused. It needs no install into the user's project, makes no network call, and is the honest
answer to "why would I believe your numbers". It leads the homepage and the launch drafts.

**Distribution is still the binding constraint and still has not been tested.** Nothing has ever
been posted. The launch drafts in `Marketing/` are rewritten around the $7,863.51 number and
every claim in them is a test in this repo. Two listings are now blocked only on an operator
action rather than on work: the community plugin marketplace submission
(`Marketing/plugin-directory-submission.txt`) and the PyPI upload.

## Done and verified

- **0.5.0 built from `main`, proven against the artifact rather than the source tree.**
  32 end-to-end flows drive a clean venv install of the wheel (`tools/verify_flows.py`), and the
  wheel was also proven to FAIL: one byte changed inside a signed record and `pr verify` exits 1
  naming `recv_hash_mismatch` and the broken chain. Not uploaded.
- **2116 tests pass. `ruff check .` is clean over the whole tree**, which it had never been:
  CI linted `src` only, and the 49 errors that gate would have caught were all in
  `guard_standalone.py`, the file the zero-install plugin actually executes. CI and the Makefile
  now lint what `PUBLISH.md` says to lint.
- **`claude plugin validate` passes, and did not before.** `hooks/hooks.json` declared its two
  events at the top level instead of inside a `"hooks"` object. It loaded and fired correctly
  that way, so five releases shipped with it, and the community-marketplace review pipeline runs
  exactly that check on every submission. The listing we did not have was not pending, it was
  impossible. Pinned three ways, including running the validator itself as a test.
- **The wrapped hook was then proven at runtime, not assumed.** A real `claude -p` session with
  `--plugin-dir` and `bypassPermissions` was refused at `git reset --hard` by
  `git-worktree.reset-hard`, with the journal written.
- **One policy, five hosts.** Claude Code, Codex (`PreToolUse`), Gemini CLI (`BeforeTool`),
  Copilot (`preToolUse`) and Cursor (`beforeShellExecution` / `beforeMCPExecution`), each in its
  own envelope with tool names mapped to one canonical set. Where a host has no "ask" verdict,
  a rule that would ask denies instead of quietly allowing (`src/provenrail/hosts.py`).
- **Twenty live routes swept at 320 px and 375 px in Chromium**, mobile emulation on: no
  horizontal scroll, no element escaping the viewport outside a deliberate scroller, no broken
  image, no console error, no page error. All 24 routes return 200 and every one of the 35
  landing-page links resolves.
- **The in-browser verifier reaches the right verdict on the live site**: `Verified and
  witnessed` on `/verify?demo`, `Tampering detected` on `/verify?tamper`, console clean.
- **`/account?plan=builder` parks the plan and strips it from the URL**, and a signed-out
  visitor is told why the sign-in screen appeared. Checkout itself is not driven; it spends real
  money.
- **JSON-LD parses on all 15 content routes** with no parse failures, and the only prices in it
  are `0` and `9`.
- **A countdown no longer outlives its own date.** Both AI Act pages showed "Article 50
  transparency applies in" above a clock reading "is now in force", from 2 August until
  2026-09-16, because each page had its own copy of the script and each wrote the clock and
  never the label. One implementation in `main.js` now, date and both labels in the markup.
  Verified in a browser in both states, the elapsed one against the real clock and the counting
  one against a faked 10 July.
- **One date per page.** `ai-agent-incidents` told search engines 12 June while showing 5 August,
  and six pages showed 5 August after being rewritten. The visible `<time>` is the source,
  `dateModified` follows it, and no eyebrow may carry a third date. Pinned by a test.
- **Three wrong model rates**, checked against the published page: Sonnet 5 carried a 50%
  increase that was announced and then cancelled, Fable 5.1 and Mythos 5.1 were missing.
  `pricing.VERIFIED` records the date and a test fails when it goes stale.
- Everything verified before this session still holds; see WORKLOG.

## Next in order

1. **Run the two blocked commands.** `Marketing/polar-migration-operator-steps.txt` FIRST: the
   pricing page says $9 and the account page and live checkout still say and charge $29,
   because the product id is in a Supabase secret the agent may not write. That is a visible
   contradiction on the one surface where money changes hands. Then
   `Marketing/release-0.5.0-operator-steps.txt` for the PyPI upload.
2. **Submit the plugin.** `Marketing/plugin-directory-submission.txt` is paste-ready for the
   Console form at platform.claude.com/plugins/submit (the claude.ai form needs a Team or
   Enterprise org this account does not have). Validation already passes.
3. **Post. Nothing above item 1 and nothing below this line matters until this happens.**
   `Marketing/launch-show-hn.txt` leads with the $7,863.51 figure;
   `Marketing/launch-week-checklist.txt` has the day-by-day plan and the success numbers fixed
   in advance.
4. **Answer the bypass replies the same day.** Each named command becomes a row in
   `tests/test_predicates.py` and a release. That is the measurement loop.
5. **Test whether plugin PreToolUse hooks fire inside `Task` subagents.** #86872 and #87360 both
   happened in subagents and #78797 says deny rules do not always propagate there. If they do
   not fire, the pack does not cover the case it was written for and the page has to say so.
6. **Watch plugin installs and unique repo views, not stars.** The old kill criterion (fewer
   than 70 unique 14-day cloners) read 88 on day zero with nothing posted, so it measured
   nothing.

## Traps

- **Screen the target, never the verb.** The whole thesis of 0.4.x, easy to undo with one
  "helpful" regex. Any new rule about a destructive command needs an answer to "what does this
  do to `rm -rf .next`", and the answer comes from `tools/measure_guard.py`, not from intuition.
- **A predicate may only ever NARROW a rule.** Unknown names and raised exceptions both evaluate
  True, so a bug in `predicates.py` cannot open a hole that was closed.
- **`classify_target` asks its exemptions LAST**, because a HOME pointed at a scratch directory
  made `rm -rf ~/` read as a temp clean-up.
- **A guard command that configures one thing must not disarm the rest.** `pr guard budget` wrote
  a policy whose `use` list held the budget and nothing else, and a config file wins completely,
  so the one command whose purpose is more protection produced 44 fewer rules while reporting
  the cap armed. Adding to the armed set is the only correct shape.
- **A budget only binds where it is read.** It bound on an SDK `model_call`, which a coding agent
  never emits, so the cap capped nothing in the recommended install while saying it was on.
- **Refusing to act is not the safe default when the refusal leaves someone unprotected.**
  `pr guard install` refused without a recording endpoint and wrote nothing at all in a fresh
  project. The local guard never needed an endpoint.
- **`hooks/hooks.json` events go INSIDE the `"hooks"` object.** The top-level shape loads and
  fires, so nothing but `claude plugin validate` will tell you, and that is the check standing
  between this plugin and the only directory whose audience already runs the host.
- **Scope belongs in the rules, not in the hook matcher.** The matcher is `*`.
- **An allow found while scanning rules is provisional, never final.**
- **A cap on the text a content rule sees bounds WORK, never what gets screened.** Truncating it
  silently is a bypass with padding, in one line. Escalate instead. `MAX_MATCH_TEXT`.
- **Never write a second enforcement engine.** `shell.py`, `predicates.py`, `hosts.py`,
  `transcript.py` and `welcome.py` are VENDORED into the plugin by `tools/vendor_guard_rules.py`.
  Run it after any engine change; `--check` fails the build if you forget.
- **The vendored copies must run on Python 3.9.** `from datetime import UTC` is 3.11+ and broke
  the plugin once. `/usr/bin/python3` on this machine is 3.9.6 and is the cheapest check there is.
- **The card must never carry an operand.** A secret is always an operand.
- **Group recorded sessions by `meta.host_session_id`, never by `session_id`.**
- **A transcript that cannot be read is UNKNOWN, never zero.** Every unreadable file, every
  unpriced model, and every figure derived from them carries the caveat. A reassuring zero is
  the exact failure this feature exists to avoid.
- **A default is a claim.** `welcome.first_run_notice` takes `config_exists` with no default,
  because a default there is the guess that produced the bug it was written to fix.
- **A partial anchor receipt is a FAILURE for an attestation**, not a warning.
- **The word "attestation" is the supply-chain sense only.** Never "compliance attestation".
- **Do not sell hosted record storage.** Unchanged and load-bearing.
- **Strategy docs never go in the public tree.** `docs/direction-2026-09-16.md` and
  `docs/launch-baselines-2026-09-16.md` were pushed to the public repo this session and had to be
  moved to `pofky/provenrail-internal` and gitignored. The history still holds them; rewriting it
  is the operator's call.
- **Do not publish autopilot.** Explicit standing instruction from the operator. It is the
  factory, not the product.
- Everything else in the 2026-08-21 trap list still applies: minimal DER nonce, trusted time out
  of the token and never the field beside it, `supabase functions deploy` does not type-check,
  and every public edge function needs `verify_jwt = false` pinned in `config.toml`.

## Open, and why

- **The tag `v0.5.0` points one commit behind `main`.** Moving a pushed tag needs a force push,
  which is gated. The only difference inside the package is a docstring in `server/plans.py`;
  the wheel in `dist/` is built from `main` and is the one to upload.
- **The site says $9 and checkout charges $29** until step 1 of the Polar file is run. Confirmed
  live: `/pricing` renders $9, `polar-prices` returns 2900 and 9900, and the account page paints
  `$29/mo` from it.
- **Nobody has installed the plugin except us.** Everything in the funnel is a claim about a path
  no stranger has walked.
- **Whether plugin hooks fire inside `Task` subagents is untested**, and it is where two of the
  cited incidents happened.
- **A command written to defeat a pattern still defeats the guard.** `V=-rf; rm $V`, a script
  invoked by name, a delete inside a `python -c`. Documented rather than hedged.
- **The path logic is POSIX**, so a PowerShell or `cmd` recursive delete always asks.
- **`access.disarm-the-guard` fires often in THIS repository** because developing the guard means
  editing `.provenrail.json`. In an ordinary project it should be rare.
- **The v0.3.0 tag points at an empty commit.** Left alone rather than force-pushed.
- **A 100,000-level nested JSON payload forces the standalone hook to fail open** via
  `RecursionError` caught by its blanket handler. Documented fail-open design.
- **The free anchor has still never been claimed through the UI by a real signed-in account.**
- **Server auth and RBAC have never been verified against live Supabase**, only in-process.
- **`bench/`, the comparative scoreboard, is deferred.** Public comparative claims about other
  vendors need operator sign-off under the six-question veto.
- **Codex has never been driven with a real payload.** `hosts.CAPTURED_PAYLOAD` is empty and says
  so; the adapter is written from the documented shape. `codex login` would close it.
- DM Sans is still a widely used free font; the design research asks for something less common.

## Environment

- Python venv: `.venv` in the repo root (3.14). `.venv/bin/python -m pytest -q` from the root.
- Lint: `uvx ruff check .` (ruff is not in the venv). The whole tree, not `src`.
- Build: `rm -rf dist build && uvx --from build pyproject-build`.
- Prove the built artifact: `python3 tools/verify_flows.py`. It builds a wheel, installs it into
  a clean venv and drives 32 flows. This is the release gate, not the test suite.
- Regenerate the plugin's vendored rules AND engine modules: `python3 tools/vendor_guard_rules.py`
  (`--check` in tests).
- Validate the plugin: `claude plugin validate ./plugins/provenrail-guard`.
- Measure the rules against your own transcripts: `python3 tools/measure_guard.py`. Local only.
- Local site: `python3 -m http.server 8777 --directory web`. Clean URLs are a Pages feature, so
  `.html` is needed locally but not in production.
- Deploy the site: `npx wrangler pages deploy web --project-name=provenrail --branch=main`
  **from the repo root** (wrangler bundles `./functions` relative to the working directory).
- Deploy edge functions: `supabase functions deploy anchor trial-license polar-webhook pageview
  polar-prices polar-checkout --project-ref jzgamrptvsdxnwtuascx`.
- Mobile sweep: Playwright is installed for the system `python3` (the playwright MCP server is
  down). Chromium with `is_mobile=True` at 320 and 375 is what verified this session's UI claims.
- Polar credentials at `~/.config/provenrail/polar.env`. Anchor signing key at
  `~/.config/provenrail/anchor-key.env`, the operator's own test licence key at
  `~/.config/provenrail/anchor-selftest.env`. All chmod 600, none in the repo.
- Supabase project `provenrail-production` (ref `jzgamrptvsdxnwtuascx`, eu-central-1).
