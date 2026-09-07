# HANDOFF

Last updated 2026-09-07. Branch `main`, tag `v0.4.3`.
**0.4.3 is on PyPI and the site is deployed.** Verified from a fresh public clone of
`pofky/provenrail` with no CLI installed: nine dangerous commands stopped, ten ordinary ones
silent, `/guard-card` correct. Read this first, then `WORKLOG.md` for history.

## Where things stand

The direction changed on 2026-09-07 on measurement rather than on feeling, and the code
followed it twice: a repositioning in the morning (`docs/repositioning-research-2026-09-07.md`)
and then a rewrite of what the guard actually screens. Do not relitigate either without reading
the numbers below.

**The distribution fact is unchanged and still the only thing that matters.** 2,534 pageviews
ever, fourteen with a referrer, nothing ever posted anywhere. The product was not rejected, it
was never shown. `Marketing/launch-week-checklist.txt` is the plan and it has still never been
executed.

**What changed in 0.4.x, and why.** The guard was aimed at the wrong half of the problem, and
both halves were measured rather than argued.

False positives: 36,977 Bash commands pulled from 1,247 local agent transcripts, replayed
offline with the working directory each one actually ran in. The 0.3.1 rules interrupted 923 of
them and refused 305, almost all of it ordinary work: `rm -rf .next out` before a build,
`chmod +x` denied because a UUID in the path contained the digits 4732, a Tailwind class read as
a SQL `TRUNCATE`. Two rules, both about `rm`, were 687 of the 923.

False negatives: the public data-loss reports filed against Claude Code are almost never about
`rm`. They are `git reset --hard` (#34327, #7232, #17190), `git checkout -- .` (#81508),
`git clean -fd` (#45974, #87360), `git stash` (#85879), `git worktree remove --force` (#46444),
a framework database reset against a live database (#80868, #90808). 0.3.1 allowed 40 of the 40
commands taken from those reports. Every issue number was confirmed against the GitHub API.

The fix is one idea. Screening the verb is wrong: nobody loses work to the letters `rm -rf`,
they lose it to the target, and the difference is not in the text, it is in where the text
points. Rules can now carry a `predicate` (`src/provenrail/predicates.py`), a named function
that sees the same single command the regex matched plus the call's context, and narrows it.
`delete.catastrophic` resolves the targets against the repository root. `git.would_lose_work`
runs `git status --porcelain` and checks for unpushed commits, so the git rules are silent on a
clean, pushed tree, where those commands destroy nothing.

Where it stands now, on the same corpus: 222 interruptions and 16 refusals on the Bash subset,
fifteen of the sixteen being this repository's own adversarial test fixtures. Widened to every
tool (56,840 calls), 276 and 24. On the 40 documented data-loss commands, none allowed. On 43
ordinary deletes and git operations, 21 interrupted before and 0 now.

**Both corpora are tests** (`tests/test_predicates.py`), and `tools/measure_guard.py` runs the
same measurement over anyone's own transcripts with no network call in it. That script is also
the honest answer to "why should I believe your numbers".

## Done and verified

- **0.4.3 on PyPI, site deployed, plugin at 0.4.3.** Fresh-clone end-to-end run is green with no
  CLI installed and with one installed; `pip install provenrail==0.4.3` resolves and its wheel
  verifies a clean bundle and rejects a changed field, a dropped record and a broken `prev_hash`.
- **The hook costs 115 ms (bundled) / 85 ms (CLI) per tool call, pre and post combined**, measured
  over 20 runs on a warm cache. It was 430 ms in 0.4.2, because the version probe spawned
  `pr --help` and `pr --version` before any work and PostToolUse is matched `*` as well. The
  resolved engine is now cached for a day in a file keyed by the plugin version, `--version` is
  probed once, `plugin.json` is read with shell built-ins, and the bundled engine is skipped
  entirely on post events (it is not a recorder). `tests/test_hook_shim.py` pins the probe count,
  the vanished-binary fallback and both post-event behaviours.
- **Every flow driven end to end against the published wheel, not just the test suite.**
  `pr demo | verify | attest | attest-verify | quickstart | guard install/status/card/receipt |
  rules` all pass; ten tampering variants across bundles and attestations are all rejected; the
  live browser verifier is green on the demo and red on the tampered fixture with a clean console;
  the live anchor service returns a public auditor URL and its receipt rejects a different bundle.
- **`/account` and the pricing CTAs.** `/account?plan=builder` parks the plan in `localStorage`
  and strips it from the URL, so the intent survives the sign-in round trip. Checkout itself is
  not driven, because completing it spends real money.
- **Mobile at 375 px.** Neither `/` nor `/claude-code-guardrails` scrolls horizontally; the wide
  rules table and every `pre` scroll inside their own containers. Console clean on both.
- **Target-aware deletes.** `predicates.classify_target` resolves against the repository root
  (`workspace_root` walks up to `.git`), with temp roots, package caches and build directories
  allowed, home-directory and shallow-absolute paths refused, and an unresolvable variable
  followed by a slash treated as `/` because that is what an unset variable makes it. Variables
  assigned earlier in the same command string are read rather than feared.
- **Three new packs, armed by default: `git-worktree`, `database`, `cloud`.** 44 rules armed,
  54 in the catalogue, ten packs.
- **`/guard-card` and `pr guard card`.** A paste-ready summary of what was stopped.
  `shell.command_shape` reduces each command to its verb and flags and drops every operand; a
  test asserts no path, hostname, URL or key survives, over both corpora.
- **The hook is wired to every tool.** The old seven-name matcher meant `mcp__*__delete*` and a
  `Read` of `~/.ssh/id_ed25519` reached no rule while the catalogue advertised both. Scope is
  declared per rule with `not_tool`, which also keeps command rules off documents, search
  queries and subagent prompts.
- **Two silent-disarm bugs, both found by driving the install rather than reading it.**
  `pr guard hook` with no config file armed nothing while the bundled engine armed the defaults,
  so `uv tool install provenrail` turned the guard off. And an older `pr` on the machine
  answered for a newer plugin, hiding every new rule. `tests/test_hook_shim.py` drives the shim
  with stand-in CLIs.
- **1281 tests pass**, ruff clean, both engines and both verifiers in lockstep
  (`predicate` and `not_tool` are in `web/verify.js` and in the policy hash).
- Everything verified before this session still holds; see WORKLOG.

## Next in order

1. **Post. This week. Nothing below matters until this happens.**
   `Marketing/launch-reddit-claudeai.txt` and `Marketing/launch-show-hn.txt` are rewritten
   around the measurement and around the git pack, which is the part with an audience.
   `Marketing/launch-week-checklist.txt` has the day-by-day plan and the success numbers, fixed
   in advance. Every claim in both drafts is a test in this repo.
2. **Answer the bypass replies the same day.** The Reddit draft ends by inviting people to name
   a command the rules miss. That invitation is the measurement loop: each named command becomes
   a row in `tests/test_predicates.py` and a release.
3. **Test whether plugin PreToolUse hooks fire inside `Task` subagents.** #86872 and #87360 both
   happened in subagents and #78797 says deny rules do not always propagate there. If they do
   not fire, the pack does not cover the case it was written for, and the page has to say so.
4. **Ten outreach messages** from `Marketing/outreach-ai-disclosure.txt`, by hand. Expect "we
   have a clause, nobody has asked for proof", and treat that as the result it is: `pr attest`
   then waits rather than leads.
5. **Watch installs, not stars.** Under 100 plugin installs in 30 days with the posts actually
   made falsifies the distribution thesis, and no further repositioning fixes it.
6. **Go verifier binary**, still. Auditors do not run Python. 5 to 10 days.

## Traps

- **Screen the target, never the verb.** This is the whole thesis of 0.4.x and it is easy to
  undo by adding a "helpful" regex. Any new rule about a destructive command needs an answer to
  "what does this do to `rm -rf .next`", and the answer has to come from `tools/measure_guard.py`
  rather than from intuition.
- **A predicate may only ever NARROW a rule.** Unknown names and raised exceptions both evaluate
  to True, so a bug in `predicates.py` cannot open a hole that was previously closed. Keep it
  that way; the reverse default would make every future predicate a potential bypass.
- **`classify_target` asks its exemptions LAST.** Home-directory and workspace-root checks come
  before "is it under a temp root", because a HOME pointed at a scratch directory made `rm -rf ~/`
  read as a temp clean-up. `test_a_home_directory_under_a_temp_root_is_still_a_home_directory`.
- **The rule engine matches case-insensitively**, which is right for SQL keywords and wrong for a
  git flag. `git branch -D` and `-d` are different commands; that one bit is checked in
  `predicates._git_force_delete_branch`, not in the regex.
- **Scope belongs in the rules, not in the hook matcher.** The matcher is `*`. A named list is
  how three advertised rules became unreachable while reporting themselves armed.
- **An allow found while scanning rules is provisional, never final.** Returning ALLOW from
  inside the loop is what let one broad `limit` rule preempt every deny rule after it.
- **A cap on the text a content rule sees is a bound on WORK, never on what gets screened.**
  Silently truncating it is a bypass with padding, in one line. Escalate instead. `MAX_MATCH_TEXT`.
- **Never write a second enforcement engine.** `shell.py` and `predicates.py` are VENDORED into
  the plugin by `tools/vendor_guard_rules.py`, not reimplemented. Run it after any rule or engine
  change; `--check` fails the build if you forget.
- **The card must never carry an operand.** A secret is always an operand, and dropping the whole
  category has to be right once where a redaction pass would have to be right every time.
  `tests/test_guard_card.py` holds this over both corpora.
- **Group recorded sessions by `meta.host_session_id`, never by `session_id`.** A hook fires in
  its own process, so guard mode writes one Provenrail session per tool call, and grouping by
  `session_id` makes the `recorded` evidence grade unreachable in the recommended setup.
- **`git log --shortstat` prints AFTER the format string**, so `attest.py` attributes it
  backwards on purpose.
- **A partial anchor receipt is a FAILURE for an attestation**, not a warning.
- **The word "attestation" is the supply-chain sense only.** Never "compliance attestation".
  `test_attestation_is_not_used_as_a_product_noun` fails the build.
- **Do not sell hosted record storage.** Unchanged and load-bearing.
- Everything else in the 2026-08-21 trap list still applies: the RFC 3161 nonce must be minimal
  DER, trusted time comes out of the token and never from the field beside it, `supabase functions
  deploy` does not type-check, and the anchor coverage check is the product rather than a limitation.

## Open, and why

- **The stderr-forwarding test was narrowed.** It used to reject `2>/dev/null)` anywhere in the
  shim; it now checks only the line that invokes an engine. The `--version` probe and the cache
  read are allowed to be quiet, because their noise is not something a user can act on.

- **Nobody has installed the plugin except us.** Everything above is a claim about a funnel that
  no stranger has walked. The first real install is the first honest data point.
- **Whether plugin hooks fire inside `Task` subagents is untested**, and it is where two of the
  cited incidents happened. See item 3 above.
- **A command written to defeat a pattern still defeats the guard.** `V=-rf; rm $V`, a script
  invoked by name, a delete inside a `python -c`. Documented on the guardrails page and in both
  launch drafts rather than hedged. Target resolution buys precision on what agents emit, not
  immunity to what someone writes to get around it.
- **The path logic is POSIX**, so a PowerShell or `cmd` recursive delete always asks rather than
  being classified.
- **`access.disarm-the-guard` fires often in THIS repository** because developing the guard means
  editing `.provenrail.json` constantly. In an ordinary project it should be rare; if a user
  reports otherwise, that is a real signal.
- **The v0.3.0 tag points at an empty commit.** Left alone rather than force-pushed.
- **A 100,000-level nested JSON payload forces the standalone hook to fail open** via
  `RecursionError` caught by its blanket handler. Documented fail-open design, not a hidden defect.
- **The free anchor has still never been claimed through the UI by a real signed-in account.**
- **Server auth and RBAC have never been verified against live Supabase**, only in-process.
- DM Sans is still a widely used free font; the design research asks for something less common.

## Environment

- Python venv: `/Volumes/T7/Projects/AgenticTools/.venv` (3.14). `pytest -q` from the repo root.
- Lint: `python -m ruff check src tests tools`.
- Regenerate the plugin's vendored rules AND engine modules: `python tools/vendor_guard_rules.py`
  (`--check` in tests). It writes `rules.json`, `shell.py` and `predicates.py` into the plugin.
- Measure the rules against your own transcripts: `python tools/measure_guard.py`. Local only.
- Local site: `cd web && python3 -m http.server 8901`. Clean URLs are a Cloudflare Pages feature,
  so `.html` is needed locally but not in production.
- Deploy the site: `npx wrangler pages deploy web --project-name provenrail` **from the repo root**
  (wrangler bundles `./functions` relative to the working directory, not to `web/`).
- Deploy edge functions: `supabase functions deploy anchor trial-license polar-webhook pageview
  --project-ref jzgamrptvsdxnwtuascx`. Nothing in 0.3.0 changed them.
- Polar credentials at `~/.config/provenrail/polar.env`. Anchor signing key at
  `~/.config/provenrail/anchor-key.env`, the operator's own test licence key at
  `~/.config/provenrail/anchor-selftest.env`. Both chmod 600, neither in the repo.
- Supabase project `provenrail-production` (ref `jzgamrptvsdxnwtuascx`, eu-central-1). Read row
  counts with `supabase projects api-keys --project-ref ... -o json` and PostgREST.
