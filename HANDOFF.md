# HANDOFF

Last updated 2026-10-10. Branch `main`. **0.6.0 is built, proven against the wheel, tagged `v0.6.0`, and NOT on
PyPI** (PyPI serves 0.4.3; the upload is refused for the agent). The plugin serves 0.6.0 from
this repository as soon as it is pushed, so the zero-install path is live. Read this first,
then `WORKLOG.md` for history.

## Where things stand

**2026-10-10: a second product round ended in no new product.** The operator asked for
something new and exciting that people would pay for. Four research reports and a red team
(`provenrail-internal/docs/direction-2026-10-10-product-round.md`) found every finalist
already built, mostly free, and none above 2% odds of 100 paying users: connectors need the
vendor to hold users' tokens (the processor role), token and quota tools are saturated, limit
handoff exists three times. Do not re-propose any of them without new evidence. What the
evidence did support was one page for a search the 0.6.0 undo already answers, so
`web/undo-claude-code-changes.html` was added. Nothing else changed in the product.

**0.6.0 turned the product from a rule engine with a record into a supervisor for coding
agents.** The operator's instruction on 2026-10-09 was to build a comprehensive tool for
agentic work (security, logging, human in the loop) and to keep the existing record as an
addition. The direction review of the same day (`provenrail-internal/docs/direction-2026-10-09.md`)
had found no market for audit or proof and real, loud demand for undo, for a kill switch, and
for approvals when nobody is at the keyboard. So the hook now does those, on all five hosts,
and the signed record sits underneath as before.

**The lead is undo, because it is the one with measured demand and a one-line demo.** Claude
Code's own documentation says "Checkpointing does not track files modified by Bash commands",
and `openai/codex#9203` ("Please make /undo back") is open with 476 upvotes. A real Claude
Code session told to delete a directory of uncommitted files replied "Deleted `src`
(untracked, so not recoverable from git)", and `pr undo last` restored both files with
identical checksums.

**What is in 0.6.0** (each is one stdlib-only module, vendored into the plugin):
`checkpoint.py` undo, `watch.py` loop breaker and stop switch, `lanes.py` two sessions in one
file, `remote.py` phone approvals over Telegram or ntfy with no server of ours, `supervise.py`
the single entry both engines call, `scan.py` what a cloned repository auto-runs, `brief.py`
a review brief from recorded facts, `localstate.py` state under `~/.provenrail`.

**What is paid.** Everything is free and local except the phone remote, which runs for 14 days
with no account and then needs the existing $9 licence (`remote.entitled`). No Polar change
was needed for that: any valid licence unlocks it. The zero-install engine cannot verify a
licence (no signature library), so after the evaluation it tells the user to install the CLI.

**Distribution is unchanged and is still the only thing that matters.** Nothing has ever been
posted. The copy for this release is written, one file per field, in
`Marketing/launch-0.6.0-*.txt`.

## Done and verified

- **`/undo-claude-code-changes`**, a how-to page for "how to undo claude code changes"
  (autocomplete-confirmed, thin results on 2026-10-10): what `/rewind`, git and the plugin each
  bring back, and recovery steps for work already lost. In the sitemap, `llms.txt` and the
  citable-question tests. Checked at 320, 375 and 1280 px, dark and light.
- **WCAG 2.2 AA pass over all 19 pages** (`docs/a11y-review-2026-10-10.md`): axe-core 0
  violations, 0 low-contrast text nodes in both schemes, every focus stop visible. Three
  defects fixed. Not run: a screen reader.

- **2,310 tests pass and `ruff check .` is clean** (run 2026-10-09; the count includes the new
  `test_checkpoint.py`, `test_supervisor.py`, `test_supervisor_hardening.py`, `test_scan.py`,
  `test_brief.py`).
- **The wheel is proven, not the source tree.** `tools/verify_flows.py` builds 0.6.0, installs
  it into a clean venv and drives the flows, now including the supervisor through BOTH engines
  (installed CLI, and the plugin alone under the system `python3`): delete, list, undo last,
  byte-for-byte comparison, stop, resume, the eighth identical call, scan, brief. 54 checks, exit 0.
- **Undo proven in a real Claude Code session** with `--plugin-dir` and no CLI on PATH: the
  agent ran `rm -rf src` over two never-committed files, `pr undo last` restored both,
  `shasum` identical, and the user's `.git` held no stash and no new ref.
- **The phone round trip proven against the real ntfy.sh**: a question with Approve and Deny
  actions was published, the action body was posted to the reply topic the way the app does
  it, `remote.ask` returned `approve` in 5.4 s, and a `stop` typed into the reply topic halted
  the machine. Telegram is covered by a scripted fake only: no bot token exists here.
- **The zero-install engine runs on Python 3.9.6** (`/usr/bin/python3`) with every new module,
  and a machine with no remote set up never imports `remote` or `scan` (a test).
- **Hook cost measured**: 78 ms against 70 ms before on a call that takes no snapshot, and
  1.04 s first / 0.03 s after for a snapshot of this repository (381 files).
- **The loop threshold is measured**: `tools/measure_loops.py` over 3,186 sessions and 147,356
  tool calls; 8 back-to-back repeats questions 0.47% of sessions. The distribution is pinned
  in `tests/test_supervisor.py::MEASURED` and the README figures are asserted against it.
- **`claude plugin validate ./plugins/provenrail-guard` passes** at 0.6.0.
- **An adversarial review of the new modules found seventeen defects and each fixed one has a
  reproduction in `tests/test_supervisor_hardening.py`.** The three that mattered: a restore
  deleted a nested repository, `.git` and unpushed commits included; the background poller ran
  `python -m` from the repository, so a planted `provenrail/__init__.py` was executed; and a
  broken `.provenrail.json` returned "not enforcing" before the stop switch was ever read. The
  same review found no path from deny or ask to allow other than a real approval, and no write
  or delete outside the repository root.
- **A legal review of the public copy found three blockers, all corrected**: the Codex comment
  claimed it worked on a host never driven, the README claimed five hosts with no hedge, and
  the site said Claude Code cannot stop on cost, which `claude -p --max-budget-usd` contradicts.
- **Two old defects found and fixed on the way.** A `.provenrail.json` with no `policy` key
  armed the defaults under the plugin and NOTHING under the CLI. And `pr guard install --host
  gemini` wrote a 15 millisecond hook timeout, because Gemini CLI counts in milliseconds
  (`hosts.GEMINI_TIMEOUT_UNITS_PER_S`, checked against the vendor page 2026-10-09).
- Everything verified before this session still holds; see WORKLOG.

## Next in order

0. **Deploy the site.** Committed, tested, swept at 320 and 375 px, and NOT deployed: the
   release rewrites `privacy.html`, `terms.html` and `disclaimer.html`, and legal wording is
   the operator's to approve. Step 0 of the operator file has the diff command and the deploy.
   The new undo page goes live with the same deploy; submit it to IndexNow afterwards.
1. **Publish 0.6.0 and prove Codex.** `Marketing/release-0.6.0-operator-steps.txt`. The Codex
   login on this machine has expired, so `tools/prove_codex.sh` could not run; it is one
   command after `codex login` and prints PASS or FAIL.
2. **Submit the plugin.** `Marketing/plugin-directory-submission.txt`, rewritten for 0.6.0.
3. **Post.** Show HN (`launch-0.6.0-show-hn-*.txt`), r/ClaudeAI the same day
   (`launch-0.6.0-reddit-claudeai-*.txt`), and the comment on `openai/codex#9203` only after
   step 1 printed PASS.
4. **The falsifier, 30 days from the first post.** Fewer than 100 plugin installs or GitHub
   stars combined, and nobody reporting a restore (working or failing), means undo is loud in
   issue trackers and not felt widely enough to install a third-party hook for. Then stop
   adding features and treat the project as maintained open source. Ten or more people setting
   up the remote with nobody paying after the evaluation means the free product is right and
   the paid line is in the wrong place: move it, do not re-aim.
5. **Capture a real payload for one more host.** `tools/prove_codex.sh` leaves the Codex
   payload on disk for `hosts.CAPTURED_PAYLOAD`.

## Traps

- **The stop switch is read before anything that can fail.** First statement of both hook
  entry points, ahead of payload parsing and policy loading. Every "could not load, allowing"
  branch is otherwise a way past a stop order.
- **`.provenrail.json` is in the working tree, so it may only tighten.** The agent can write
  it and a clone can ship it. It can switch undo, the loop breaker or lanes off only with a
  notice; for the remote it can only reduce detail to `shape` or shorten the wait. When the
  phone is asked and how much it is sent live in `~/.provenrail/remote.json`
  (`pr remote config`).
- **A restore never touches a nested repository and never empties a directory holding a file
  that is in no checkpoint.** Both are reported as refused and the restore is then NOT marked
  verified. A snapshot holds only a pointer to a nested repository, so "restoring" one could
  only ever delete it.
- **The safety snapshot and the writes of a restore are one lock hold.** Split, an agent's
  write between them was replaced with no copy anywhere.
- **An empty snapshot is an error only when the tree has files.** Everything ignored is a
  gap to report; everything just deleted is the exact state an undo must be able to record.
- **The shadow store's `info/attributes` overrides the repository's `.gitattributes`.** One
  line of `* working-tree-encoding=bogus` in a repository failed every snapshot.
- **Nothing spawned by the hook may run with the repository as its working directory**, and
  nothing on the hook's path may wait on a lock without a limit (`localstate.locked(timeout)`).
- **A command cut for the phone must say it was cut.** 600 harmless characters and then a
  destructive tail otherwise looks harmless to the person approving it.
- **The supervisor may only make a verdict stricter, with one exception.** A human answering
  "approve" turns an ask into an allow. Nothing else in `supervise.py` may loosen anything,
  and every step that fails must leave the verdict as it found it.
- **A phone wait must end before the host's hook timeout.** A host that kills a hook reads it
  as "no opinion", so a question still open at that moment becomes an allow. The timeout the
  host is given and the `--budget` on the hook command are one number (`guard.HOOK_TIMEOUT_S`),
  a test holds them equal, and an install made before 0.6.0 gets no phone wait at all until
  `pr guard install` is run again.
- **Never `git gc --prune=now` in the shadow store.** It runs detached, overlaps the next
  snapshot, and deleted a tree that snapshot had just written. The default two-week expiry
  cannot race.
- **Every inherited `GIT_*` variable is dropped before the shadow store is touched.** One stray
  `GIT_DIR` from a rebase would point the snapshot at the user's real repository.
- **A dry run must not log a snapshot, and `last` must skip the future an undo escaped.** Both
  were bugs the tests caught: `pr undo last --diff` made itself the newest checkpoint, and a
  second `pr undo last` stepped forward into the damage the first one removed.
- **The newest checkpoint is often an undo's safety snapshot, which has no session.** Anything
  that asks "which session was last" must skip `checkpoint.UNDO_TOOL` entries (`brief._scope`).
- **Lanes are claimed at the pre event on an allow, not at post.** The plugin's shim runs no
  engine after a tool call unless the CLI is installed, so a post-only claim meant lanes did
  not exist in the zero-install path.
- **Nothing the hook runs on every call may import the HTTP stack, `tempfile`, `secrets` or
  `scan`.** They cost 45 ms a call when they were at module top. `remote` is imported only
  when `~/.provenrail/remote.json` exists.
- **Tests must never write to the real `~/.provenrail`.** `conftest.py` points
  `PROVENRAIL_HOME` at a temp directory for every test; a subprocess with an explicit `env`
  has to pass it on.
- **A config file with no `policy` key still arms the default rules, in both engines.**
- **Gemini CLI counts a hook timeout in milliseconds.** Every other host counts in seconds.
- **Do not say undo works on a host it has not been driven on.** Claude Code only, until
  `tools/prove_codex.sh` prints PASS.
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

- **Undo is proven on Claude Code only.** Codex, Gemini CLI, Copilot and Cursor run the same
  module behind adapters written from each vendor's documented contract.
- **Telegram has never been driven against the real API**, only a scripted fake. ntfy has.
- **Cursor fails open on a hook timeout by default** (its docs, checked 2026-10-09), so on
  Cursor a hook killed mid-question lets the call through. The budget keeps the wait inside
  the timeout; `failClosed` is still left at the vendor default on purpose.
- **Nested repositories and submodules are snapshotted as a pointer, not by content.**
- **A shell command that rewrites a file takes no lane**, because it does not say which files
  it will touch. Stated in `lanes.py` and the docs.
- **The checkpoint store has no total size cap.** Fourteen days of large changes can fill a
  disk. Files over 50 MiB are skipped, which bounds a single snapshot and not the sum.
- **`find_root` takes the nearest `.git`**, so a session started inside a nested repository
  snapshots only that one.
- **The remote does not defend against hostile software in the user's own account**, which can
  read its state files, and on ntfy can read the topic and answer its own question. Said in
  `remote.py`, in the setup text and on the site. Telegram is the stronger channel.
- **Three legal notes left for the operator, all older than 0.6.0**: the terms do not say the
  subscription renews until cancelled, the refund channel differs between `terms.html` (email)
  and `pricing.html` (the Polar portal), and neither can be settled without knowing how the
  Polar product is actually configured.
- **The 8 ms hook overhead was measured once, on a quiet machine** (70 ms against 78 ms,
  interleaved). Under load both figures move by more than the difference.
- **The paid line is an untested guess.** One feature, one price, a 14-day evaluation counted
  locally. Nobody has reached it.

- **The tag `v0.5.0` points one commit behind `main`.** Moving a pushed tag needs a force push,
  which is gated. The only difference inside the package is a docstring in `server/plans.py`;
  the wheel in `dist/` is built from `main` and is the one to upload.
- **Billing is consistent as of 2026-09-17 and was verified live.** The operator ran both
  Supabase secret commands; `polar-prices` now returns exactly one product, `builder` =
  "Anchored statements" at 900 usd/month, and the account page paints `$9/mo` from it with a
  clean console. Nothing in Polar itself needed changing: own org, webhook correct in raw format
  with all eight events, $9 product already live. One optional step remains, deliberately last
  because archiving before the secret moved would have broken checkout: archive Builder
  (`0b5e05d4-...`, $29) and Team (`c70fdf7a-...`, $99) in the Polar dashboard. Both agent paths
  to that are gated, the classifier on secret writes and autopilot's extreme gate on live Polar
  writes, and both gates are right.
- **The only subscription that has ever existed is the operator's own $0 billing-proof run**
  (`billing-proof+delete-me@provenrail.com`, created and canceled within four minutes on
  2026-08-05, period ended 2026-09-05). An earlier note claiming there were none at all was
  wrong and is corrected in `Marketing/polar-migration-operator-steps.txt`.
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
- Measure the loop threshold the same way: `.venv/bin/python tools/measure_loops.py`.
- Prove undo on Codex with a real session: `tools/prove_codex.sh` (needs `codex login`).
- Supervisor state lives in `~/.provenrail` (`PROVENRAIL_HOME` overrides it): one directory per
  project under `projects/`, plus `remote.json`, `stop.json` and `away`.
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
