# Direction, 2026-09-16

Decision memo. Inputs: the evidence brief and primary-source verification of 2026-09-16, the
code in `src/provenrail/` and `plugins/provenrail-guard/` as it stands at `v0.4.3`, and five
vendor hook docs fetched today (URLs inline). Every claim below cites one of those or says
"no evidence". Written to be acted on tomorrow morning.

---

## 1. Verdict

Provenrail is the deterministic policy layer for coding agents that run where nobody is
watching: it stops an agent at the tool boundary when it is about to spend past a dollar cap
or destroy work no remote has a copy of, and it does so identically in CI, `claude -p`, the
Agent SDK, Bedrock, Vertex and Foundry (where Anthropic's classifier does not run at all) and
across Claude Code, Codex, Gemini CLI, Copilot and Cursor (where no vendor will ever ship a
shared policy). Nobody pays for it in the next six months, and the memo says so plainly: the
product has never been shown to a stranger (2,618 pageviews ever, zero social referrals, launch
copy unposted since 2026-08-05, brief A), every paid guard in the category shows no customers
(brief F), and the one pain with proven payment behaviour, cost, has produced exactly one paid
enforcer at $4.99 a month (Terse) and one 18,576-star reporter with zero revenue (ccusage,
brief F). The eventual invoice is a licence for an artefact, never a data relationship: a
signed, independently timestamped monthly statement of what the agent was stopped from doing
and what it spent, which is the anchor service that already exists, repriced. This is not yet a
business. It is a two-week repositioning onto the only ground the vendor has left open,
followed by the launch that has never been run, with a kill date. If the kill date fires, the
repository is frozen as a maintained portfolio piece and the founder builds something else; the
memo is explicit that this is the more likely outcome, and the two weeks are spent because the
distribution thesis has never once been tested and testing it costs nothing but the fortnight.

Why not "portfolio project, stop now" today: the brief shows a product that was never rejected,
only never shown (A), a discovery surface it is absent from that lists install counts and took
one day to enter (D), and a launch format with a measured track record (D: measured numbers in
the title, mechanism plus data, guard-vs-guard scoreboard slot open). Stopping before running
that once would be deciding on feeling, which is the mistake `HANDOFF.md` already forbids.

Why not the 0.4 guard as it stands: Anthropic shipped `git.would_lose_work`, `classify_target`,
the unset-variable rule and the subagent gap as free defaults on every Pro, Max and Team plan
in August (primary-verified, https://code.claude.com/docs/en/permission-modes). The homepage H1
sells a feature the visitor already has (brief B). The first HN comment writes itself.

Why not attribution: every disclosure clause in the brief is satisfied by self-assertion, no
standard has a field for it, nobody has been burned by inability to prove provenance,
developers are fighting to remove the trailers, and OpenAI hired the Git AI founders into Codex
on 2026-09-11 (brief E). `pr attest` stays in the tree as a free command. It leaves the front
page and gets no more engineering.

---

## 2. Kill list

Retire, de-emphasise or move to a second page. Nothing here is deleted from the tree unless
stated; the only inbound traffic is search (30 of 36 referred visits in 30 days, brief A) and
those pages carry it.

| Item | Action | Why (citation) |
|---|---|---|
| `web/index.html` H1 "Your agent is one `git reset --hard` away from your afternoon" and the hero claim paragraph | Rewrite (task 8) | Sells a free first-party default; auto mode runs `git status` before `git reset --hard` and `rm -rf` and blocks critical-path removes (primary-verified). We lose the public argument. |
| `web/claude-code-guardrails.html` title and H1 "Stop Claude Code from running `git reset --hard`", section "Why the permission prompt is not enough" (line 153) | Rewrite (task 9) | Argues against a solved problem. `tests/test_claims_hygiene.py::test_the_page_title_and_the_headline_argue_the_same_thing` pins the old phrase and must move with it. |
| `plugins/provenrail-guard/.claude-plugin/plugin.json` description ("Block destructive tool calls before they run (rm -rf, terraform destroy...)") and `README.md` first line "Stops your coding agent one command before it deletes prod" | Rewrite (task 12) | Same claim, in the one place the discovery surface reads (brief D: claude.com/plugins is sorted by installs, we are not in it). |
| Homepage sections "For teams with regulatory exposure" (EU AI Act Art. 12, HIPAA), the JSON-LD `featureList` entries "EU AI Act Article 12 technical evidence" and "HIPAA 164.312(b) audit log evidence", the compliance FAQ entry | Remove from `index.html` and `llms.txt`; pages stay as footer resources | No dated obligation exists that Provenrail satisfies: Art 12 deferred to 2027-12-02, Art 50 excludes source code (brief E; `docs/repositioning-research-2026-09-07.md` 2.2). The buyer it attracts needs the hosted system of record the operator cannot legally run (brief H). |
| `web/eu-ai-act.html` (38 Art 12 mentions), `web/eu-ai-act-deadline-moved.html` | Keep URLs, drop from nav and homepage, footer "Resources" only, lower `sitemap.xml` priority | Search traffic only; not load-bearing. |
| Homepage section "For freelancers and agencies" and `web/for-agencies.html` | Remove section; page to footer | Insurance sold before the incident to an audience that has not had one (`repositioning-research` section 2, "the product is insurance"). No evidence of demand in the brief. |
| Homepage section "Which of this code did an AI write?" and `pr attest` terminal card; Builder feature line "Timestamped AI code attribution" on `pricing.html` | Remove from homepage and pricing; `web/ai-code-attribution.html` stays as a resource | Brief E: attribution thesis dead as stated. |
| Team ($99) and Enterprise tiers on `web/pricing.html`, `web/index.html` pricing section, both JSON-LD `offers` blocks, the comparison table rows "Events per month", "Team members", "Roles + SSO", "Data exports", "One-click evidence packs in the dashboard", "Private / self-hosted deployment" | Remove (task 10) | Events-per-month quotas and dashboard evidence packs read as hosted capacity, which is the processor line (brief H; `test_no_page_sells_a_liability_the_operator_cannot_carry` exists for exactly this drift). Paid guards at $19.99 and $25 show no customers (brief F). |
| Builder $29 | Reprice to $9 and rename (task 10) | Only proven payment in the space is $4.99 for enforcement (brief F). $29 has zero takers after 6 weeks live. |
| `web/compare.html` ("observability vs verifiable proof"), `web/vs-microsoft-agt.html` | Footer only | Head-on comparison with a commodity price war (`repositioning-research` 2.3). |
| Homepage "Watch it work" videos 03 (Plans and licensing), 04 (Record from code, EU AI Act evidence report), 05 (Team and SSO) | Remove from `index.html`; files stay in `web/media/` | They demo the retired tiers. |
| Homepage "Three steps" (`with pr.record()` instrument, chain, verify) as the first explanation | Move below the guard and spend sections | Crypto is "the least differentiating part commercially" and "should stop being the first sentence" (`repositioning-research` section 3). |
| `Marketing/launch-show-hn.txt`, `Marketing/launch-reddit-claudeai.txt` as written | Rewrite (task 13) | Both lead with the git pack, which the vendor now ships. The measurement framing survives; the object changes. |
| `HANDOFF.md` "Next in order" item 3 (test hooks in subagents) and item 4 (attribution outreach) | Retract item 3 as answered against us; drop item 4 | Primary-verified: classifier checks subagents at three points. Brief E on attribution. |
| `cli.py:1576` "Budgets bind model calls made through the SDK; tool hooks carry no model spend." and `web/docs.html:443` "Tool hooks carry no model spend." | Becomes false after task 2; rewrite with the new truth | Code as read. |

Not killed, and why: the two verifiers, the spec, conformance vectors, RFC 3161 and OTS anchoring,
`replay.py`, `pr reconcile`, the anchor service. They are the record layer, they cost nothing
to keep, and the paid artefact in section 4 is built on them. `pr attest` and `action.yml` stay
as free commands with no roadmap.

---

## 3. The wedge

The question was: what does Provenrail do that is verifiably not covered by Anthropic auto mode,
Copilot managed permissions, Codex sandboxes or Docker sbx, that someone feels daily and before
an incident. Four candidates, ranked, with what exists and what is missing.

### Rank 1, and the choice: the same deterministic policy where no classifier runs, and across every agent

These are one wedge, not two, because they share the customer (whoever runs agents unattended
or on more than one vendor) and the code (one engine, thin host adapters).

Verifiably not covered:
- "`claude -p` or the Agent SDK" start in `default`; "Amazon Bedrock, Google Cloud's Agent
  Platform, Microsoft Foundry, Claude Platform on AWS" start in `default`. The documented CI
  story is a static allowlist with no target resolution and no record (primary-verified).
  Confirmed again today: "For `-p`, the built-in starting permission mode is Manual on every
  plan" (https://code.claude.com/docs/en/headless).
- Hooks are the user-owned deterministic layer and run in `-p`: "Without `--bare`, a `-p`
  session runs the hooks in a project's `.claude/settings.json`" (same URL). The Agent SDK runs
  "shell command hooks from settings files when the corresponding `settingSources` ... entry is
  enabled, which it is for default `query()` options" (https://code.claude.com/docs/en/agent-sdk/hooks).
- Every other agent now has a PreToolUse-shaped hook, and none of them has a classifier or a
  shared policy format: Codex `PreToolUse` with `tool_name`, `tool_input`, `cwd`, `session_id`,
  `transcript_path`, returning `permissionDecision` (https://learn.chatgpt.com/docs/hooks,
  enabled by default); Gemini CLI `BeforeTool` with the same five base fields, returning
  `decision: deny` or exit 2 (https://geminicli.com/docs/hooks/reference/); Copilot `preToolUse`
  with `toolName`, `toolArgs`, `cwd`, `sessionId`, returning `permissionDecision`
  allow/deny/ask, "supported in two Copilot surfaces: Copilot CLI and Copilot cloud agent"
  (https://docs.github.com/en/copilot/reference/hooks-reference); Cursor `beforeShellExecution`
  and `beforeMCPExecution` with `command`, `cwd`, `conversation_id`, returning `permission`
  allow/deny/ask (https://cursor.com/docs/agent/hooks). "ALL OF IT IS CLAUDE CODE ONLY" (brief C)
  is the vendor's ceiling and our floor.

Felt daily and before an incident: a team on CI feels it every pipeline run; a developer on two
agents feels it every time they would otherwise configure two guards. Not as loudly as cost,
which is why rank 2 ships inside it.

What exists: the whole engine. `guard.decide(policy, tool, tool_input, session_id, cwd)` is
already host-agnostic; only `parse_hook_input` (Claude field names) and the stdout shape in
`run_hook` (`hookSpecificOutput.permissionDecision`) are Claude-specific. `predicates.py`
resolves targets against `cwd`, which every host supplies. The standalone plugin engine is a
vendored copy held in lockstep by `tests/test_guard_standalone.py`. `pr guard hook --use` arms
packs with no config file.

CORRECTION, 2026-09-16, made after checking the code rather than this memo: the line that
stood here said "`attest.AGENT_SIGNATURES` already names the five hosts" and counted that as a
head start. It is not one. `AGENT_SIGNATURES` is a list of regexes matching a `Co-authored-by:`
trailer in a git commit message (`attest.py:74` to `89`). Matching the string "codex" in a
commit message and driving the Codex CLI's `PreToolUse` hook share a vendor name and nothing
else. No host other than Claude Code has ever been driven by this project, and the operator has
never run Codex, Gemini CLI, Copilot CLI or Cursor against it. The "no captured fixture, no
claim" rule in task 5 is the defence against exactly this, and this memo tripped over it on the
way to writing it.

What is missing: per-host payload parsing and output rendering (`hosts.py`, task 5), per-host
install (`pr guard install --host`), one captured real payload per host as a test fixture, a
tool-name normalisation table (the rules' `not_tool` lists use Claude Code names), a
`--bare`-compatible install path for `claude -p` (task 6; `--bare` skips settings discovery and
"will become the default for `-p` in a future release", headless doc), and the copy.

One limit to state, never hide: "The `permissionDecision` field on `PreToolUse` and
`PermissionRequest` hooks is ignored in `bypassPermissions` mode, when the classifier hasn't
finished running (indicated by `pendingClassifier: true`), or when the API has denied the
call" (https://code.claude.com/docs/en/hooks, fetched today). So under `--dangerously-skip-permissions`
the hook is advisory only, and in auto mode the interaction with `pendingClassifier` has to be
driven and documented before any claim is made about auto mode (task 0). `permissions.deny`
rules are a different mechanism and do block in every mode (primary-verified); the guard is not
one of those.

### Rank 2, shipped inside rank 1: an enforced spend cap at the tool boundary

Verifiably not covered: no vendor in the brief enforces a per-agent, per-day dollar cap at the
tool boundary; two tools in the whole space enforce a budget at all, Terse ($4.99/mo) and
LiteLLM (proxy), the other five only report (brief F). Anthropic reports `total_cost_usd` in
`-p` JSON output (headless doc) and does not stop anything on it. The classifier is not a cost
control. No evidence was gathered in this pass on Anthropic Console workspace spend limits;
task 13 requires verifying their granularity before any comparative sentence ships.

Felt daily and before an incident: the incident is the invoice, discovered afterwards
(`spend.py` docstring). `/guard-status` showing "$4.12 of $25 today" is felt every session.
Cost is "the only pain in the whole space with PROVEN payment behaviour" (brief F). It bites
hardest exactly where rank 1 lives: API-key billing in CI, the SDK and third-party clouds.
On Pro and Max the dollar figure is notional (flat rate), and the copy must say so.

What exists: `spend.py` (cross-process ledger, locked on POSIX and Windows, corrupt file reads
as unknown, never zero), `policy.Budget` with `session`/`day`/`total` scopes and `warn_at`,
`Policy.decide` budget evaluation with `on_unpriced`, `pricing.py` with Anthropic cache read,
5m and 1h cache write rates and `_flatten_usage` lifting `usage.cache_creation`,
`guard._seed_prior_spend`, `guard.budget_status`, `pr spend`, `pr reconcile` against a
provider invoice, `easy._validate_budgets` rejecting a cap that cannot bind.

What is missing, and it is one module: budgets bind only on `model_call` events raised by the
SDK. In hook mode `cli.py:1576` says so: "tool hooks carry no model spend". But the hook
payload carries `transcript_path` (hooks doc, "PreToolUse hook for a Bash command receives ...
`transcript_path`"), and the transcript carries `message.model` and `message.usage` with
`input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens` and
`cache_creation.ephemeral_1h_input_tokens` per assistant message (verified on this machine
today against a live Claude Code transcript). `pricing.cost_for` already accepts every one of
those keys (`_INPUT_KEYS`, `_CACHE_READ_KEYS`, `_CACHE_WRITE_KEYS`, `_CACHE_WRITE_1H_KEYS`,
pricing.py:222 to 234). So a PreToolUse hook can read the transcript tail since its last
offset, price each new assistant message, add it to the ledger, and deny the next tool call
once the day cap is crossed. Codex and Gemini hand over `transcript_path` too; their transcript
formats are not read in this pass and are deferred until a fixture exists. The transcript "is
written asynchronously and may lag" (hooks doc), so enforcement is roughly one turn late and the
copy says "stops within a turn", never "at the exact dollar".

### Rank 3: the record of what the classifier allowed

Verifiably not covered: "The classifier leaves NO ARTEFACT. Denial reasons are often just a rule
name" (brief C). What exists: the journal, `pr guard receipt`, `/guard-card`, signed chain,
anchoring, `pr risk`. What is missing: nothing structural. Ranked third because its value lands
after the incident (`repositioning-research` section 2), which is the framing this memo is
retiring from the front page. It becomes the paid artefact in section 4 and every rank 1 and 2
decision already writes into it.

### Rank 4: more first-party-grade destructive-command detection

Rejected as a wedge. Already free from the vendor for interactive Pro, Max and Team sessions
(brief B). The rules and predicates stay as the engine rank 1 carries to the surfaces and hosts
the vendor does not reach.

---

## 4. The invoice

Constraint honoured: the operator cannot host customer data (brief H). Paid is a licence for an
artefact produced from a 32-byte root, which is what the live anchor service already accepts and
cannot accept more of (`pricing.html` FAQ, "there is no field a record could arrive in").

Free, forever, MIT, no account: the guard on every supported host, the spend cap, the journal,
`/guard-status`, `/guard-card`, `pr spend`, `pr reconcile`, `pr guard receipt` (signed locally),
the two verifiers, `pr attest`, one independent RFC 3161 anchor per account (unchanged).

Paid, one SKU, $9 a month, Polar, licence key only: **Anchored statements**. Unlimited
`pr anchor-push` and `pr guard receipt --anchor`: an RFC 3161 timestamped, publicly checkable
receipt of what the agent was stopped from doing and what it spent, per repository and per
agent, that a third party (finance, security, a client) can verify without an account. This is
the existing Builder tier with two changes: the price, and the sentence it is sold with. It is
kept live because it already works end to end (HANDOFF "Done and verified") and retiring a
working payment path buys nothing.

Retired: Team $99, Enterprise, every events-per-month quota, SSO and roles as a sold feature,
dashboard evidence packs, data exports as a tier. The AGPL server remains self-hostable and is
not sold.

Honest expectation, in writing: zero paid conversions in the first six months. The evidence
supports no other forecast (brief F: paid guards show no customers; ccusage 332,083 downloads a
month, zero revenue). The SKU exists so that the first stranger who asks "can I pay you" has a
button, not because the button will be clicked.

What has to be true before more invoice is built: three distinct strangers, unprompted, ask for
one of (a) a policy pinned across an organisation's repositories, (b) a spend statement for
finance, or (c) a receipt they can hand to someone else. Each request is recorded verbatim in
`WORKLOG.md` with a date. Until three exist, no pricing work beyond task 10.

---

## 5. The two-week build

Ordered. Each task: files, one-line reason, definition of done. 1,279 tests stay green, ruff
clean, `python tools/vendor_guard_rules.py --check` passes, and every new user-facing claim is
pinned in `tests/test_claims_hygiene.py` or a sibling test. No em-dashes anywhere. Copy the
user will paste goes in `.txt` files.

**Task 0. Drive the classifier interaction once, before any copy is written.**
Files: `docs/auto-mode-interaction-2026-09.md` (new, findings only, verbatim output).
Reason: the hooks doc says `permissionDecision` is ignored while `pendingClassifier: true` and
in `bypassPermissions`; whether the hook is re-invoked after the classifier finishes in auto
mode decides one sentence on every page.
Done when: an interactive Claude Code session in auto mode with the plugin installed is asked to
run `rm -rf ~/x` and `git reset --hard` on a dirty tree, the hook payloads (with
`permission_mode` and any `pendingClassifier` field) are captured via a `tee` hook to a file,
and the doc records which engine answered and what the user saw. Same run repeated with
`--dangerously-skip-permissions`. The result determines the wording of tasks 8 and 9.

**Task 1. Transcript spend reader.**
Files: `src/provenrail/transcript.py` (new), `tests/test_transcript.py` (new),
`tests/fixtures/transcripts/claude-code-spend.jsonl` (new, synthetic, labelled fixture).
Reason: the hook has `transcript_path`; the transcript has `message.model` and `message.usage`;
`pricing.cost_for` prices it. Nothing joins them today.
Done when: `accrue(path, state) -> (new_cost_usd, unpriced_calls, state)` reads only lines
after `state.offset`, considers only `type == "assistant"` lines with `message.usage`, dedupes
by `message.id` (a streamed message appears as several lines sharing an id; the last usage
wins), prices with `pricing.cost_for`, returns the new byte offset and the set of ids seen in
the current partial message, and treats an unreadable or truncated file as "unknown" (returns
`known=False`), never as zero, mirroring `spend.prior_spend`. Tests cover: three messages
summed, a duplicated id counted once, an unpriced model reported not priced, a resume from
offset counting nothing twice, a file that shrank (rotated) resetting the offset to zero with
`known=False`. Stdlib only, because it is vendored in task 3.

**Task 2. Budgets bind in hook mode.**
Files: `src/provenrail/policy.py` (add `Policy.spent_verdict(session) -> Decision | None`
evaluating `effective_budgets()` against `session.scope_spend` already incurred; do not touch
`to_dict`, so no policy hash or conformance vector changes), `src/provenrail/guard.py`
(`parse_hook_input` adds `transcript_path`; `decide()` gains `transcript_path=None`; before the
rule loop, if the policy has budgets and a transcript path is present, load the per-session
transcript state from `.provenrail-guard-counts.json` under key `"spend"`, call
`transcript.accrue`, `spend.add_spend` the delta under `spend_agent_id()`, seed the state,
and return `deny` with rule `budget.<scope>` if `spent_verdict` denies; journal a warning entry
when `warn_at` is crossed), `src/provenrail/cli.py:1576` and `web/docs.html:443` rewritten to
the new truth, `tests/test_guard_budget.py` (new).
Reason: the spend cap is the one control with proven payment behaviour and it currently caps
nothing in the product's own recommended install.
Done when: driving `run_hook` twice against a fixture transcript that grows past a `day` cap
of $1 yields allow-with-warning then deny naming `budget.day`, the reason text tells the agent
to stop and names the file to raise the cap; an unreadable transcript yields allow plus a
once-a-day stderr line "spend cap cannot bind: transcript unreadable" (a misconfigured guard
never fails silently); a model with no price follows `on_unpriced`; `pr guard status` prints
today's figure from the ledger; a policy with no budgets pays no transcript I/O (assert the
file is never opened). The Anthropic-subscription caveat is in the deny reason: "estimated at
API list price".

**Task 3. Vendor the same into the zero-install plugin, in lockstep.**
Files: `tools/vendor_guard_rules.py` (`VENDORED_MODULES` gains `transcript.py`, `pricing.py`,
`spend.py`), `plugins/provenrail-guard/scripts/guard_standalone.py` (same budget path as task
2, reading `budgets` from `.provenrail.json`), `tests/test_guard_standalone.py` (lockstep cases).
Reason: the standalone engine answers when no CLI is installed, which is every fresh install;
a cap that binds only after `uv tool install` is a cap the README lies about.
Done when: `--check` passes; the same fixture transcript and policy produce the same verdict,
rule id and dollar figure from both engines; `pricing.py` imports nothing outside the standard
library (add a test that imports the vendored copy with `sys.path` restricted).

**Task 4. Set a cap in one command.**
Files: `src/provenrail/cli.py` (`pr guard budget <usd> [--scope day|session|total]
[--warn-at 0.8]`, merging into `.provenrail.json` through `easy._validate_budgets`, refusing a
second budget of the same scope unless `--replace`), `plugins/provenrail-guard/commands/guard-budget.md`
(new, writes the same JSON with a python one-liner), `tests/test_cli_guard.py`.
Reason: a default cap is a claim about the user's money and is forbidden; the cap must be one
command away instead.
Done when: `pr guard budget 25` writes `{"policy": {"budgets": [{"scope": "day",
"limit_usd": 25}]}}` preserving any existing `use` and `rules`, `pr guard status` shows it,
`/guard-budget 25` does the same with no CLI installed, and a non-numeric or zero value is
refused with the `_validate_budgets` message.

**Task 5. Host adapters: Codex and Gemini first, Copilot and Cursor second.**
Files: `src/provenrail/hosts.py` (new: `parse(host, data)` normalising to the dict
`parse_hook_input` returns, `render(host, verdict, reason)` producing each host's stdout JSON,
`canonical_tool(host, name)` mapping host tool names onto Claude Code names so `not_tool`
lists keep working), `src/provenrail/guard.py` (`run_hook(..., host="claude-code")`,
`install_hooks(host, root)` writing `.codex/hooks.json`, `.gemini/settings.json` hooks block,
`.github/hooks/provenrail.json`, `.cursor/hooks.json` additively, same idempotence as
`install_claude_hooks`), `src/provenrail/cli.py` (`pr guard install --host`, `pr guard hook
--host`), `plugins/provenrail-guard/scripts/guard_standalone.py` (`--host`),
`tests/fixtures/hosts/<host>-pretooluse.json` (one REAL captured payload per host, captured by
installing a `tee` hook and running each CLI once; not hand-written), `tests/test_hosts.py`.
Reason: no vendor will ship a policy that spans its competitors (brief C), and the engine is
already host-agnostic; only the envelope differs.
Rules for `render`: hosts without an `ask` verdict (Gemini; Codex until its `PermissionRequest`
event is driven) receive `deny` for `require_oversight`, and the journal and record keep
`require_oversight` as the effect with the host verdict in `extra`, so the record is never
flattened (the `record_hook` principle). Copilot cloud agent treats `ask` as `deny` per its own
doc; say so in the docs.
Done when: for each host with a fixture, the fixture for `rm -rf ~/` renders that host's deny
shape byte-exactly as its doc specifies, an ordinary command renders nothing, every command in
`tests/test_predicates.py::GIT_INCIDENTS` and `DATA_INCIDENTS` is non-allow through the adapter
on a dirty repo, `pr guard install --host X` in a temp dir writes the file and a second run
changes nothing, and `tests/test_claims_hygiene.py` gains
`test_every_host_named_on_the_site_has_a_fixture` (mirror of the detector-list test). A host
with no captured fixture is not named on any page. Codex and Gemini are due by day 5; Copilot
and Cursor by day 9; whichever is not fixtured by day 9 is left off the site, not promised.

**Task 6. The CI and headless recipe.**
Files: `src/provenrail/cli.py` (`pr guard settings --json` printing the hooks block for
`--settings`), `docs/ci.md` (new), `web/docs.html` (new section `#ci`), `.github/workflows/`
example in `docs/ci.md`, `tests/test_ci_recipe.py`.
Reason: `claude -p` starts in Manual with no classifier on every plan, `--bare` skips settings
discovery and will become the default, so the only durable install is `--settings` or
`--plugin-dir` (headless doc table).
Done when: `pr guard settings --json` output is valid Claude settings JSON with both hook
events; an integration test skipped when `shutil.which("claude")` is None runs
`claude --bare -p "run exactly: rm -rf ~/x" --settings <that json> --allowedTools Bash
--permission-mode dontAsk --output-format json` and asserts the hook's reason appears in
`permission_denials`; the founder runs it once and pastes the verbatim output into
`docs/ci.md`. The same doc shows the Agent SDK Python form with `setting_sources` default and
the Bedrock environment variables unchanged.

**Task 7. The guard-vs-guard scoreboard.**
Files: `bench/README.md` (new, pinned commit SHAs, exact reproduction command), `bench/run.py`
(new), `bench/vendors/` (git submodules or a `fetch.sh`, never committed copies),
`tests/test_scoreboard_inputs.py` (asserts `bench/run.py` imports `GIT_INCIDENTS`,
`DATA_INCIDENTS`, `UNRECOVERABLE`, `ROUTINE_GIT`, `ROUTINE_DELETES` from
`tests/test_predicates.py`, one list, one place).
Reason: "NOBODY has published a guard-vs-guard scoreboard on destructive commands. That slot is
open" and measured numbers in the title are the only launch format with a track record (brief D).
Done when: `python bench/run.py` feeds identical PreToolUse JSON to Provenrail defaults and to
cc-safety-net, nah, dcg, safety-net (kenryu42), railguard, ccguard and TracineHQ guard at
pinned SHAs, offline, and prints one table: documented data-loss commands stopped or allowed,
ordinary commands interrupted. Each vendor row links to its repo and the exact commit. The
README invites corrections and states the method's limits (regex hooks only, no sandbox
products, no classifier). Comparative public claims about named projects are the one item in
this memo the operator confirms before posting (CLAUDE.md legal fork (c)); the confirmation is
"the numbers are reproducible from the pinned commits", nothing else.

**Task 8. Homepage.**
Files: `web/index.html`, `web/llms.txt`, `web/sitemap.xml`, `tests/test_claims_hygiene.py`.
Reason: the H1 sells a free first-party default (brief B) and the rest sells retired tiers.
New order: (1) H1 and claim built from tasks 1 to 6: the surfaces where no classifier runs and
the cap that stops spend, in one sentence a stranger understands; (2) the table "where Claude
Code's classifier runs and where it does not" with the quoted starting modes and the URL,
fair to the vendor; (3) the spend cap with the exact `pr guard budget 25` line and the
subscription caveat; (4) one policy, N agents, naming only fixtured hosts; (5) the record
(`/guard-card`, receipt, anchor) as the second-page value; (6) the measured numbers
(36,977 commands, 40 of 40, scoreboard table once task 7 exists); (7) install; (8) pricing
(task 10); (9) FAQ with the auto-mode question answered first. Remove the three audience
sections, the compliance FAQ, videos 03 to 05, and the `featureList` compliance entries.
Done when: `test_the_completeness_boundary_is_stated_where_the_strong_claim_is_made` still
passes; new tests pin: the three surface strings "claude -p", "Agent SDK", "Bedrock" appear;
the dollar example on the page is evaluated through the task 1 fixture and yields the verdict
shown (extend `DEMOED`); no page names a host without a fixture; `index.html` contains neither
"Article 12" nor "HIPAA" outside the footer; every JSON-LD block parses; the page passes the
existing 375 px no-horizontal-scroll check and console-clean check; `seo-cro-aeo-auditor`
gate passes (CLAUDE.md rule 2).

**Task 9. Claude Code guardrails page.**
Files: `web/claude-code-guardrails.html`, `tests/test_claims_hygiene.py::test_the_page_title_and_the_headline_argue_the_same_thing`.
Reason: title, H1 and the "permission prompt is not enough" section argue against a solved
problem; this is the page the launch links to.
Done when: title, H1, `og:title`, `twitter:title` share one new anchor phrase (the test's
`phrase` tuple is updated to it in the same commit); a section "What auto mode already does,
and where it does not run" quotes the permission-modes doc with the URL and the CHANGELOG
2.1.183 line; the `bypassPermissions` and `pendingClassifier` limits from task 0 are stated
under "Limits, stated plainly"; the `DEMOED` verdicts on this page still hold; the install
section shows plugin, `--settings` for `-p`, and `--host` for the fixtured hosts.

**Task 10. Pricing.**
Files: `web/pricing.html`, `web/index.html` pricing section and both JSON-LD `offers`,
`src/provenrail/server/plans.py` (keep the four internal plan names; the site sells two),
Polar: a new $9 product in the sandbox org first, then production, per
`memory/polar-sandbox-proof-recipe.md`; `supabase/functions/polar-webhook/index.ts` gains
`POLAR_PRODUCT_STATEMENTS` mapped to the `builder` entitlement; `tests/test_claims_hygiene.py`.
Reason: section 4.
Done when: two cards (Free, Anchored statements $9/mo); no "events per month", "Team",
"Enterprise", "SSO", "dashboard" or "evidence pack" wording on either page (new banned
phrases in `SELLING_WHAT_WE_CANNOT_CARRY` with reasons); `test_the_pricing_page_still_says_where_records_live`
passes; a sandbox checkout with the test card provisions a licence that `pr anchor-push`
accepts (recipe), then the production product is created and the webhook secret and product
id rows are added to `CREDENTIALS.md`. Zero customers, so no migration.

**Task 11. Second-page the rest.**
Files: `web/eu-ai-act.html`, `web/eu-ai-act-deadline-moved.html`, `web/for-agencies.html`,
`web/ai-code-attribution.html`, `web/compare.html`, `web/vs-microsoft-agt.html` (nav and
footer links only; a one-line note at the top of each: "This page describes the record layer.
Start at the front page for the guard and the spend cap."), `web/sitemap.xml` priorities,
`web/_redirects` unchanged.
Reason: search referrals are 30 of 36 referred visits (brief A); the URLs stay, the emphasis goes.
Done when: none of these is linked from `index.html` above the footer; `test_every_json_ld_block_on_every_page_parses`
passes; all 22 routes still 200 (existing route check).

**Task 12. Plugin manifest, README, directory listing.**
Files: `plugins/provenrail-guard/.claude-plugin/plugin.json` (version 0.5.0, description
rewritten to lead with the surfaces and the cap, keywords add `spend-cap`, `budget`, `ci`,
`headless`), `plugins/provenrail-guard/README.md`, `pyproject.toml` version 0.5.0,
`web/changelog.html`.
Reason: brief D, the directory is the only ranked discovery surface and we are not in it.
Done when: `test_the_advertised_rule_counts_match_the_catalogue` passes against the new README;
the submission at clau.de/plugin-directory-submission is made and a PR adding
`provenrail-guard` to `anthropics/claude-plugins-community/.claude-plugin/marketplace.json` is
open; both URLs are in `WORKLOG.md`.

**Task 13. Launch copy, four files, paste-ready.**
Files: `Marketing/launch-show-hn.txt` (title carries the scoreboard number from task 7),
`Marketing/launch-reddit-claudeai.txt` (opens by crediting auto mode, then the surfaces table,
then the cap), `Marketing/launch-x-thread.txt` (new; brief D: dcg went to 5,992 stars off one X
post; the tamper clip becomes the cap clip: an agent stopped at $25.00 with the deny reason on
screen), `Marketing/launch-week-checklist.txt` (baselines re-read on day 0: cloners, views,
stars, referred pageviews, plugin directory installs once listed).
Reason: HANDOFF item 1, still true: nothing else matters until this happens.
Rules: every number in the copy is a test or a reproducible script; the three objections that
killed cc-safety-net are pre-answered (bypasses, wrong layer, false positives) plus the fourth,
"Claude Code already does this", answered with the quoted surfaces; any sentence about Anthropic
Console spend limits is written only after their granularity is verified from a URL, otherwise
omitted; ASCII only, no markdown, one paragraph per field.
Done when: the four files exist, the checklist has day-by-day order and the section 6 numbers
verbatim, and `test_the_advertised_rule_counts_match_the_catalogue` passes against the two
launch drafts it already reads.

**Task 14. The card shows money.**
Files: `src/provenrail/guard.py::card`, `plugins/provenrail-guard/scripts/guard_standalone.py::card`,
`tests/test_guard_card.py`.
Reason: the card is the shareable moment (brief D: incident posts travel; this is the same story
before the loss) and a dollar figure is not an operand.
Done when: when a budget exists the card adds one line "Spend today: $X of $Y (estimated at API
list price)"; the existing test that no path, hostname, URL or key survives still passes over
both corpora; both engines print the same line for the same ledger.

**Task 15. Release, record, back up.**
Files: `HANDOFF.md` (rewritten: retract item 3 as answered by the vendor, drop attribution
outreach, new "Next in order" is the launch checklist), `WORKLOG.md`, `BUSINESS.md` (streams
reduced to: MIT everything, one $9 artefact licence, AGPL server unsold),
`DISTRIBUTION.md` (sections 1 to 3 and 8 rewritten; the numbers table becomes section 6 of this
memo), `docs/repositioning-research-2026-09-07.md` (one line at the top pointing here as the
superseding decision).
Done when: `pytest -q` green, `ruff` clean, `vendor_guard_rules.py --check` green, `0.5.0` on
PyPI, plugin at 0.5.0, site deployed from the repo root, edge functions deployed if task 10
changed them, tag `v0.5.0` pushed, `autopilot-handoff --check` passes.

Sequencing: tasks 0 to 4 days 1 to 4; task 5 (Codex, Gemini) days 4 to 5; tasks 6 and 7 days 6
to 7; task 5 (Copilot, Cursor) days 8 to 9 in parallel with tasks 8 to 11; tasks 12 to 15 days
10 to 12; days 13 and 14 are the first two posts from the checklist, not more code. A task not
done by its day is cut from the copy, never promised.

---

## 6. What would falsify this

Measured, not remembered. Baselines from `Marketing/launch-week-checklist.txt` as of 2026-09-07:
unique 14-day cloners 23, unique repo views 5, stars 0, referred pageviews 14 in 17 days.
Re-read all four on launch day 0 and write them into the checklist before posting.

Primary falsifier, the distribution thesis. All five posts in task 13 actually made, plugin
listed in the directory, and by **2026-10-31**: fewer than **200 installs** on the
claude.com/plugins listing (the directory publishes the count, brief D) **and** unique 14-day
cloners below **70** (three times the baseline, the criterion HANDOFF already fixed). Either
number met keeps the thesis alive; both missed kills it. Then: tag `v0.5.x` final, README says
"maintained, not marketed", stop building, move the founder's time to a different product. No
further repositioning; the checklist already says so.

Second falsifier, the wedge. By **2026-10-31**, zero unprompted inbound (GitHub issue, email,
DM, comment) that mentions the spend cap, CI or headless use, or a second agent. Then the
"unattended and cross-agent" framing is wrong even if installs are fine, and the product is
judged on the guard alone, which the vendor ships free; same freeze.

Third, the invoice. By **2027-03-16** (six months), zero paid statements and fewer than three
recorded requests for a pinned policy, a spend statement or a hand-over receipt (section 4).
Then the paid SKU is removed and the project stays free for good.

What would strengthen it instead: one stranger's `/guard-card` posted anywhere, or one CI run in
someone else's repository visible in a public workflow file. Either is worth more than the
launch itself and is recorded verbatim in `WORKLOG.md` the day it appears.

---

## Sources fetched 2026-09-16

- https://code.claude.com/docs/en/permission-modes (via primary-verified.md)
- https://code.claude.com/docs/en/hooks (common input fields incl. `transcript_path`; `permissionDecision` ignored in `bypassPermissions` and while `pendingClassifier: true`)
- https://code.claude.com/docs/en/headless (`-p` starts Manual on every plan; runs project hooks unless `--bare`; `--bare` will become the default)
- https://code.claude.com/docs/en/agent-sdk/hooks (settings hooks run by default via `setting_sources`)
- https://learn.chatgpt.com/docs/hooks (Codex `PreToolUse`, fields, `permissionDecision`, on by default)
- https://geminicli.com/docs/hooks/reference/ (Gemini `BeforeTool` fields, `decision: deny`, exit 2)
- https://docs.github.com/en/copilot/reference/hooks-reference (Copilot `preToolUse`, CLI and cloud agent, `ask` is `deny` in cloud)
- https://cursor.com/docs/agent/hooks (Cursor `beforeShellExecution`, `beforeMCPExecution`, `permission` allow/deny/ask)
- Local: a Claude Code transcript on this machine, `message.model` and `message.usage` keys as listed in section 3.
