# Beginner persona audit and full documentation fact-check
**Date:** 2026-08-18  
**Auditor:** automated (Claude Sonnet 4.6)  
**Installed version under test:** provenrail 0.2.30 (PyPI latest, matching pyproject.toml)  
**uv version:** 0.11.6  
**Scratch directory:** /private/tmp/claude-501/.../scratchpad/sam-run/test-dev  

---

## Part 1 -- Sam's narrative

Sam is 24, six months into his first job. He found /start because his lead said "set this up for our agent by Friday." He reads pages literally and follows instructions keystroke by keystroke.

**Time started:** about 8 minutes into reading (after absorbing the introduction and TOC).

**Section 0 -- What you need**  
Sam reads the requirement list: a computer, internet, ten minutes, no Python, no Docker, no account. Clear. No ambiguity.

**Section 1 -- Open the terminal**  
Sam is on macOS. He presses Cmd+Space, types Terminal, presses Enter. A window opens with a % prompt. The page describes this exactly. No confusion.

**Section 2 -- Install uv**  
Sam copies the macOS line and pastes it. It works. He closes the terminal and opens a new one as instructed. He runs `uv --version`. The actual output is `uv 0.11.6`, which matches the version shown on the page exactly. Sam is on track.

**Section 3 -- Install Provenrail**  
Sam runs `uv tool install provenrail`. It installs successfully. The page claims output: `Installed 3 executables: pr, pr-server, pr-verify`. The actual uv output matches this format.

Then the page says: "Check it is there by running `pr` on its own. It prints its list of commands."

**First confusion point.** The page shows:
```
usage: pr [-h] {serve,activate,demo,verify,disclose,report,pack,diff,quickstart,...} ...
```
The actual output Sam sees is a friendly message:
```
Provenrail: a tamper-evident, independently verifiable record of what your AI agent did.

Start here (no account, nothing leaves your machine):
  pr demo            create a sample sealed run
  pr verify bundle.json   re-derive every hash and signature, trusting nobody
...
```
The page promised a `usage:` line. Sam sees something different. He reads the note "It prints its list of commands, which means it is installed and working." The commands are there in the friendly output, just not in the format shown. A literal reader would not recognise this as matching. Sam likely proceeds but is unsure.

**Section 4 -- Your first proof**  
Sam runs `pr demo`. The first two lines of output match what the page shows. The actual output also includes additional lines the page does not show (tampering hint, `pr report`, `--pin` and `--tlog-pubkey` lines). These are not harmful; they are additional guidance. Sam is not confused here.

Sam runs `pr verify bundle.json`. The output shows several `[warn]` lines and ends with `RESULT: VERIFIED`. The page correctly anticipates these warnings in a note box. The final line matches. Sam sees the green VERIFIED. This step passes cleanly.

**Section 5 -- Record your own run**  
Sam makes the `my-first-agent` folder and moves into it. Clear.

Sam runs `pr quickstart`.

**Second confusion point.** The page shows quickstart output that includes:
```
See it work right now, without writing any code:
    pr demo                   # records a real run and writes bundle.json
    pr verify bundle.json     # recomputes everything, trusts nobody
```
The actual quickstart output says:
```
Now your whole setup is two lines:

    import provenrail as fr
    with fr.record('my-agent'):
        ...
```
The demo suggestion is absent. The prose that follows says "Do the two lines it just offered you, in that order" but the terminal did not offer those two lines. Sam looks at the terminal, then at the page, back at the terminal. He runs `pr demo` and `pr verify bundle.json` as the page instructs explicitly, so the commands execute, but he is not sure why the output did not match.

Sam writes the script. Two versions are shown on the page: a full editor version (with `record_human_oversight` and `usage=`) and a `cat > EOF` shell version (missing both). These are presented as equivalent alternatives but produce different runs.

Sam runs `uv run --with provenrail python my_first_agent.py`. The page shows the first output line as `Installed 26 packages in 19ms`. This line only appears when packages are not cached; on a warm uv cache it is absent. Sam, on a first-ever uv run, would see it. The script prints "Done. The run was captured and sealed off-box." Correct.

Sam runs `pr export my-run.json`.

**Third confusion point (the clearest failure).** The page shows:
```
wrote my-run.json (4 records, 1 anchors).
```
The actual output is:
```
wrote my-run.json (5 records, 2 anchors).
```
The record count and anchor count are wrong. Sam reads "4 records, 1 anchors" on the page and sees "5 records, 2 anchors" in the terminal. A literal reader assumes they did something wrong. Sam tries `pr export` twice more. The number does not change. Sam messages his lead: "it doesn't work, the numbers are wrong."

`pr verify my-run.json` returns VERIFIED. If Sam gets this far, the integrity proof is green. Sam is reassured but the count mismatch is unexplained.

The `pr report` and `pr pack` commands both execute cleanly. The pack output says "attestation" where the page says "evidence summary," a minor wording mismatch Sam would not notice on first read.

`pr quickstart --stop` matches exactly.

**Where Sam ends up:** Sam completes the walkthrough with green VERIFIED results on both the demo bundle and his own run. The confusion at `pr quickstart` output and the "5 records vs 4 records" discrepancy caused him to hesitate, but he did not give up permanently. He considers it "done but weird." Total time: roughly 14 minutes, not 10.

---

## Part 2 -- Command and code sample fact-check table

### web/start.html

| Command / sample | Expected (page) | Actual | Result |
|---|---|---|---|
| `uv --version` | `uv 0.11.6` | `uv 0.11.6` | PASS |
| `uv tool install provenrail` | `Installed 3 executables: pr, pr-server, pr-verify` | Matches | PASS |
| `pr` (no args) | `usage: pr [-h] {serve,activate,demo,verify,disclose,...}` | Friendly help message; no `usage:` line at top | FAIL |
| `pr demo` | 2 specific output lines | Same 2 lines plus extra hint lines | PASS |
| `pr verify bundle.json` | `RESULT: VERIFIED` | `RESULT: VERIFIED` (with extra warn lines, noted on page) | PASS |
| `pr quickstart` output | Shows demo suggestion lines | Those lines are absent; output text differs | FAIL |
| Python editor script | 3 calls: record_model_call + record_decision + record_human_oversight | All 3 methods exist and accept shown args | PASS |
| cat > EOF shell script | Claims same as editor script | Missing record_human_oversight and usage= | FAIL |
| `uv run --with provenrail python my_first_agent.py` | `Installed 26 packages in 19ms` + "Done..." | "Done..." only (install line missing on warm cache) | PASS on first run |
| `pr export my-run.json` | `wrote my-run.json (4 records, 1 anchors)` | `wrote my-run.json (5 records, 2 anchors)` | FAIL |
| `pr verify my-run.json` | `RESULT: VERIFIED` | `RESULT: VERIFIED` | PASS |
| `pr report --regime eu-ai-act my-run.json --md > report.md` | Writes report.md | Writes report.md with EU AI Act Article 12 mapping | PASS |
| `pr pack my-run.json --out evidence.zip` | Contents includes "evidence summary" | Contents shows "attestation" | FAIL |
| `pr quickstart --stop` | `stopped the local Provenrail sink` | `stopped the local Provenrail sink` | PASS |
| `pr activate prl_live_your_key_here` | `License valid: builder tier...` | `License key invalid: malformed license key` (correct for fake key) | PASS |

### web/docs.html

| Command / sample | Result |
|---|---|
| `uv tool install provenrail` | PASS |
| `python3 -m venv .venv && source .venv/bin/activate; pip install provenrail` | PASS |
| `uv add provenrail` | PASS |
| `npm install provenrail` | PASS -- npm package exists at 0.2.30 |
| `pr quickstart; pr guard install; pr guard status; pr guard receipt; pr guard uninstall` | PASS |
| `import provenrail as fr; with fr.record("my-agent"): ...` | PASS |
| `from provenrail.integrations import instrument_openai, instrument_anthropic, instrument_mcp` | PASS |
| `from provenrail.integrations.langchain import ComplianceCallbackHandler` | PASS |
| `from provenrail.integrations.claude_sdk import provenrail_hooks` | PASS |
| `from provenrail.integrations.agno import provenrail_tool_hook` | PASS |
| `from provenrail.integrations.hermes import register_provenrail` | PASS |
| `import { record } from "provenrail"; await record(...)` (TypeScript) | PASS |
| `pr verify bundle.json --pin pin.json` | PASS |
| `pr export my-run.json; pr verify my-run.json` | PASS |
| `pr rules --check bundle.json` | PASS |
| `pr risk bundle.json; pr risk bundle.json --json` | PASS |
| `pr spend my-run.json; pr spend; pr spend --agent billing-bot` | PASS (0.2.30) |
| `pr reconcile my-run.json --invoice openai-usage.csv` | PASS (0.2.30) |
| `pr verify-content my-run.json --file prompt.json --field request` | PASS |
| `pr disclose my-run.json --openings keys.json` | PASS |
| `pr report --regime eu-ai-act / hipaa / generic` | PASS -- all three regimes exist |
| `pr serve --anchor rfc3161 --tsa https://freetsa.org/tsr` | PASS |
| `docker compose up` | PASS -- docker-compose.yml exists |
| hmac webhook code: `hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()` | PASS |
| `pr activate prl_live_...` | PASS |

### web/for-agencies.html

| Command / sample | Result |
|---|---|
| `uv tool install provenrail; pr quickstart` | PASS |
| `with fr.record("client-project"): result = run_agent(task)` | PASS |
| `instrument_anthropic(client, fr)` where fr is the module | FAIL -- records nothing; see CRIT-1 |
| `pr export my-run.json; pr verify my-run.json` | PASS |
| `pr pack my-run.json --regime generic --out client-evidence.zip` | PASS |

### web/claude-code-guardrails.html

| Command / sample | Result |
|---|---|
| `/plugin marketplace add pofky/provenrail; /plugin install provenrail-guard@provenrail` | Cannot test (Claude Code plugin) |
| `uv tool install provenrail; pr quickstart; pr guard install` | PASS |
| `pr guard receipt; pr verify guard-receipt.json` | PASS |

### README.md

| Command / sample | Result |
|---|---|
| `pr quickstart; pr guard install; pr guard status; pr guard receipt` | PASS |
| `pr --version` | PASS in 0.2.30 |
| `pr guard hook --use destructive,secrets` | PASS |
| `pr demo; pr verify bundle.json --pin pin.json` | PASS |
| `pr report --regime eu-ai-act bundle.json --md` | PASS |
| `pr diff run-a.json run-b.json` | PASS |
| `pr serve --anchor rfc3161` | PASS |
| `pr sidecar --upstream https://api.openai.com` | PASS |
| `pr witness --log <origin>=<pubkey>` | PASS |
| `pr anchor-push` | FAIL -- command does not exist |
| `pr anchor-verify` | FAIL -- command does not exist |
| `pr verify --tsa-root host=cert.pem` | FAIL -- flag does not exist |
| `from provenrail.ingest_client import provision_stream` | PASS |
| `from provenrail.sdk import FlightRecorder` | PASS |
| `@fr.tool("search")` decorator | PASS |
| `pr spend; pr risk guard-receipt.json` | PASS |

---

## Part 3 -- Findings by severity

### CRITICAL -- affects correctness or trust

**CRIT-1: for-agencies.html instrument_anthropic(client, fr) silently records nothing**  
File: `web/for-agencies.html`, code block containing `instrument_anthropic(client, fr)`  
The example passes the module object (`import provenrail as fr`) as the recorder argument to `instrument_anthropic`. The integration layer's `_capture()` in `src/provenrail/integrations/_common.py` calls `recorder.record_model_call(...)` which on the module object raises `AttributeError`. That exception is swallowed by `except Exception: pass`. No model calls are recorded. No error is raised. An agency operator who follows this example will believe they have an audit trail and will have none.  
Corrected code:
```python
with fr.record("client-project") as rec:
    instrument_anthropic(client, rec)
    result = run_agent(task)
```

### HIGH -- broken commands documented as working

**HIGH-1: `pr anchor-push` does not exist**  
File: `README.md`, line 372  
Text: "`pr anchor-push` sends a local bundle's root". Running it: `pr: error: argument cmd: invalid choice: 'anchor-push'`. The command is absent from the CLI at 0.2.30.  
Remove the mention or replace with the actual API call (POST /v1/anchors with the merkle root).

**HIGH-2: `pr anchor-verify` does not exist**  
File: `README.md`, line 373  
Text: "`pr anchor-verify` checks a receipt against a bundle offline, without calling". Same error.  
Remove or describe the actual offline verification approach.

**HIGH-3: `pr verify --tsa-root` flag does not exist**  
File: `README.md`, approximately line 456  
Text: `(pr verify --tsa-root host=cert.pem`, `trust.add_root(...))`. Running it: `pr: error: unrecognized arguments: --tsa-root`. The flag list for `pr verify` is: `--pin`, `--openings`, `--tlog-pubkey`, `--witness-pubkeys`, `--registry-pubkey`, `--bitcoin-header`, `--json`.  
Remove the flag mention or substitute `--tlog-pubkey` which pins the transparency log public key.

### MEDIUM -- wrong output causes literal-follower confusion

**MED-1: `pr export` record and anchor count is wrong**  
File: `web/start.html`, step 5, sub-step 5  
Page shows: `wrote my-run.json (4 records, 1 anchors)`. Actual output for the documented 3-call script: `wrote my-run.json (5 records, 2 anchors)`. The 5 records are `lifecycle.session_start`, `model_call`, `decision`, `human_oversight`, and `lifecycle.session_end`. Lifecycle events were added after this copy was written.  
Corrected expected output: `wrote my-run.json (5 records, 2 anchors)`.

**MED-2: `pr` (no args) output format does not match the page**  
File: `web/start.html`, section 3  
Page shows the `usage: pr [-h] {...}` format. Actual output of `pr` with no args is a friendly multi-line help message. The `usage:` format appears only with `pr -h`. A beginner comparing terminal output to the page sees a mismatch and cannot tell if the install worked.  
Change the instruction to `pr -h` or update the expected output block to match the friendly message.

**MED-3: `pr quickstart` output is stale**  
File: `web/start.html`, section 5, sub-step 2  
Page quotes output that includes "See it work right now, without writing any code: pr demo / pr verify bundle.json". Actual output omits this section; it says "Now your whole setup is two lines." The prose following says "Do the two lines it just offered you, in that order," which then refers to lines the terminal never printed.  
Update the quoted output block and the following prose to match the current quickstart output.

**MED-4: Two versions of the sample script are not equivalent**  
File: `web/start.html`, section 5, sub-step 3  
Editor version has three API calls and a `usage=` argument. The `cat > EOF` shell version has two API calls and no `usage=`. The page presents them as equivalent alternatives. A beginner who uses the shell version gets a different run from the one described in subsequent steps.  
Make both versions identical. Add `record_human_oversight` and `usage=` to the shell version.

**MED-5: `pr pack` contents label changed from "evidence summary" to "attestation"**  
File: `web/start.html`, section 5, sub-step 6  
Page: `Contents: bundle.json, evidence summary, VERIFY.txt, MANIFEST.json`. Actual: `Contents: bundle.json, attestation, VERIFY.txt, MANIFEST.json`. The copy is stale.

### LOW -- factual notes

**LOW-1: DESIGN-agent-audit-trail.md referenced in source code does not exist**  
File: `src/provenrail/__init__.py`, line 5 (comment)  
Comment refers to "DESIGN-agent-audit-trail.md section 11". No such file is in the repository. Not user-facing; impacts only developers reading the source.

**LOW-2: "Nothing is sent anywhere" badge is not qualified for paid plans**  
File: `web/start.html`, meta section, line 129  
The badge appears before the paid plan discussion and reads as a global property. The paid section and FAQ do explain the Merkle root transmission, but a reader who skims the badges gets an incomplete picture. Consider adding "on the free plan" or qualifying the badge text.

