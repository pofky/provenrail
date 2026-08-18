# Persona walkthrough: Marek, freelance AI engineer, 2026-08-18

Persona: Marek, 31, Krakow. Builds custom agents for three SME clients at 60 EUR/hr. His client just asked "how do I know your bot didn't delete those records?" He has 20 minutes. He googles and lands on provenrail.com. He has never touched cryptography beyond `https`.

Audited the LOCAL copy (`web/` served via `python3 -m http.server 8911`). CLI version: `provenrail 0.2.30`, binary at `/Users/povkon/.local/bin/pr`. Date: 2026-08-18.

---

## Stage-by-stage narrative

### Stage 1 - Landing on the homepage (0-10 seconds, elapsed: ~0:00)

Marek lands on the homepage. In 3 seconds he reads: "Your coding agent is one command from deleting prod." The hero paragraph directly answers his client's question: "Every decision is signed and hash-chained off-box, verifiable by anyone with an open-source tool that trusts neither the agent nor us."

The headline and sub-copy nail the scenario. The eyebrow label says "Agent guardrails, with a receipt" - that word "receipt" maps immediately to what his client is asking for.

His eyes go first to the two CTAs: "Guard my agent" (scrolls to the live proof demo) and "Verify a record yourself" (/verify). He probably clicks the second one - that is the client's question, not his.

The "For freelancers and agencies" section on the homepage confirms this is for him: "When you deliver an autonomous agent project to a client, billing disputes and scope-creep questions are inevitable."

One friction point: the nav shows "Start here" but clicking it returns a 404 on the local server. Every clean URL - /start, /docs, /for-agencies, /pricing, /verify, /account - returns 404 via the Python static server. This is because Python's http.server does not honour Cloudflare's clean-URL convention; on the deployed site these work. But in any local dev session, all nav links are dead. Marek, following homepage CTAs, would hit 404 immediately on any click that isn't an anchor link.

TIMING: 10 seconds to understand the product. Clean. The "Honest scope" note below the hero is good - it pre-empts the "but my agent could just not call the hook" objection before any skeptic asks it.

### Stage 2 - /for-agencies page (elapsed: ~1:30, via /for-agencies.html locally)

The page opens with a scenario that is Marek's exact situation: "A client hired you to build an agent that processes their customer data... Three weeks after delivery, they come back with a question."

The five-step scenario walkthrough is persuasive and concrete. Step 04 is the money paragraph: "The client installs the open-source verifier (uv tool install provenrail) and runs: pr verify my-run.json --pin pin.json." This answers the client's question.

Three honest disclaimers are present and well-written: "Not a compliance certificate", "Not a guarantee of completeness", "Not a promise the client cannot dispute." These are appropriate for a sole operator with no liability shield.

The regulatory section names three EU dates correctly (Art 50 from 2026-08-02, Art 12 from 2027-12-02, Annex I from 2028-08-02) and includes the honest framing: "Do not claim to a client that you are EU AI Act compliant because you use Provenrail."

Skim-reading time to reach the five-minute setup section: about 2 minutes. The page is long but the section anchors let Marek skip.

### Stage 3 - Install and first run (elapsed: ~3:00)

Following start.html (accessed as /start.html since /start 404s):

Step 1 - start.html already has uv installed (the page instructs `curl -LsSf https://astral.sh/uv/install.sh | sh`). Skipped.

Step 2 - `uv tool install provenrail` - already installed at 0.2.30. Would work on a fresh machine.

Step 3 - `pr` with no args - prints usage. PASSES.

Step 4 - `pr quickstart` in a new folder:

```
started a local sink (pid 47022) and wrote .provenrail.json
```

PASSES. Output is clear.

Step 5 - `pr demo`:

```
Recorded a 6-event demo run and sealed it into bundle.json.
```

PASSES.

Step 6 - `pr verify bundle.json`:

```
[warn] local_anchor_only: only LOCAL anchors present ...
[warn] anchor_local_only: anchor 0: LOCAL anchor only ...
[warn] tlog_log_key_unknown: anchor 0: no log public key configured ...
[warn] tlog_inclusion_unwitnessed: anchor 0: ...
[info] scitt_receipt_present: 1 SCITT COSE receipt(s) present but unverified ...
[info] summary: 6 records, 1 anchors, 0 heartbeats.

RESULT: VERIFIED
```

PASSES but produces 4 [warn] lines and 2 [info] lines before the verdict. The page pre-empts this: "You will also see a few [warn] lines, and that is expected on the free plan." The explanation is present. Still jarring for a first-time user - 6 lines of yellow/grey noise before the green verdict. Marek sees "warn" and "unverified" and wonders if something is broken. He reads the explanation and calms down, but this is friction.

Elapsed time to VERIFIED: approximately 4 minutes from terminal open. Within Marek's 20-minute budget.

### Stage 4 - Recording a real agent run (elapsed: ~8:00)

Following start.html step 5, Marek creates my_first_agent.py using the documented API. The page shows:

```python
import provenrail as fr

with fr.record("my-first-agent") as run:
    run.record_model_call("anthropic", "claude-opus-4-8", ...)
    run.record_decision("answer is grounded; returning to user", confidence="high")
    run.record_human_oversight("approved", approver="me@example.com")
```

Running `uv run --with provenrail python my_first_agent.py` - PASSES.

`pr export my-run.json` - PASSES, outputs "wrote my-run.json (7 records, 2 anchors)".

`pr verify my-run.json` - PASSES, RESULT: VERIFIED.

`pr report --regime eu-ai-act my-run.json --md` - PASSES, produces readable Markdown with honest "WARNING: no trusted timestamp" caveat. Good.

`pr pack my-run.json --out evidence.zip` - PASSES, produces 14692-byte ZIP with bundle, attestation, VERIFY.txt, MANIFEST.json.

One trap: the page's code uses `python` (not `python3`). On macOS only `python3` exists unless Python 2 is installed. However `uv run --with provenrail python` works because uv provides its own Python. If Marek tries `python my_first_agent.py` directly (skipping the `uv run` prefix), he gets `command not found: python`. A footnote warning about this would prevent confusion.

### Stage 5 - Giving the client something (elapsed: ~13:00)

Marek has `my-run.json` and `pin.json`. The for-agencies page tells him to send both files. The client runs:

```
pr verify my-run.json --pin pin.json
```

On the free tier, the CLIENT must install `pr` to verify. This is the key friction point for the value proposition: free tier = client installs a CLI tool; Builder plan ($29) = client opens a URL in a browser.

The browser verifier at /verify works. The demo button loads the real demo bundle and shows VERIFIED in browser. The "See it catch a tampered run" button would demonstrate tampering detection. This is the right UX for a client who will not install anything.

The free tier is enough to answer the client's question IF the client is willing to install `uv tool install provenrail`. For a non-technical client that is a barrier.

### Stage 6 - Pricing decision (elapsed: ~16:00)

Marek reads the pricing section. Does he understand what $29 buys?

Mostly yes. The pricing copy on /for-agencies is the clearest: "The Builder plan at $29 per month adds RFC 3161 trusted timestamps from an independent time authority (so timing cannot be back-dated, even by you) and shareable hosted read-only proof links your client can open in a browser without installing anything."

That last phrase - "without installing anything" - is the upgrade trigger for Marek. His client is not a developer. Making the client install a CLI tool is a professional friction. A URL they can open is not.

However: the Builder plan feature list says "Independent anchoring: send the root of your chain, keep every record" and mentions `pr anchor-push`. That command does not exist (see findings). This actively breaks trust in the pricing page if Marek tries it.

Would Marek pay $29? Honest answer: YES, if he successfully completed stages 3-5 AND the anchor-push confusion doesn't derail him. The hosted proof link alone justifies $29 for a 60 EUR/hr freelancer. One client conversation avoided is worth more than $29.

### Stage 7 - pr anchor-push and pr anchor-verify (elapsed: ~18:00)

Marek reads that Builder includes "independent anchoring: send the root of your chain, keep every record (pr anchor-push)" in pricing.html (line 144).

He runs:

```
$ pr anchor-push
pr: error: argument cmd: invalid choice: 'anchor-push'
```

The command does not exist. He also tries:

```
$ pr anchor-verify
pr: error: argument cmd: invalid choice: 'anchor-verify'
```

Also does not exist.

The for-agencies FAQ does contain a disclosure buried in a dropdown: "Works today against a server you run; the hosted independent service is not open yet." But this is below the fold and requires expanding a FAQ item. The pricing bullet point mentions the command as if it is runnable today. It is not.

The actual workflow for self-hosted trusted timestamps is `pr serve --anchor rfc3161 --tsa https://freetsa.org/tsr`, documented in docs.html. This is never surfaced in the pricing or for-agencies pages as the alternative to the missing hosted service.

---

## Findings by severity

### CRITICAL

**F1 - `pr anchor-push` and `pr anchor-verify` do not exist**
File: `web/pricing.html` line 144; `web/for-agencies.html` line 144
The pricing feature "Independent anchoring (pr anchor-push)" lists a command that returns "invalid choice" when run. The for-agencies FAQ discloses that the hosted service is not open, but the bullet point implies the command works. `pr anchor-verify` is also absent from the CLI. The actual self-hosted path is `pr serve --anchor rfc3161` (documented only in docs.html). A user who pays for Builder and tries to exercise this feature immediately hits an error. Fix: remove the command references from pricing bullets, or add a parenthetical pointing to `pr serve --anchor rfc3161` as the current path, or add a prominent "hosted independent anchoring: coming soon" label to the pricing card.

**F2 - Team plan compliance regime inconsistency: HIPAA vs ISO 42001**
File: `web/index.html` (hero pricing section, JSON-LD) says "EU AI Act Article 12 and HIPAA audit-control requirements"; `web/pricing.html` (feature list line 164, JSON-LD line 77) says "EU AI Act Article 12 and ISO 42001 controls". These are different compliance frameworks. A buyer comparing both pages gets contradictory feature descriptions. Either HIPAA or ISO 42001 is wrong, or both are included and neither page is complete. Fix: pick one canonical list and apply it everywhere, or list both if both are delivered.

### HIGH

**F3 - All clean URL navigation 404s on the local dev server**
File: all pages; root cause: `web/_redirects` comment says Cloudflare handles clean URLs natively but Python http.server does not. Every navbar link (/start, /docs, /pricing, /for-agencies, /compare, /verify, /account) returns HTTP 404. The homepage loads; clicking any nav link breaks. This makes local development and local auditing broken. Fix: add a `README-local.md` note to use `python3 -m http.server 8911` only for asset inspection and use Wrangler or Cloudflare Pages local dev for navigation testing. Alternatively, add a thin local router script.

**F4 - Console error on every page (analytics CORS)**
File: `web/main.js` line 140
The analytics beacon fires a fetch to the production endpoint from localhost, prints a CORS failure in the browser console, and the code even comments "printed a CORS failure in the visitor's console. That is a console error on a real [visit]." The comment acknowledges this is also present on the deployed site for visitors who block the endpoint or are on a network that blocks it. One visible console error on every page reduces confidence for any visitor who opens DevTools (including technical evaluators). Fix: suppress the console error for the fallback fetch path (catch the rejection silently, or use `mode: 'no-cors'`), or remove the comment that says this is expected on real visits.

### MEDIUM

**F5 - Five [warn] lines before RESULT: VERIFIED confuse first-time users**
File: `web/start.html`
The free-tier verify output produces 4 [warn] and 2 [info] lines before the verdict. The page explains this well in a callout box, but the callout appears AFTER the code block showing the output - the user sees the warning-heavy output first, then scrolls to the explanation. Marek sees "local_anchor_only", "anchor_local_only", "tlog_log_key_unknown", "tlog_inclusion_unwitnessed" and wonders if the install worked. Fix: move the callout before the code block, or change the callout heading from the current generic text to something that directly says "You will see warning lines - that is correct."

**F6 - Free tier client friction not surfaced early enough**
File: `web/for-agencies.html`, `web/index.html`
The free tier requires the client to install `uv tool install provenrail` to verify a bundle. This is a significant friction for a non-technical client. The distinction (free = client installs CLI; Builder = client opens a URL) is present on the for-agencies page but only in the pricing section at the bottom. The for-agencies hero and scenario walkthrough treat client verification as equally easy on all plans. Fix: add one sentence to the scenario walkthrough noting that on the free plan the client installs the verifier; Builder gives them a browser link instead.

**F7 - `python` command absent on macOS is a latent trap**
File: `web/start.html` step 4
The page instructs `uv run --with provenrail python my_first_agent.py` which works because uv provides Python. But the agent script template uses `python` (not `python3`), and if Marek tries to run it with `python my_first_agent.py` directly (without the `uv run` prefix), he gets `command not found: python` on macOS. The troubleshooting table covers "command not found: python or python3" but only if the user reads it. Fix: add a note in step 4 that `python` must be run via `uv run --with provenrail python` or that `python3` can substitute.

### LOW

**F8 - `pr verify` shows `pr-verify 1.2.0` in for-agencies example output but installed version is 0.2.30**
File: `web/for-agencies.html` (example output block)
The example output shows `verified by: pr-verify 1.2.0 (local, offline)` but the actual installed binary is `provenrail 0.2.30`. If a Marek compares the example to his own output he sees a version mismatch. Not a functional issue but reduces confidence. Fix: update the example or use a generic placeholder.

**F9 - `start.html` last updated "5 August 2026"; `claude-opus-4-8` is an invented model ID**
File: `web/start.html`
The example agent code uses `claude-opus-4-8` as a model name. As of August 2026, the current Anthropic model names are claude-opus-4-5 or similar. An AI engineer like Marek would notice this is not a real model ID and wonder if the rest of the example is accurate. Fix: use `claude-opus-4-5` or a real model identifier in the sample code.

---

## Claim verification

The following claims were checked against the running code:

- "Free tier. No credit card. Installs in seconds." - TRUE. `uv tool install provenrail` works, no auth required.
- "Two commands. Nothing to rewrite." (`pr quickstart && pr guard install`) - PARTIALLY TRUE. `pr quickstart` works. `pr guard install` is a separate subcommand for Claude Code hook install; not tested here but documented separately.
- "pr verify exits 0 if intact and non-zero with a detailed error if any record is missing" - TRUE, confirmed by test.
- "Nothing is sent anywhere" (local install) - CONFIRMED by packet behaviour; analytics beacon fails and falls back, no agent records leave the machine.
- "RFC 3161 trusted timestamps on Builder and higher" - TRUE in code; `pr serve --anchor rfc3161` implements this. The hosted Provenrail service for this is NOT OPEN yet (disclosed in for-agencies FAQ).
- "Independent anchoring: send the root of your chain, keep every record (pr anchor-push)" - FALSE as stated. The command `pr anchor-push` does not exist. The underlying feature exists when self-hosting.
- EU AI Act Art. 12 applies from 2027-12-02 - CORRECT per MEMORY (Reg (EU) 2026/1744).
- Art. 50 applies from 2026-08-02 - CORRECT.
- Team plan: "evidence packs mapped to EU AI Act Article 12 and HIPAA audit-control requirements" (index.html) vs "ISO 42001 controls" (pricing.html) - INCONSISTENT. Cannot verify which is accurate.

---

## Three direct answers

**(a) Would Marek finish the setup?**

YES, if he follows start.html step-by-step using `uv run --with provenrail python`. The commands work end-to-end: install, quickstart, demo, verify, write agent script, export, verify own run, pack evidence ZIP. Total time to a working evidence pack: approximately 15 minutes. Within his 20-minute window. The only sticking point is the verify warning lines, which the page explains adequately if he reads it.

**(b) Would Marek pay?**

PROBABLY YES, at $29/month for Builder, but not on the first visit. He finishes the free tier, successfully sends his client evidence.zip and the CLI verify command. The client balks at installing a tool. Marek goes back, reads that Builder gives the client a URL instead, and converts. The anchor-push confusion (F1) is the risk that prevents conversion - if he discovers the command fails before he sees the hosted proof link value, he loses confidence and closes the tab.

**(c) What is the single biggest thing standing between him and paying?**

The `pr anchor-push` ghost command. It is listed on the Builder plan pricing card as a deliverable. It does not exist. A technical buyer like Marek will test it before paying. When it fails, the question becomes "what else on this pricing page is not real?" The honest FAQ disclosure ("the hosted service is not open yet") is present but requires expanding a FAQ item to find it. The fix is one line: remove `(pr anchor-push)` from the pricing bullet and replace it with `(self-hosted: pr serve --anchor rfc3161; hosted service: coming soon)`. That removes the false-positive failure and converts honest-but-incomplete into honest-and-clear.
