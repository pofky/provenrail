# Auditor persona review: Ingrid, 2026-08-18

Prepared by: engineer stepping out of persona after a full walkthrough.  
Local server: `http://localhost:8912` (web), `http://localhost:8913` (sink).  
Test artefacts: `scratchpad/ingrid-bundle.json` (6-event demo run, local anchor), `scratchpad/ingrid-anchor-receipt.json`.

---

## Part 1: Ingrid's narrative

### She receives two files

The vendor emails Ingrid a bundle (`bundle.json`) and a link: `http://[sink-host]/v1/anchors/anc_ed0f946040ea4cd08b8cc517bda37c81`. The email says this is "proof of what the agent did, with a trusted timestamp." She is told she can verify it herself.

### Stop 1: The anchor URL

She opens the link in Chrome. The browser renders raw JSON:

```
{"anchor_id":"anc_ed0f946040ea4cd08b8cc517bda37c81","stream_id":"1572c26a...","merkle_root":"db553dafd1149af3c3595f5fb2d1fe4ff5a7557814dd669f897e377e9cec366d","covers_up_to":6,"receipt":{"kind":"local","merkle_root":"db553...","gen_time":"2026-08-18T19:23:16.577007Z","token_b64":null,"signature":"7e15f711...","anchor_pubkey":"b556d34b...","tsa_url":null},"created_at":"2026-08-18T19:23:16.577772Z"}
```

Ingrid can read three things: there is an ID, a timestamp, and many hex strings. She cannot read `"kind":"local"` and know that this means the timestamp came from the machine's own clock, not from an independent time authority. She cannot read `"tsa_url":null` and know that RFC 3161 timestamping was not used. She cannot read `"token_b64":null` and know what is absent. She has no guidance on the page about what to do next, what this proves, or what it does not.

Her first impression: the vendor has given her a page of numbers. She cannot tell if these numbers are meaningful evidence or generated fiction.

**Ingrid's note in her working papers at this point:** "Vendor-supplied anchor URL returns raw JSON. No context. Cannot interpret without specialist assistance. The field 'kind: local' and 'tsa_url: null' suggest the timestamp may not be from an independent authority - will need to confirm."

### Stop 2: The verify page

She navigates to `provenrail.com/verify` (locally: `/verify.html`). The page is clean. The headline says "Verify a record. Trust no one." The sub-heading explains the verifier recomputes everything locally. She is reassured: no install needed, browser-only.

She drops her bundle file. After a moment, the result appears:

> **Verified, with notes** (amber badge)  
> Records are intact and signed; see the advisory notes below.  
> Checks: Hash chain, Signatures, Arrival order  
>
> WARN | tlog_log_key_unknown | anchor 0: no log public key configured  
> WARN | tlog_inclusion_unwitnessed | anchor 0: in the transparency log but not witnessed  
> INFO | summary | 6 records, 1 anchors, 0 heartbeats. Completeness is never attested by this tool.

**Ingrid's reaction, genuine:**

The amber verdict is ambiguous. "Verified, with notes" - are the notes trivial or serious? She reads the WARN lines. "tlog_log_key_unknown" tells her nothing. "anchor 0: no log public key configured" - is that her problem, the vendor's problem, or just how it works? She does not know what a transparency log is or why it matters that the log "is not witnessed."

She reads the INFO line at the bottom: "Completeness is never attested by this tool." She pauses. As an auditor, this is the sentence she was actually looking for an answer to. She would like to know: does this proof mean the agent recorded everything it did, or only that what was recorded was not changed? The answer is the latter - but she found it in the lowest-severity category (INFO), in code-speak ("attested"), after two WARN codes she could not interpret, at the end of the finding list.

She is uncertain whether she missed something. She is also uncertain whether the two WARN codes mean the evidence is weaker than the word "Verified" suggests.

She tries the tampered demo. The result is clear: "Tampering detected" in red with eight FAIL entries. The tamper-detection path is unambiguous. The clean-record path is not.

**Ingrid's note:** "The browser verifier works without install. The tamper case is clear. The clean case shows 'Verified, with notes' - amber, not green. Two WARN codes I cannot interpret. The key limitation (completeness not proved) is in INFO at the bottom in technical language. Need specialist to interpret the WARN codes before I can give this a clean sign-off."

### Stop 3: Reading the site

She reads the pages a vendor audit would normally cover.

**`/compare`**: The table is honest. The note "No overclaiming" is present. The sentence "it never claims to capture everything" is there, but in a FAQ answer buried below the fold. The distinction between a SOC 2 report (statement about a company) and an RFC 3161 timestamp (statement about a record) is clearly drawn and useful. She appreciates the intellectual honesty. The "Regulatory evidence packs (EU AI Act, HIPAA)" row in the feature table gives her pause - HIPAA is a US regulation. No footnote explains what "HIPAA-mapped" means or that it is an evidence mapping, not a certification.

**`/conformance`**: Dense. She reads: "Anyone can claim their records are verifiable. The honest test is whether a second, independent implementation reaches the same conclusion." She understands this is about software testing, not a third-party conformance certification. The language is for developers. She moves on.

**`/security`**: The "Limits" section is well-structured. Three named limits - not a security control on the operator, not legal advice or certification, not a guarantee of truthfulness - are prominent. She notes "not a guarantee of truthfulness: it proves a record was not altered after it was sealed. It cannot prove the agent's inputs to that record were honest." This is useful. The threat model (adversary is the agent, not the sink operator or the vendor) is explained and matches what she would expect.

**`/eu-ai-act`**: This page is the most useful to her professionally. The dates are stated precisely. The "honest framing" note explicitly says "not legal advice and not a compliance certification." The mapping table (Article 12 expectation vs what Provenrail records) is specific. The PLD section is accurate: Recital 46 and the defectiveness presumption. She trusts the regulatory content more than she expected to.

**`/disclaimer`**: Standard. "As is, without warranty." No certification issued. Consult counsel. Lithuanian governing law. Appropriate.

**`/privacy`**: States the software is self-hosted, records never reach the vendor. Supabase hosts authentication data in EU (Frankfurt). Cloudflare handles connections. Lithuanian data controller, GDPR applies, complaint to Lithuanian DPA. This is appropriate for the operator's legal structure.

**`/terms`**: Lithuanian law, no arbitration clause, EU consumer court access preserved, EC ODR platform referenced. Consistent with a Lithuanian sole trader. No class-action waiver (appropriate for EU).

### Stop 4: The completeness question

She looks specifically for an answer to: "Can this prove the agent recorded everything it did?"

She finds it, eventually, in five places:

1. The verify result INFO line: "Completeness is never attested by this tool." (lowest severity, in code-speak)
2. The footer boilerplate on every page: "It never claims completeness." (low-contrast small text)
3. The security page limits section: "Not a guarantee of completeness" (clear, but only if you read that page)
4. The for-agencies page: "A record proves what was recorded. An agent that never calls the SDK at all will not appear in the record." (clearest statement, but on a marketing page aimed at builders)
5. The README: "Completeness: No, never claimed" in the guarantee table.

Her problem is that none of these answers appear at the point of use - the verify result. An auditor who drops a bundle into the verifier, sees "Verified," and does not know to read the security page will carry away a false impression. The word "Verified" unmodified is what most people remember from the page.

**Ingrid's note:** "Completeness limitation is disclosed, but only to someone who looks for it in the right places. The verifier result itself does not lead with it. This is the one gap that, if exploited by a vendor with something to hide, would be undetectable to a user who trusts 'Verified.'"

---

## Part 2: Findings by severity

### CRITICAL

**C1: Anchor receipt serves raw JSON with no auditor-facing context**  
Page: `http://[sink-host]/v1/anchors/[id]`  
File: `src/provenrail/sink/routes/anchors.py` (or equivalent route handler)  
Issue: The public anchor URL - the URL the vendor gives an auditor - returns bare JSON with no explanation of `"kind":"local"` vs `"kind":"rfc3161"`, no statement of what `"tsa_url":null` means for evidentiary value, and no guidance on what to do next. An auditor sees a wall of hex with no context.  
Fix: Add an `Accept: text/html` branch that renders the anchor receipt as a minimal human-readable page with: anchor ID, timestamp, anchor type in plain English (local clock vs RFC 3161 from [TSA name]), Merkle root, records covered, a link to the offline verifier, and a one-paragraph explanation of what this proves and what it does not. The JSON branch (`Accept: application/json`) stays unchanged for programmatic use.  
Legal risk: A vendor can hand this URL to an auditor and say "here is your trusted timestamp." If the anchor type is `local`, that claim is false. The raw JSON gives the auditor no way to detect this without specialist knowledge. Zero real legal risk only if the auditor never encounters a case where a `local` anchor was presented as RFC 3161.

**C2: Completeness limitation not prominent in the verify result**  
Page: `/verify.html`  
File: `web/verify.js` lines 1266-1272, `web/verify.html` result rendering  
Issue: The most important audit caveat - that verification proves records were not altered but not that all actions were recorded - appears only as an INFO-level code at the bottom of the findings list, styled identically to technical summary metadata, using the word "attested" which is a certification term an auditor may misread. The verb "attest" has a specific professional meaning in audit (a formal written assertion); using it to mean "verified by this tool" conflates the two.  
Fix: Render a plain-English "What this verifies and what it does not" summary card at the top of every verify result, before any technical codes:  
- "Confirmed: The records loaded have not been altered, reordered, or deleted since they were signed."  
- "Not confirmed: Whether the agent recorded all its actions. Completeness cannot be proven by any verification tool."  
- "Timestamp certainty: [Based on anchor type: either 'Timing certified by [TSA name] under RFC 3161' or 'Timing from the recording machine's clock only - not independently certified']"  
Replace "Completeness is never attested by this tool" with "Completeness is never verified by this tool."

### HIGH

**H1: WARN codes are opaque to a non-technical auditor**  
Page: `/verify.html` result  
File: `web/verify.js` render function  
Issue: Warning codes "tlog_log_key_unknown" and "tlog_inclusion_unwitnessed" appear with one-line explanations ("anchor 0: no log public key configured", "anchor 0: in the transparency log but not witnessed") that require domain knowledge to interpret. An auditor does not know whether these reduce the evidentiary value of the record (they do - witnessing provides anti-equivocation, and without the log public key the inclusion cannot be verified) or are just configuration gaps on her end.  
Fix: Add a "learn more" inline expansion for each WARN code with a two-sentence plain-English explanation: what the warning means in practice and what the auditor should do about it.  
Example for `tlog_inclusion_unwitnessed`: "The record is registered in a transparency log, but the log entry has not been countersigned by an independent witness. Without a witness cosignature, the log operator could theoretically show different histories to different parties. Ask the vendor whether their transparency log has independent witness cosignatures enabled."

**H2: HIPAA evidence-pack reference without disclaimer on compare page**  
Page: `/compare.html`, feature table row "Regulatory evidence packs (EU AI Act, HIPAA)"  
File: `web/compare.html`  
Issue: HIPAA is a US federal regulation. The operator is a Lithuanian sole trader. Listing HIPAA as a supported regime with no footnote that this is an evidence mapping (not HIPAA certification, not compliance, not a BAA relationship) creates risk that a US-regulated deployer interprets this as a HIPAA compliance claim. The disclaimer at the bottom of the page covers it, but a table row without a footnote is a harder target.  
Fix: Add a footnote marker to the HIPAA row and a note: "Evidence packs map records to framework requirements; they are not certifications and do not constitute compliance with any regulation. HIPAA-regulated entities should consult qualified counsel."

**H3: Verify result "Verified, with notes" verdict is ambiguous**  
Page: `/verify.html` result  
File: `web/verify.js` deriveState function  
Issue: The amber verdict "Verified, with notes" is triggered when there are warnings (warn > 0). An auditor does not know whether "notes" means trivial advisory or material limitation. The two warnings from the local anchor (no log public key, not witnessed) materially reduce the independence of the timestamp and transparency guarantees - these are not trivial. The amber badge correctly signals caution, but the sub-text "Records are intact and signed; see the advisory notes below" does not indicate severity.  
Fix: Differentiate the sub-text based on the type of warning: advisory-only warnings (e.g., RFC 3161 not available on free plan) vs. assurance-reducing warnings (witnessing absent, log key unknown). Use different sub-text for each case.

### MEDIUM

**M1: ISO/IEC 42001 A.6.2.8 cited without context**  
Page: `/eu-ai-act.html`, regime mapping table  
File: `web/eu-ai-act.html` line 187  
Issue: The citation "ISO/IEC 42001 | A.6.2.8 | Tamper-evident event-log storage" is specific enough that an auditor familiar with the standard will look it up. The standard is from 2023 and is an AI Management System framework. A.6.2.8 is cited as "Tamper-evident event-log storage." If this control number is incorrect or the summary is imprecise, a professional auditor will discount the rest of the page. This citation has not been verified against the published standard in this review.  
Recommendation: Verify the A.6.2.8 control text against the published ISO/IEC 42001:2023 standard before this citation is shown to an auditor. Add the full control title in parentheses.

**M2: "Audit trail" in page tag but no definition of what that means**  
File: `web/index.html` og:image:alt  
Issue: The alt text reads "Provenrail: the verifiable audit trail for AI agents." The term "audit trail" has a specific meaning in ISO 27001 and GDPR contexts: a chronological record sufficient to reconstruct events and changes. Provenrail's records can form an audit trail, but only if completeness holds (which the tool explicitly disclaims). Using "audit trail" without qualification may overclaim.  
Fix: Consider "verifiable evidence record" or "tamper-evident agent log" in promotional alt text, or add a qualifying phrase on the relevant page.

**M3: The anchor receipt format gives no signal about timestamp quality**  
File: `scratchpad/ingrid-anchor-receipt.json`, `src/provenrail/sink/` anchor route  
Issue: The receipt JSON has `"kind":"local"` but the verify result WARN text says "no log public key configured" and "in the transparency log but not witnessed." There are thus two separate quality dimensions (local vs RFC 3161 timestamp; unwitnessed transparency log) that an auditor needs to understand. The anchor receipt itself and the anchor URL give no plain-English indication of either dimension.  
Fix: Addressed by C1 (HTML view on anchor URL) and C2 (plain-English summary in verify result).

### LOW

**L1: Conformance page is developer-only**  
Page: `/conformance.html`  
Issue: The page is useful for developers but opaque to an auditor. It does not explain what conformance vectors are or why their existence supports trust in the tool. An auditor reading this page gets no actionable information.  
Fix: Add one introductory paragraph aimed at non-developers: "Two independent software implementations verify every record. They are tested against a shared set of frozen test cases. If the two implementations agree on every test case, the verification logic cannot be quietly changed by the vendor after the fact."

**L2: The verify page does not explain what "6 records" means in context**  
Page: `/verify.html` result summary  
File: `web/verify.js` summary INFO code  
Issue: "6 records, 1 anchors, 0 heartbeats" is reported as an INFO summary. An auditor does not know what a "heartbeat" is or why zero is either good or bad. The record count (6) has no context: was the agent expected to generate 6 records or 600?  
Fix: Either suppress "heartbeats" from the plain-English summary if the count is zero and unexplained, or add a tooltip: "Heartbeats are periodic keepalive records that narrow the time window in which a hostile agent could refuse to log. Zero heartbeats means the session had no keepalives; the unanchored tail window equals the full session length."

---

## Part 3: Regulatory claim verification

| Claim | Source | Verdict |
|---|---|---|
| Art. 50 transparency in force from 2 August 2026 | `/eu-ai-act.html` | Correct. Art. 50 was not deferred by Reg (EU) 2026/1744. |
| Art. 12 record-keeping deferred to 2 December 2027 (standalone Annex III) | `/eu-ai-act.html` | Correct. Reg (EU) 2026/1744 entered into force 27 July 2026 with fixed date 2 Dec 2027. |
| Art. 12 further deferred to 2 August 2028 (Annex I embedded) | `/eu-ai-act.html` | Correct. |
| Reg (EU) 2026/1744 citation | `/eu-ai-act.html` | Correct citation, correct OJ publication date (24 July 2026), correct entry into force (27 July 2026). |
| PLD (EU) 2024/2853, Recital 46, defectiveness presumption | `/eu-ai-act.html`, `/for-agencies.html` | Correct. Recital 46 links defectiveness presumption to missing logging required by Union law. Transposition deadline 9 December 2026 correct. |
| ISO/IEC 42001 A.6.2.8 "Tamper-evident event-log storage" | `/eu-ai-act.html` line 187 | Plausible mapping but unverified against published standard text. Flag for legal review before showing to an auditor. |
| "not legal advice and not a compliance certification" | All pages, footer boilerplate | Consistently stated. No certification is issued or implied in any page reviewed. |
| "We host no agent records" | `/eu-ai-act.html`, `/privacy.html` | Correct for self-hosted plan (the reviewed configuration). Must remain true if any SaaS hosted-sink feature is launched. |

---

## Part 4: Ingrid's conclusions

### (a) Is the evidence meaningful?

**Yes, conditionally.** The tamper-detection mechanism is mathematically sound and the verifier is genuinely independent (open-source, offline, runs in a browser with no install). If a record reaches the sink, it cannot be silently altered, reordered, or deleted without `pr verify` reporting it. An auditor can verify this herself. That is a meaningful property that a plain log file, a vendor report, or a screenshot cannot provide.

The condition is: this bundle used a **local anchor** (`"kind":"local"`, `"tsa_url":null`). The timestamp is the recording machine's clock. The vendor's claim of a "trusted timestamp" is not supported by this receipt - there is no RFC 3161 token from an independent time authority. If the vendor used RFC 3161 (Builder plan), the evidence is meaningfully stronger. If not, the timing cannot be verified against an independent authority.

### (b) What does Ingrid still not trust?

Three things:

1. **Completeness.** The vendor recorded 6 events. Ingrid has no way to know whether the agent performed 6 actions or 60. The vendor could have disabled recording for 54 of them. The tool honestly says this. But "honest disclaimer" and "verifiable assurance" are not the same thing. She cannot sign off on "the agent did only what is shown in this record."

2. **The timestamp.** The anchor is `"kind":"local"`. Without RFC 3161, back-dating within the session cannot be ruled out. The vendor's characterization of this as a "trusted timestamp" is inaccurate for this receipt.

3. **The two WARN codes.** She cannot interpret "tlog_log_key_unknown" or "tlog_inclusion_unwitnessed" without specialist help. The amber "Verified, with notes" verdict correctly signals she should not give a clean sign-off without understanding these warnings, but the page gives her no path to understanding them.

### (c) The one change that would most increase an auditor's confidence

**A plain-English summary card at the top of every verify result, before any technical findings.**

The card should state, in plain prose:

- What is confirmed: The records have not been altered, reordered, or deleted since they were signed.
- What is not confirmed: Whether the agent recorded all its actions. This cannot be proven by any verification tool.
- Timestamp certainty: Either "Timing certified by [TSA name] (RFC 3161, independently verifiable)" or "Timing from the recording machine's clock only. Independent certification of timing requires RFC 3161 anchoring."
- Any assurance-reducing warnings: summarized in one plain-English sentence per issue, not a code name.

This card costs nothing to implement and resolves the two most important auditor questions (completeness, timestamp) at the point of use. Currently an auditor who drops a bundle and sees "Verified" and does not read the INFO line and does not read the security page and does not look at the anchor receipt type walks away with a materially incorrect impression of what was proved.

---

## Part 5: What Ingrid would write in her working papers

**Working paper reference: IT-AI-VENDOR-001**  
**Subject: Evidence review of Provenrail tamper-evident record, [vendor agent], [date]**

**Purpose.** Assess whether the bundle and anchor receipt supplied by [vendor] constitute meaningful, independently verifiable evidence of agent activity for audit reliance.

**Procedures performed.**
1. Opened anchor receipt URL in browser. Received raw JSON. Noted `kind: local` and `tsa_url: null`. Concluded timestamp is machine-clock only, not from an independent time authority. Vendor's description of this as a "trusted timestamp" is not supported.
2. Uploaded bundle to in-browser verifier at provenrail.com/verify. Result: "Verified, with notes" (amber). Hash chain, signatures, and arrival order passed. Two WARN codes ("tlog_log_key_unknown", "tlog_inclusion_unwitnessed") not interpretable without specialist assistance. Summary note states completeness not attested.
3. Reviewed /security, /eu-ai-act, /disclaimer, /privacy, /terms, /compare, /conformance.
4. Noted regulatory claims (Art. 12 dates, PLD Recital 46, Art. 50) are consistent with published regulation as of August 2026.

**Findings.**
- Tamper-detection is independently verifiable. The open-source verifier can be run by any party with a browser. The mathematical mechanism is sound.
- The local anchor means timestamps are machine-clock only. This reduces but does not eliminate the evidentiary value of timing claims.
- Completeness is explicitly not guaranteed. The bundle proves what was recorded was not altered; it does not prove all actions were recorded.
- Two WARN codes in the verify result require specialist interpretation. Obtain written explanation from vendor or engage a cryptography specialist.

**Conclusion.** This evidence is suitable for the limited purpose of **proving that specific records were not altered after they were produced.** It is not suitable, on its own, to support a finding that the agent recorded all its actions, or that timestamps are independently certified. Reliance should be conditioned on: (a) obtaining a vendor statement confirming RFC 3161 anchoring was used for the records in question, and (b) specialist review of the two WARN codes.

**Auditor sign-off:** Pending items (a) and (b) above.

---

*End of report. Files: `/Volumes/T7/Projects/AgenticTools/flightrecorder/docs/persona-auditor-2026-08-18.md`*
