# DISTRIBUTION.md

Standard: `/Volumes/T7/Projects/autopilot/docs/distribution-virality-playbook.md`
Linter: `/Volumes/T7/Projects/autopilot/bin/autopilot-launch-check .`

Companion files: `Marketing/launch-sequence.md` holds the order and the reasoning,
`Marketing/*.txt` hold the paste-ready copy, `STRATEGY.md` holds positioning and
`BUSINESS.md` holds the legal shape that constrains what can be sold at all.

Product: Provenrail
Last updated: 2026-08-21
Stage: launched (product live, distribution not yet executed)

---

## 1. Idea filter (all five, or do not build)

- **One problem, one solution:** when an AI agent does something consequential, nobody
  can prove afterwards what it actually did.
- **Named audience:** freelancers and small agencies who run AI agents against a paying
  client's systems, and the engineer inside a regulated company who has to answer "show
  me what the agent did" before an agent deployment is signed off.
- **Already paying for a worse version:** LangSmith, Langfuse, Braintrust and W&B Weave,
  at roughly $39 to $50 per seat per month, plus the audit-log line item of whatever
  platform they already run. All of them record; none of them produce a record a
  counterparty can verify without trusting the vendor's cloud.
- **AI-unlocked:** the artefact only exists because agents now take consequential
  actions on their own. Nobody needed a signed, third-party-timestamped chain of tool
  calls when a human clicked every button and the human was the accountable party.
- **We use it:** the operator records his own agent runs with it daily, and the CI suite
  is itself a user (949+ tests, two verifier implementations held in lockstep).

## 2. Gotcha feature (exactly one)

- **The 15-second clip:** a real Provenrail record verifying green in a browser with no
  signup and no upload. One character of one hash is changed on screen. The same
  open-source verifier goes red and names the broken check. No narration needed.
- **The feature that makes the clip possible:** `web/verify.js`, the browser verifier,
  and the `?demo` / `?tamper` deep links. Both shipped.
- **The 5-second pitch:** know what your AI agent did, and prove it to anyone.

Every surface leads with this: the homepage (now the second section, above the install
snippet), every launch post, every outreach second message. If a page is competing to
put something else first, that page is wrong.

## 3. Retention feature (different from section 2)

- **Daily-reason feature:** the guardrails. `pr guard install` sits at the agent's tool
  boundary and blocks `rm -rf`, `terraform destroy`, force pushes and key leaks before
  they run, which is a reason to keep it installed on a day when nobody is auditing
  anything.
- **Why this audience opens it daily:** they do not open a dashboard. The tool runs
  inside the loop they already run, and the receipt accrues whether or not they think
  about it. The habit it attaches to is "start the agent", not "check the tool".
- **What churn tells us:** if people install and then remove it, the guardrail is either
  too noisy (blocking things they meant to allow) or too quiet (never firing, so it
  looks like it does nothing). Fix the ruleset, not the marketing. `pr rules --check`
  exists to make the first case visible before it annoys anyone.

## 4. Channel

- **Where this audience already is:** Hacker News (Show HN), r/ClaudeAI and r/AI_Agents,
  Indie Hackers, and for the regulated buyer, LinkedIn validation and CSV groups. For
  the agency buyer, Upwork and Contra profiles, contacted one at a time by hand.
- **Feed trained on the ICP:** no. Nothing is running yet, which is the honest state and
  the single biggest gap in this file.
- **The 10 creators we track:** not yet chosen. Do this during the Show HN week: the ten
  accounts whose posts about agent failures, agent safety or AI compliance get traction,
  captured as handles in `Marketing/` with the date.
- **What their outlier posts have in common:** unknown until the above is done. Do not
  invent an answer here.

## 5. Source material

- **Corpus of real customer language:** does not exist yet. This is the reason the
  outreach in `Marketing/outreach-agencies.txt` asks a question before it pitches: the
  replies are the corpus.
- **Where it comes from:** incident write-ups (the April 2026 production-database
  deletion and the other cases in `web/ai-agent-incidents.html`), r/ClaudeAI threads
  about destructive agent actions, and outreach replies.
- **Refreshed:** weekly during any active launch window, by the operator, into
  `Marketing/`.

## 6. Creative plan

- **Save-earning format:** the threat-model post. "What your agent's log does not prove,
  and what would have to be true for it to hold up." Reference material people bookmark
  rather than a launch announcement they scroll past.
- **Viral variants:** the tamper clip (15 seconds, no words), the incident timeline, and
  the "verify this yourself, here is the link" reply that can be dropped into any thread
  where someone claims logs are enough.
- **Converting variants:** the 60-second first-run: install, `pr demo`, `pr verify`,
  green, then `pr anchor-push` and a receipt with someone else's timestamp on it.
- **Winners to remix:** none yet. First measurement is the Show HN.
- **Ad-library study:** not applicable. No paid acquisition, by choice: there is no
  budget and the unit economics of a $29/mo developer tool do not support cold ads
  before the funnel converts organically.

## 7. Onboarding and paywall

- **Educate:** the homepage hero says what the product knows and what it can prove; the
  tamper widget, directly beneath it, proves the claim before anything is installed.
- **Social proof:** none yet, deliberately omitted. There are no customers, so there are
  no testimonials, and inventing them is out of the question. The substitute is
  verifiable evidence: the live verifier, the public spec, the conformance vectors.
- **Personalize:** `pr rules --check <bundle>` shows which prebuilt guardrails match the
  user's own tool names, which is the one place the product can talk about their setup
  rather than a generic one.
- **Simulate the result:** `pr demo` produces a real signed run in about ten seconds, so
  the first thing a new user sees is their own VERIFIED, not a screenshot of someone
  else's.
- **Paywall placement:** at the end of a successful `pr verify` on a locally-anchored
  run. That is the moment of maximum curiosity, because the verifier has just proved the
  record is intact and then says plainly that it cannot prove when it happened. Shipped
  2026-08-21 in `src/provenrail/verifier/verify.py`.
- **Price and trial:** Free forever (50k events/month) with one independent RFC 3161
  timestamp, ever. Builder $29/month for unlimited anchoring. Team $99/month for seats,
  SSO, exports and evidence packs. No time-limited trial: a trial that expires teaches
  nothing about a product whose value is measured in years of retained evidence. The one
  free anchor is the trial, and it is the only part of the product a self-hoster cannot
  reproduce alone.

Note on currency: prices display in USD because the Polar products are USD and Polar
prices are immutable. Moving to EUR means creating new Polar products and migrating any
existing subscribers; do it before the first customer, or not until there is a reason.

## 8. Numbers

Targets set 2026-08-21, from a standing start of ~92 PyPI downloads/month, zero
customers and zero inbound.

| Metric | Target | Actual | Read when |
|--------|--------|--------|-----------|
| First paying customer | 1 by 2026-09-21 | | 30 days after launch week |
| MRR | $200 by 2026-10-21 | | 60 days |
| MRR | $500 by 2026-11-21 | | 90 days |
| Free anchors claimed | 25 in the first 30 days | | weekly |
| Free anchor to paid conversion | >= 10% | | once 25 anchors are claimed |
| Unprompted inbound (an email nobody was asked for) | 1 by 2026-11-21 | | 90 days |
| Show HN | 20+ points, front page 2h+ | | launch day |

The free-anchor claim rate is the leading indicator that matters most: it separates "no
traffic" from "traffic that does not want this", and those two failures have opposite
fixes. `cta_trial_key` is recorded by the analytics beacon for exactly this reason.

## 9. Launch-window revenue play

- **Cohorts:** visitors who claimed the free anchor and did not upgrade (the only warm
  cohort that will exist), checkout-intent drop-offs from `/account?plan=builder`, and
  Show HN commenters who asked a real question.
- **Sending stack:** Polar for billing, Supabase Auth for the magic link. No email
  marketing tool is connected, and none should be added before there is a list worth
  sending to.
- **Review queue:** every outbound message is written by hand into `Marketing/` before it
  is sent. There is no automated sending path, on purpose.
- **Urgency:** there is no real deadline, so there is no urgency line. The EU AI Act
  Article 12 logging obligation moved to 2 December 2027 under Regulation (EU) 2026/1744,
  and pretending otherwise is both dishonest and checkable. Article 50 transparency
  (2 August 2026) and the revised Product Liability Directive (9 December 2026) did not
  move, and the PLD is the honest hook: from that date a defective software product,
  agents included, carries strict liability, and the defence is evidence of what the
  system actually did.

## 10. Boundaries confirmed

- [x] No bought followers or engagement
- [x] No scraped-contact cold email or DM outbound (outreach is one-at-a-time, on
      platforms where a message is within the terms of service, per
      `Marketing/outreach-agencies.txt`)
- [x] No fabricated reviews, testimonials or social proof (there are none, and the site
      says so rather than filling the space)
- [x] No impersonation, no unevidenced "as seen in"
- [x] Every channel used is within its own terms of service
