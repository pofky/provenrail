# Repositioning research, 2026-09-07

Question asked: the product is live and nobody uses it, so what should it become?

This document separates three things that keep getting mixed together: what the numbers
actually say, what the market actually pays for, and which of Provenrail's parts are
reusable in a different shape. It ends with three directions, a recommendation, and a
test that costs days rather than months.

---

## 1. What the numbers say, measured today

Pulled from production, not estimated.

| Signal | Value | Reading |
|---|---|---|
| Pageviews, all time | 2,534 | Since 2026-07-30 |
| Pageviews since 2026-08-22 | 115 in 17 days | ~7/day |
| Of those, with a referrer | 14 of 115 | Google 8, ChatGPT 3, Bing 2, Brave 1 |
| Signed-up profiles | 4 | Operator's own, including the deleted test |
| Anchor accounts | 1 | Operator's |
| External anchors | 5 | Operator's |
| npm `provenrail`, last 30d | 65 | Mirror and CI noise |
| PyPI `provenrail`, daily | 1 to 173, spiky | Release-day mirror pulls, not humans |

Top paths since 22 Aug: `/` 64, `/verify` 10, `/pricing` 9, `/docs` 6, `/start` 5,
`/account` 4. Countries: US 60, IN 15, CA 7, DE 7.

**The honest reading: this is not a rejected product, it is an unshown one.** Eleven
referred visits in seventeen days is what a site gets when nothing links to it. The
launch copy in `Marketing/` has existed since 2026-08-05 and has never been posted.
No repositioning decided on this data is decided on data.

That said, three structural facts do argue against the current concept independently of
traffic. They are in section 2.

---

## 2. Three reasons the current concept is hard to sell, regardless of reach

**2.1 The buyer needs the exact thing the operator has ruled out.**
"Prove what your AI agent did" is bought by a compliance or risk function inside a
company. That buyer wants a hosted system of record, a DPA, a vendor security review and
ideally SOC 2. `BUSINESS.md` and `docs/cost-to-execute-2026-08-18.md` correctly refuse
all of it: a Lithuanian `individuali veikla` with no liability shield cannot become a
GDPR processor for other people's agent records. What remains sellable, anchor-only with
a customer-hosted sink, moves the work to the customer and charges for the one component
they do not feel. That is a real offer, and it is the hardest possible first sale.

**2.2 The deadline that supplied the urgency has moved.**
EU AI Act Article 12 logging is now 2 Dec 2027 under Regulation (EU) 2026/1744. Public
write-ups still say 2 Aug 2026 and are wrong. Article 50 transparency and the PLD did
not move, but neither of those requires a tamper-evident agent log. **Nobody currently
has a dated obligation that Provenrail satisfies.** The compliance framing has fifteen
months of no pressure behind it.

**2.3 The category next door is funded and enterprise-sold.**
Agentic AI security raised roughly $3.6B across 2026 (Oasis $120M, Noma $100M, AIR $50M
seed). Agent observability is a commodity price war: Langfuse free self-hosted, Braintrust
1M spans free, LangSmith $39/seat, Arize Pro $50, Logfire $2 per million spans. Provenrail
should not be within a hundred miles of a head-on comparison with either.

**Underneath all three: the product is insurance.** Its value lands after something goes
wrong, and for the visitor nothing has gone wrong yet. Insurance from an unknown solo
vendor is the hardest category there is. Whatever the shift is, it has to move the value
to *before* the incident and to *daily*.

---

## 3. What is actually built and reusable

Not the pitch, the parts. Any new direction should reuse most of this or it is a rewrite,
not a repositioning.

- **A policy engine that runs at the tool boundary**, plus a Claude Code plugin with
  PreToolUse hooks: `src/provenrail/policy.py`, `rulesets.py`, `guard.py`,
  `plugins/provenrail-guard/`. Blocks, asks, and limits. Blast-radius caps with
  cross-process state.
- **A spend ledger with budgets**: `spend.py`, `easy.py` `_validate_budgets`. Per agent,
  today / 7d / 30d / lifetime, atomic and locked.
- **Signed hash-chained records** with a second independent server receipt chain, and
  an offline verifier in two languages held in lockstep (`verifier/verify.py`,
  `web/verify.js`), frozen in `SPEC.md`, plus RFC 3161 anchoring against FreeTSA and OTS.
- **Replay and diff between two runs**: `replay.py`.
- **A live, hosted, free-tier anchor service** that costs nothing to run and never
  receives a record.
- **951 tests, ruff clean, conformance vectors, deno check in CI.**

The crypto is the least differentiating part of this list commercially and the most
expensive to rebuild. It should stay, as the thing that makes a claim unforgeable, but it
should stop being the first sentence.

---

## 4. Where demand actually is, with evidence

**4.1 The Claude Code plugin channel is a real, ungated distribution surface.**
46% of 15,000 surveyed developers named Claude Code their favourite coding tool in 2026,
ahead of Copilot and Cursor. The plugin marketplace passed 200 entries; Superpowers has
752,000+ installs, Anthropic's own Frontend Design roughly 277,000. Installs are free and
one command. `provenrail-guard` already sits in that channel, has never been promoted,
and taxes the user with `pip install provenrail` plus `pr quickstart` plus
`pr guard install` before it does anything.

**4.2 The loudest pain in that audience is scope creep and destruction, not audit.**
The August 2026 r/ClaudeAI thread that travelled furthest describes a "fix my sitemap"
request that became a full site rebuild, with the only backup of the original files
deleted in the process. The other recurring cases: a 202GB archive removed by a misfired
shell command in a directory the model had been told not to touch; approval fatigue under
`--dangerously-skip-permissions` where repeated "yes" became reflex. This is a daily,
pre-incident, felt-by-hundreds-of-thousands pain. It is the pain `guard` already solves.

**4.3 Guardrail hooks alone are commoditised and free.**
Public gists and a dozen blog posts ship "block rm -rf in a PreToolUse hook." Nobody will
pay for the block. It is a wedge, never the invoice.

**4.4 Cost is a budget line with a real number attached.**
Anthropic's own figures: about $13 per developer per active day, $150 to $250 per
developer per month. Gartner puts heavy agentic coding at $2,000 to $5,000 per developer
per month. Copilot billing changes took some teams from $29 to $750. A finance owner
exists for this number, which is more than can be said for the audit story.

**4.5 AI code attribution is entering procurement, and today it is self-asserted.**
CISA's 2026 SBOM guidance adds hash requirements and AI coverage. AI-BOM language is
appearing in vendor contracts. The practice being recommended everywhere is a
`Co-authored-by:` or `Generated-by:` git trailer, or a git note: **entirely
self-asserted, trivially forged, and written by the same agent it describes.** Exceeds
Ink is the closest commercial product (line-level authorship as git notes, on-machine).
FOSSA sells the adjacent licensing angle. The category is early and nobody in it is
selling *verifiable* attribution, which is precisely and only what Provenrail already is.

---

## 5. Three directions

### Direction A. The leash. Free guard plugin as the front door.

**The change.** `provenrail-guard` becomes zero-install: the hook ships as a
self-contained script with no Python package, no `quickstart`, no sink, no account. It
blocks and asks on the first run after `/plugin install`. Recording is off by default and
one flag away. The homepage first sentence becomes the incident, not the proof.

**Who pays.** Nobody, at first, and that is the point. Paid appears one layer up: a shared
policy a team can pin across repos, and a receipt of what was blocked.

**Why us.** The engine, the rulesets, the limits and the plugin manifest already exist and
are tested. The work is subtraction.

**First proof.** Installs. If a zero-friction, free, genuinely useful plugin promoted in
the places that audience reads cannot cross a few hundred installs in two weeks, the
distribution thesis is wrong and no amount of repositioning fixes it.

**Kill criterion.** Under 100 installs in 30 days with the posts actually made.

**Risk.** High reach, low willingness to pay. On its own this is a portfolio piece.

### Direction B. Verifiable AI code attribution. The money.

**The change.** The record stops being "what the agent did" in the abstract and becomes
"which lines of this repository an agent wrote, with which model, under which prompt,
which a human reviewed, and when," emitted as an AI-BOM artefact plus a signed,
third-party-timestamped chain. Runs in the customer's CI. We never receive the code, only
optionally a Merkle root, which keeps the entire liability position from section 2.1
intact.

**Who pays.** The software vendor whose customer's procurement now asks for AI
disclosure; the agency delivering code to an enterprise client; the company preparing for
due diligence or an IP question. A tool licence and a CI seat, not a data-processing
relationship.

**Why us.** Every competing approach is self-asserted metadata. A git trailer proves
nothing, and the buyer's counterparty knows it. "The only AI attribution your customer's
lawyer cannot dismiss as something you typed yourself" is a sentence no incumbent can
say, because none of them have a signed chain or a trusted timestamp. Provenrail has both,
frozen in a spec, with two independent verifiers.

**First proof.** Ten conversations with people who ship software to enterprise customers,
asking whether an AI disclosure clause has appeared in a contract yet. If the clause is
not real, the sale is not real.

**Kill criterion.** Ten conversations, zero contracts that mention AI authorship.

**Risk.** Contested (Exceeds Ink), and the trigger may be a year early, like 2.2.

### Direction C. The budget and blast-radius cap.

**The change.** `pr` becomes the thing that stops an agent at a dollar figure and a blast
radius, with the receipt as the audit byproduct. "Your agent cannot spend more than $40
today and cannot touch more than 30 files without asking."

**Who pays.** The engineering manager who owns the $2,000/dev/month line.

**Why us.** `spend.py`, budgets and limit rules are already built and locked.

**Risk.** Vendors are shipping native spend controls, and community forecasters like
cc-budget are free. Thin and likely to be absorbed. **Recommend as a feature of A, not a
product.**

---

## 6. Recommendation

**Do A and B together, in that order, as one product with two surfaces. Fold C into A.**

A is the audience. B is the invoice. They share the engine, the chain and the verifier,
and the story connecting them is one sentence: *the tool that keeps your coding agent
inside its lane, and turns the record of that into the AI attribution your customer's
procurement is starting to ask for.*

What that means concretely for the current site and offer:

- The compliance-first homepage is retired. "Know what your AI agent did, prove it to
  anyone" is a second-page sentence, not a first one, because the visitor has not yet had
  the incident that makes it matter.
- The EU AI Act pages stay but stop being load-bearing. The date moved; do not build the
  funnel on it again.
- The anchor service does not change and does not need to. It becomes the thing that makes
  B's artefact unforgeable, which is a better job than being the paid tier of an audit
  product nobody has asked for.
- The pricing page's current shape, selling independent anchoring to a self-hoster,
  survives as the enterprise tail, not the front door.

**Before any of this is built, run the launch that has never been run.** Seven days,
the existing `Marketing/*.txt`, the plugin as it stands. It costs nothing, and it is the
only way to tell a concept problem from a reach problem. A repositioning launched into the
same silence produces the same 7 pageviews a day and the same absence of information.

---

## 7. What would change this conclusion

- If the seven-day launch converts a paying customer for the current offer, section 2.1 is
  wrong and this document is premature.
- If ten conversations find real AI-disclosure clauses in real contracts, B moves ahead of
  A and the guard becomes the marketing.
- If Anthropic ships native policy files that cover the destructive-command cases, A's wedge
  closes and only B remains.

## Sources

Traffic and package figures: production Supabase (`pageviews`, `profiles`,
`anchor_accounts`, `external_anchors`), pypistats, npm registry, pulled 2026-09-07.

- https://www.langchain.com/resources/llm-observability-tools
- https://www.braintrust.dev/articles/best-ai-observability-tools-2026
- https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/
- https://www.geekwire.com/2026/codeintegrity-raises-4-8m-to-put-permanent-guardrails-on-unpredictable-ai-agents/
- https://buildtolaunch.substack.com/p/best-claude-code-plugins-tested-review
- https://www.buildthisnow.com/blog/guide/mechanics/best-claude-code-plugins-2026
- https://www.explainx.ai/blog/opus-5-over-engineering-reddit-reaction-august-2026
- https://www.aiqnahub.com/claude-code-lost-my-code/
- https://gist.github.com/sgasser/efeb186bad7e68c146d6692ec05c1a57
- https://www.morphllm.com/ai-coding-costs
- https://www.finout.io/blog/claude-code-pricing-2026
- https://devops.com/cisas-2026-sbom-guidance-adds-hash-requirements-and-ai-coverage/
- https://talkthinkdo.com/guides/ai-and-code/ai-code-attribution-enterprise-procurement/
- https://blog.exceeds.ai/analyze-git-commits-ai-code/
- https://crashoverride.com/resources/knowledge-base/code-ownership/attributing-ai-commits-git
- https://fossa.com/solutions/ai-coding-guardrails/
- https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/
