# Provenrail: Competitive Study and Positioning Analysis

Status date: 2026-08-18. Author: competitive sweep for Provenrail / flightrecorder.
Sources: live web research conducted 2026-08-18, product docs, regulatory texts. Every
external claim is cited. Unverified claims are flagged.

---

## Part 1. Competitive Map

### Category A: LLM / Agent Observability (the daily-use camp)

This is the dominant market segment. LLM observability is estimated at $2.69B in 2026,
growing to $9.26B by 2030 at 36% CAGR.
Source: https://blog.aimactgrow.com/high-llm-observability-and-analysis-platforms-in-2026-langfuse-langsmith-braintrust-arize-and-extra-in-contrast/

**Langfuse** (now part of ClickHouse)
- What it does: open-source LLM tracing, prompt versioning, eval pipelines, dataset
  management, cost analytics, user feedback. Self-hostable; cloud managed.
- Pricing: free (OSS self-host); cloud Pro ~$249/month; Enterprise custom.
- Who buys: engineering teams building on any LLM stack; open-source community.
- Acquisition: ClickHouse acquired Langfuse January 2026 in a deal accompanying a $400M
  Series D that valued ClickHouse at $15B. MIT license stays intact; self-hosting remains
  first class. Source: https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability
- Tamper evidence: none. No hash chain, no signed records, no independent verifier.
  Authenticity requires trusting ClickHouse cloud.
- Momentum: 2,000+ paying customers, trusted by 19 of the Fortune 50, 63 of the Fortune 500
  at acquisition. Source: https://www.infoworld.com/article/4118621/clickhouse-buys-langfuse-as-data-platforms-race-to-own-the-ai-feedback-loop.html

**LangSmith** (LangChain)
- What it does: tracing tightly integrated with LangChain / LangGraph; agent graph
  visualization, annotation queues, dataset evals, human feedback.
- Pricing: free tier; Plus $39/seat/month; Enterprise custom.
  Source: https://www.respan.ai/market-map/compare/braintrust-vs-langsmith
- Who buys: teams that already live in the LangChain ecosystem.
- Tamper evidence: none.

**Braintrust**
- What it does: eval-first observability. Eval scores native to the trace view, not bolted on.
  Strong dataset and LLM-as-judge pipeline.
- Pricing: free (1GB + 10K scores); Pro $249/month.
  Source: https://www.braintrust.dev/articles/langfuse-alternatives-2026
- Who buys: teams where evaluation quality is the primary concern.
- Tamper evidence: none.

**Arize Phoenix**
- What it does: agent-native eval and observability, OTel + OpenInference, strong eval
  rigor. Elastic License 2.0 (not permissive).
- Pricing: open source / self-host free; managed Arize ~$60K/yr median.
  Source: https://www.confident-ai.com/knowledge-base/compare/top-7-llm-observability-tools
- Who buys: teams prioritizing eval rigor; Arize enterprise for regulated orgs.
- Tamper evidence: none.

**W&B Weave** (Weights and Biases)
- What it does: model and function call tracing, LLM-as-judge, production monitoring,
  integrated with W&B experiment tracking.
- Pricing: free to start; for existing W&B customers $50K-$500K/yr.
  Source: https://aisuperior.com/datadog-llm-observability-cost/
- Who buys: ML teams already in the W&B ecosystem.
- Tamper evidence: none.

**Helicone**
- Status: acquired by Mintlify in March 2026; effectively in maintenance mode.
  Source: https://openobserve.ai/blog/llm-observability-tools/
- Tamper evidence: none.

**Traceloop / OpenLLMetry**
- What it does: Apache 2.0 OTel-native SDK; bring your own backend. Managed platform with
  free and paid tiers. Source: https://aicalculatorpro.com/ai-stack/llm-observability/traceloop/
- Tamper evidence: none published.

**HoneyHive**
- What it does: SOC 2, HIPAA, GDPR compliance claimed; enterprise deployment options;
  evaluation pipelines.
- Pricing: $50K+/yr; longer sales cycles.
  Source: https://en.ai-pedias.com/blog/ai-llm-observability-monitoring-2026
- Who buys: regulated enterprise (financial services, healthcare).
- Tamper evidence: SOC 2 certifies the vendor's process, not that individual records are
  unalterable.

**Datadog LLM Observability**
- What it does: LLM spans inside the Datadog platform; agent tracing, prompt tracking,
  anomaly detection.
- Pricing: free 40K LLM spans/month (15-day retention); Pro $160/month for 100K spans.
  Source: https://ecorpit.com/datadog-llm-observability-pricing-cap-costs-2026/
- Who buys: teams already on Datadog for infrastructure monitoring.
- Tamper evidence: none. Datadog's tamper-evident logging claim is a storage-layer
  marketing statement, not an entry-level cryptographic proof. Verified 2026-08-18: no
  published spec, no independent verifier.

**Logfire** (Pydantic)
- What it does: OTel-native, exports to any compatible backend; Python-first.
- Pricing: tiered, open export. Source: https://softcery.com/lab/top-8-observability-platforms-for-ai-agents-in-2025
- Tamper evidence: none.

**Galileo** (acquired by Cisco)
- What it does: LLM evaluation and hallucination detection; now part of Cisco's AI safety
  stack. Source: https://www.confident-ai.com/knowledge-base/compare/top-7-llm-observability-tools
- Tamper evidence: uses "cryptographically signed" in marketing; no published spec or
  verifier found as of 2026-08-18.

**Summary for Category A:** No player in this category produces an independently
verifiable record that survives an adversarial third party. Their compliance certs
(SOC 2, HIPAA) certify the vendor's process, not the immutability of any given run.
Authenticity requires trusting their cloud.

---

### Category B: AI Governance / Risk / Compliance Platforms

**Credo AI**
- What it does: policy-and-program specialist; translates regulation into control sets and
  audit evidence; EU AI Act and ISO 42001 deep coverage.
- Pricing: not published; enterprise $50K-$500K+/yr typical.
  Source: https://aicompliancevendors.com/vendors/credo-ai
- Who buys: enterprise compliance and risk teams; regulated industries.
- Placement: Gartner Magic Quadrant for AI Governance (Visionary), June 16, 2026.
  Source: https://www.kosmoy.com/resources/blog/credo-ai-vs-holistic-ai/
- Tamper evidence: none at the run level. Governance documentation layer only.

**Holistic AI**
- What it does: grew out of algorithm-audit work; in 2026 moved into runtime enforcement.
  EU AI Act, ISO 42001, bias assessment.
- Pricing: enterprise, not published.
- Placement: Gartner Magic Quadrant for AI Governance (Challenger), June 2026.
  Source: https://eveaicore.com/blog/credo-ai-vs-holistic-ai
- Tamper evidence: none at the run level.

**Trustible**
- What it does: AI governance workflow, policy templates, risk catalogues.
- Pricing: enterprise, not published.
- Tamper evidence: none found.

**Vanta / Drata AI modules**
- What they do: extend existing compliance automation (SOC 2, ISO 27001) to cover AI
  inventory and risk classification.
- Tamper evidence: process-level certification. No run-level cryptographic integrity.

**Summary for Category B:** These platforms are procurement-questionnaire and policy
tools. They document what an organization says it does with AI; they do not produce
independently verifiable evidence of what any individual run actually did. They are
buyers of Provenrail's evidence layer, not competitors for it.

---

### Category C: Software Supply Chain Provenance (cryptographic, not agent-native)

**Sigstore / Rekor** (Google, Linux Foundation)
- What it does: keyless code-signing; Rekor is a public append-only transparency log for
  software artifacts. RFC 6962 Merkle proofs.
- Pricing: free / open source.
- Who buys: DevSecOps, CNCF ecosystem, open-source maintainers.
- Agent-native: no. Designed for software artifacts (binaries, container images), not
  AI agent run events. Could theoretically anchor agent records but there is no SDK or
  schema for it.
- Relevance: Provenrail's tlog format is C2SP-compatible; cross-anchoring into Rekor is
  on the roadmap.
  Source: https://github.com/sigstore/rekor

**in-toto / Witness (TestifySec)**
- What it does: supply-chain attestation framework; Witness automates, normalizes, and
  verifies artifact provenance across a build pipeline. Donated from TestifySec to the
  CNCF in-toto ecosystem.
- Pricing: open source.
- Agent-native: no. The 2026 push from TestifySec is applying SLSA principles to AI
  model training pipelines (training provenance), not to runtime agent run events.
  Source: https://cloudsmith.com/blog/the-2026-guide-to-software-supply-chain-security-from-static-sboms-to-agentic-governance
- Relevance: adjacent; not a runtime competitor. Provenrail could position as the
  runtime complement to SLSA training provenance.

**SLSA** (Supply chain Levels for Software Artifacts)
- What it does: graduated assurance framework for build provenance. SLSA levels 1-4.
- Agent-native: no. Covers model development lineage, not inference-time decisions.

**Chainguard / GitHub Attestations**
- What they do: secure container supply chains; GitHub now supports in-toto attestations
  for CI artifacts.
- Agent-native: no.

**immudb (Codenotary)** -- DIRECT COMPETITOR
- What it does: open-source append-only tamper-proof database with Merkle inclusion
  proofs; immutable audit logging built into immudb 1.11 (May 2026).
  Source: https://www.businesswire.com/news/home/20260505298955/en/Open-Source-Tamper-Proof-Database-Adds-Immutable-Audit-Logging-and-Expands-PostgreSQL-Compatibility
- Agent-native: via AgentMon (see Category D). immudb itself is a general database; the
  agent layer is a separate product.
- Tamper evidence: genuine per-entry Merkle proofs. No RFC 3161 managed anchoring in a
  turnkey product. No agent-as-adversary threat model; the audited agent shares the
  auditor's trust boundary.

**SCITT** (Supply Chain Integrity, Transparency, and Trust -- IETF)
- What it is: emerging IETF standard for a Transparency Service that accepts COSE receipts
  from multiple signers. Provenrail is positioned as the first AI-agent-native SCITT
  Transparency Service.
- Relevance: defining the standard before it is written is the core moat move.

---

### Category D: Agent-Specific Audit / Security Startups (new entrants, last 12 months)

**Codenotary AgentMon 3** (July 2026) -- DIRECT COMPETITOR
- What it does: adaptive runtime security policies for AI agents; monitors MCP servers,
  tool access, data sharing; all runtime decisions recorded in immudb tamper-proof ledger.
  Learning system that evolves policies from observed behavior. Now on AWS Marketplace.
  Observes 5M+ agent interactions/day across enterprise customers.
  Source: https://www.businesswire.com/news/home/20260707200686/en/Codenotary-Launches-AgentMon-3-with-Adaptive-Runtime-Security-Policies-Expands-Availability-on-AWS-Marketplace
- Pricing: enterprise; not published.
- Who buys: enterprise security teams; defense; retail.
- Tamper evidence: immudb ledger provides genuine entry-level Merkle proofs. No RFC 3161
  anchoring in the managed product. No client-side signing independent of the vendor.
  Standalone independent verifier: not found.
- Threat: most complete crypto audit competitor; enterprise distribution through AWS
  Marketplace is a significant channel advantage. No agent-as-adversary model.

**WitnessAI** ($58M raised, January 2026)
- What it does: enterprise AI security and agent governance; observability for which agents
  are active, which MCP servers they access, what data they share; behavioral governance.
- Funding: $58M led by Sound Ventures (Ashton Kutcher); investors include Qualcomm Ventures,
  Samsung Ventures, Forgepoint. Reported 500% ARR growth.
  Source: https://witness.ai/resources/witnessai-raises-58-million-for-global-expansion-and-announces-new-ways-to-secure-ai-agents/
- Who buys: global enterprise (financial services, technology).
- Tamper evidence: none found. Focus is behavioral discovery and governance, not
  cryptographic audit.
- Threat: well-funded; could buy or build crypto audit if a regulated customer demands it.
  Potential acquirer of a crypto-native team.

**Geordie AI** ($30M Series A, May 2026)
- What it does: security and governance for AI agents; gives security and IT teams
  continuous insight into agent behavior, decision-making, and tool usage. London-based.
  Source: https://fortune.com/2026/05/28/geordie-security-governance-ai-agents/
- Funding: $30M Series A led by Balderton Capital.
  Source: https://www.crunchbase.com/organization/geordie-ai
- Who buys: enterprise security teams.
- Tamper evidence: none found. Behavioral observability, not cryptographic audit.

**Microsoft Agent Governance Toolkit** (open source, April 2026)
- What it does: runtime security governance for AI agents; policy enforcement, zero-trust
  identity, execution sandboxing, regulatory framework mapping (EU AI Act, HIPAA, SOC 2),
  OWASP Agentic AI Top 10 evidence collection. MIT license, 9.5K tests.
  Source: https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/
- Tamper evidence: "tamper-evident audit trails out of the box -- every governance decision
  logged with SHA-256 hash chains." However: the audit log is in-process with the agent
  (same trust boundary). No off-box server receipt chain. No RFC 3161. No standalone
  independent verifier. No agent-as-adversary model.
  Source: https://microsoft.github.io/agent-governance-toolkit/tutorials/04-audit-and-compliance/
- Threat: brand authority; wins enterprise procurement by default on Azure. Does not
  satisfy independent verifiability. For organizations that trust Microsoft, it is
  sufficient for checkbox compliance.

**Asqav** (solo dev, MIT, April 2026)
- What it does: ML-DSA-65 + hash chain; claims per-entry RFC 3161 timestamping.
- State: prototype / solo dev; no managed service; no server receipt chain; no independent
  verifier; no business model found.

**nono.sh**
- What it does: Merkle + DSSE, kernel-isolated capture (agent cannot tamper with the
  recorder); local only; OSS.
- Strongest threat model: kernel separation is the correct response to in-process
  recording. Acknowledged gap: no external anchor; local only.

**agentstamp**, **EPI Recorder**, **TierZero**
- State: prototypes or narrow scope. None have server receipt chains, RFC 3161 anchoring,
  or managed services at the scale that would represent a commercial threat.

---

## Part 2. Where Provenrail Actually Wins and Loses

### Where the moat is real

**Independent verification without trusting the vendor.**
Every observability tool in Category A requires its cloud to attest authenticity. Provenrail's
offline verifier lets an auditor, regulator, or counterparty check a bundle with no dependency
on Provenrail. This is not a feature Camp A can add in one sprint; it requires re-architecting
the trust model of the entire product. The dual-chain design (client signs, server receipts
independently) means neither party alone can rewrite history. This is architecturally unique
among managed products as of 2026-08-18.

**Agent-as-adversary threat model.**
Camp A assumes the agent is honest and the sink is the authority. Provenrail's design assumes
the agent may tamper with its own record. This is the correct model for high-stakes deployments.
No funded competitor (WitnessAI, Geordie, Codenotary AgentMon) applies it; only nono.sh (kernel
isolation, local-only) has a comparable threat model.

**EU AI Act Art. 12 / ISO 42001 evidence layer.**
The Art. 12 logging obligation (deferred to December 2, 2027 for Annex III systems) requires
retained event records. Harmonized standards are not yet published. Provenrail's pr report
--regime eu-ai-act generates a mapped attestation; no competitor produces a standalone,
independently verifiable regime-attestation artifact as of 2026-08-18.

**SCITT alignment.**
Provenrail is positioned as the first AI-agent-native SCITT Transparency Service. If the SCITT
format becomes the auditor standard (plausible given RFC-imminent status), early movers who
shaped the format have a structural advantage.

**Accumulated anchoring history.**
A competitor entering the market in 2027 cannot manufacture Provenrail's Bitcoin and Rekor
anchor history from 2026. Every epoch that gets anchored and witnessed increases the cost of
catching up. This is the one compounding moat that is genuinely hard to replicate.

### Where the moat is thin or illusory

**The receipt chain alone.**
The independent server receipt chain is ~200 lines of code. A funded competitor (Datadog,
Langfuse/ClickHouse, Codenotary) copies it in a sprint once they see the idea. It is a feature,
not a barrier. Codenotary AgentMon already has a comparable capability through immudb.

**Temporary counter-positioning.**
"Trust no one, not even us" is a real wedge today. The window before a major observability
incumbent ships a "tamper-evident logging" checkbox (RFC 3161 + a hash chain in their own cloud)
is estimated at 12-18 months. The checkbox will satisfy 80% of buyers.

**No daily-use surface.**
Category A wins the daily engineering habit. Provenrail has no persistent run explorer that
engineers open between audits. No cost/token analytics surfaced through a self-serve cloud.
No alerting integrated into Slack or PagerDuty. Without the daily habit there is no word-of-
mouth, no virality, no bottom-up expansion. According to STRATEGY.md this has been shipped
as Tier 0 but is not publicly accessible in a managed cloud product yet.

**Enterprise procurement blockers.**
No publicly available managed cloud hosting means every enterprise buyer must self-host or
wait. No RBAC, SSO, or SIEM push connectors visible in the public product as of 2026-08-18
(STRATEGY.md says Tier 2 is shipped in code; the managed product and billing surface are not
publicly live). This is the hardest blocker for any B2B deal.

**Solo founder, no LLC, no brand.**
Zero distribution (92 PyPI downloads/month per memory note). WitnessAI has $58M, Geordie has
$30M, Codenotary has enterprise contracts and AWS Marketplace. Provenrail has none of those.
Brand matters when incumbents add the checkbox; being first is only durable if buyers know
about it.

**Verifier Python-only for most users.**
The JS verifier exists but RFC 3161 CMS validation is not in the browser. A Go verifier does
not exist yet. "Verify it yourself" is weakened when most auditors cannot run Python.

---

## Part 3. The Buyer

### ICP 1: Freelancers and agencies delivering AI agent work to EU clients
- **Trigger event:** EU AI Act Art. 50 (in force August 2, 2026) creates pressure; EU
  clients insert AI Act compliance clauses into procurement agreements.
  Source: https://www.secondtalent.com/resources/eu-ai-act-vendor-compliance/
- **Pain:** "How do I prove to a client what my agent actually did?" A signed receipt that
  the client can verify without trusting the contractor is the exact answer.
- **Conversion speed:** fast; no procurement cycle; can buy on a credit card.
- **Reachability:** Indie Hackers, Twitter/X, LangChain Discord, r/MachineLearning,
  r/LocalLLaMA, Claude Code plugin marketplace.
- **Revenue ceiling:** low ($29-$99/month). Volume play.
- **Rank: 1 (fastest to first dollar).**

### ICP 2: Developer / startup building an AI-powered product for a regulated vertical
- **Trigger event:** a paying enterprise customer asks for an audit trail, or a procurement
  questionnaire asks about AI governance. First enterprise deal creates urgency.
- **Pain:** needs to produce evidence for one specific customer fast without building a
  compliance function.
- **Conversion speed:** medium; one decision maker; can sign in a day if the pain is acute.
- **Reachability:** LangChain / LangGraph Discord, Y Combinator circles, Hacker News,
  AI engineer conferences.
- **Revenue ceiling:** medium ($99-$500/month; potential commercial license).
- **Rank: 2.**

### ICP 3: Enterprise compliance/security team at an Annex III high-risk AI deployer
- **Trigger event:** December 2, 2027 (Art. 12 enforcement); but procurement prep starts
  12-18 months ahead, meaning NOW (Q3 2026) is the planning window.
- **Pain:** needs documented, independently verifiable event logs for a high-risk AI system.
  A generic SaaS that requires trusting the vendor is not sufficient for a serious audit.
- **Conversion speed:** slow (6-18 months enterprise sales cycle); but contract values are
  $50K-$500K/yr.
- **Reachability:** CISOs, DPOs, AI governance leads; via Big-4 audit firms, law firms
  advising on EU AI Act, CISO forums, RSA / GITEX / European cybersecurity conferences.
- **Rank: 3 (highest value; requires LLC and enterprise features first).**

### ICP 4: Life sciences / GxP / 21 CFR Part 11 environment
- **Trigger event:** internal audit, FDA inspection readiness, or EMA Annex 22 review.
- **Pain:** Part 11 requires a "secure, computer-generated, time-stamped audit trail" that
  "independently records" operator entries -- which is exactly what Provenrail's off-box
  server receipt chain delivers.
- **Conversion speed:** slow; validation-heavy; requires formal product validation pack.
- **Revenue ceiling:** very high; single deal $100K-$500K.
- **Rank: 4 (high value but validation effort needed; not solo-founder-reachable without a
  warm introduction).**

### ICP 5: Financial services / DORA-covered entity
- **Trigger event:** DORA is in its first genuine supervisory enforcement cycle as of 2026.
  ICT third-party risk management requires auditable records.
  Source: https://compliancehub.wiki/dora-nis2-2026-enforcement-eu-financial-cyber-resilience-compliance/
- **Rank: 5 (high value; requires RBAC, SIEM connectors, and enterprise features; not
  reachable solo without a partner channel).**

---

## Part 4. How to Be Best in Market

Ranked by "moves us closer to a paying customer."

### 1. Launch the managed cloud product (effort: high, revenue signal: critical)
**What:** Deploy the server (already built) as a public hosted service. Free tier, Builder
tier ($29/month), Team tier ($99/month). The billing surface is Polar (already integrated).
**Why:** Without a URL a buyer can point their agent at, there are zero conversions. Every
other improvement to positioning, pricing, or features is wasted until the managed product
is live. Self-hosted only means every sales conversation requires an ops conversation.
**Revenue signal:** first paying subscribers. This is the gate before everything else.
**Stop doing:** treating managed hosting as a Tier 2 roadmap item. It is Tier 0.

### 2. Publish one sharp proof page for the freelancer / agency ICP (effort: low, signal: fast)
**What:** A single page at provenrail.com/for-agencies (or similar) that speaks directly to
the freelancer delivering AI agent work to an EU client. Headline: "Give your client a
receipt they can verify without trusting you." Show the workflow in three steps. Link to the
plugin marketplace. One-click demo. CTA to free tier.
**Why:** This is the fastest-converting ICP (no procurement, one credit card), it is
reachable by a solo founder through Indie Hackers and Twitter, and it is the message that
generates the word of mouth that unlocks ICP 2 and 3.
**Stop doing:** leading with EU AI Act Art. 12 as the primary hook. Art. 12 enforcement
is December 2027; it creates urgency for enterprises in the planning window, not for
the developer who needs to convert this week.

### 3. Ship the Claude Code plugin to the public marketplace (effort: low, signal: fast)
**What:** The README already describes the plugin install flow. Publish it. The target
audience is Claude Code users (a fast-growing power-user base), and the install path is
two commands.
**Why:** This is distribution that compounds. Every developer who installs the plugin and
runs pr guard receipt is a potential word-of-mouth referrer and a potential paying customer
for the managed sink. It is also a moat: a plugin-marketplace listing is not replicable by
Langfuse or Datadog without building the same guardrail layer.
**Revenue signal:** plugin installs as a leading indicator of managed-sink signups.

### 4. Position against Microsoft AGT specifically (effort: low, signal: medium-fast)
**What:** A compare page (or a section on /compare) that contrasts Provenrail's dual-chain,
off-box, independently verifiable design against Microsoft AGT's in-process SHA-256 chain.
The headline: "In-process means the auditor and the agent share the same trust boundary.
That is not independent recording." Cite the AGT GitHub and the STRATEGY.md analysis.
**Why:** Microsoft AGT is the only competitor with real market visibility in the crypto-
audit space. Naming it specifically makes Provenrail visible in searches for AGT
alternatives, and the technical argument is air-tight. This is the "Langfuse vs. the field"
moment: the first comparison page wins the search intent.
**Revenue signal:** inbound from AGT searches.

### 5. Build the Go verifier (effort: medium, signal: medium)
**What:** A statically-linked binary that verifies a bundle.json. No dependencies, one
download, runs everywhere.
**Why:** "Verify it yourself" is the core claim. Auditors and compliance professionals
cannot run Python. A Go binary removes the largest friction point in the verification story.
It also deepens the lockstep to three implementations, making the format a genuine standard
candidate.
**Revenue signal:** auditor adoption of the verifier is a leading indicator of enterprise
procurement.

### 6. Submit to the IETF SCITT working group now (effort: low-medium, signal: slow but structural)
**What:** Submit a brief to the IETF SCITT working group citing Provenrail as an
AI-agent-native SCITT Transparency Service. Comment on draft-ietf-scitt-architecture and
draft-stone-aivs. Get "Provenrail" or the bundle format referenced as a compliant profile.
**Why:** The harmonized standard for Art. 12 logging (prEN ISO/IEC 24970) is not yet
published. The window to influence is now. If the standard is shaped around Provenrail's
format, the moat is institutional rather than technical.
**Revenue signal:** lags by 12-24 months but is the highest-durability outcome.

### 7. Package a 21 CFR Part 11 validation pack (effort: medium, signal: high-value)
**What:** A formal validation pack (IQ/OQ/PQ templates, control-to-requirement mapping,
vendor assessment checklist) that a GxP organization can use to include Provenrail in their
validated system documentation. Price it as a one-time add-on ($500-$2K as a solo founder;
$5K-$20K enterprise).
**Why:** 21 CFR Part 11 is the strongest existing tamper-evidence mandate and it is in
force today with no deferral. Life sciences organizations are already conditioned to pay for
compliance tooling. This is the fastest path to a high-value deal that does not require
an LLC (it is IP / document sale, not data hosting).
**Revenue signal:** first consulting or license sale.

### What to STOP doing

- **Treating distribution as a fast-follow.** It is the job. 92 PyPI downloads/month at
  this stage is a measurement problem, not a product problem. The product is good. It is
  invisible. Everything else is secondary to getting people to see it.
- **Leading with the full technical stack in the first sentence.** "SCITT, COSE, RFC 3161,
  Ed25519, C2SP" as the hero message repels the freelancer who just wants to prove what
  their agent did. Save the stack for the technical trust section.
- **Building more crypto infrastructure before the managed product is live.** Bitcoin
  anchoring, eIDAS QTSP, ML-DSA post-quantum: all valuable, all premature while the managed
  hosting that generates the first dollar does not exist.
- **Targeting enterprise before the LLC exists.** GDPR processor status, BAA exposure, and
  procurement questionnaires that require a legal entity are blockers. Get revenue from
  ICP 1 and 2 first; form the LLC; then pursue enterprise.

---

## Part 5. Regulatory Timing

### EU AI Act: verified dates as of 2026-08-18

**Article 50 -- Transparency obligations (chatbots, deepfakes, emotion recognition)**
- IN FORCE: August 2, 2026. No deferral. Fines up to 15M EUR or 3% of worldwide turnover.
- European Commission guidelines published July 20, 2026.
- Source: https://www.cooley.com/news/insight/2026/2026-08-03-eu-ai-act-transparency-obligations-take-effect-2-august-2026
- Source: https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act
- Provenrail relevance: low for Art. 50 itself (covers interaction disclosure, not audit
  trail). Relevant as a signal that EU enforcement is real and escalating.

**Article 12 -- Automatic logging for high-risk AI (Annex III standalone)**
- Deferred by Regulation (EU) 2026/1744 (the Digital Omnibus on AI) to December 2, 2027.
- Published in the Official Journal July 24, 2026; in force July 27, 2026.
- Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-deadline-omnibus-20260/
- Source: https://www.whitecase.com/insight-alert/eu-ai-omnibus-enters-force-amending-ai-act
- For Annex I systems (embedded in EU product safety law): deferred to August 2, 2028.
- Logging obligations themselves were not weakened; only the deadline moved.
- Harmonized standard prEN ISO/IEC 24970 (AI logging) is still not published.
- Provenrail relevance: primary long-horizon forcing function. Enterprise planning cycles
  start now (12-18 months ahead of December 2027). This is the moment to be in
  procurement conversations even though enforcement is 16 months away.

**What to say in messaging:**
"Enterprise procurement teams are already running EU AI Act readiness assessments for
December 2027. If you are in those conversations, Provenrail's regime attestation report is
what goes in the evidence pack." Do not claim the obligation is already in force for
Art. 12; it is not.

### Product Liability Directive (Directive 2024/2853)
- Transposition deadline: December 9, 2026. Applies to products placed on market after
  that date. AI systems explicitly included in the definition of "products."
- Source: https://www.reedsmith.com/articles/eu-product-liability-directive-software-digital-products-cybersecurity/
- Source: https://euverify.com/resource/eu-product-liability-directive-2026-changes/
- Provenrail relevance: under the PLD, if an AI system causes harm, the developer faces
  no-fault strict liability. A Provenrail bundle is evidence of what the agent actually
  did -- the defense artifact. This is an underexploited angle: "when your agent causes
  harm, what is your defense?"
- Nearest real forcing function: December 9, 2026 is 4 months away. For any organization
  shipping AI software to the EU, the PLD creates an immediate incentive to maintain an
  immutable audit trail. This is a more immediate trigger than Art. 12 and applies to
  any AI software, not just high-risk Annex III systems.

### DORA (Digital Operational Resilience Act)
- In force: January 17, 2025. Now in first active supervisory enforcement cycle.
- Source: https://digital.nemko.com/regulations/digital-operational-resilience-act
- Applies to: financial entities (banks, investment firms, payment institutions).
- ICT third-party risk management and incident reporting require auditable records.
- Provenrail relevance: ICT incident reconstruction for financial AI agents. The
  existing SIEM export (ndjson) is the right interface; SIEM push connectors would
  unlock this ICP.

### NIS2 (Network and Information Security Directive)
- National transposition and compliance obligations: October 2026 deadline.
- Source: https://compliancehub.wiki/dora-nis2-2026-enforcement-eu-financial-cyber-resilience-compliance/
- Applies to: critical infrastructure, digital service providers.
- Provenrail relevance: incident logging and evidence retention for critical-sector AI.
  Same evidence layer; different compliance label.

### ISO/IEC 42001 (AI Management Systems)
- Published 2023; in active use as a voluntary framework. Gartner Magic Quadrant vendors
  (Credo AI, Holistic AI) cite it for control mapping.
- Provenrail relevance: A.6.2.8 (AI event logging). The regime attestation report
  already maps to it.

### US equivalents
- No federal AI logging mandate in force as of 2026-08-18.
- Colorado AI Act became enforceable June 2026 (limited scope, high-risk AI in consumer
  decisions; documentation requirements).
- NIST AI RMF (voluntary): measure, manage, govern functions all call for event records.
- FDA / 21 CFR Part 11: in force, no deferral, life sciences only. Strongest existing US
  mandate for tamper-evident electronic records.

### Which date is the nearest real forcing function for a buyer

1. **Product Liability Directive -- December 9, 2026 (4 months).** Applies to all AI
   software shipped to the EU. Creates strict liability for harm. An immutable audit trail
   is the defense artifact. No carve-out for small companies. This is the most actionable
   near-term regulatory angle.

2. **EU AI Act Art. 12 -- December 2, 2027 (16 months).** The big horizon event for
   enterprise Annex III deployers. Planning cycles start now. Use this to get into
   procurement conversations today, not to imply the obligation is immediate.

3. **DORA -- already in enforcement.** For financial services AI agents, this is active
   today. Provenrail's NDJSON export and agent guardrails are directly relevant.

**What the product should say about it:**
Separate the near-term and the long-horizon explicitly. For ICP 1/2: "The EU Product
Liability Directive makes AI developers strictly liable for software harm starting December
2026. A Provenrail bundle is your defense artifact." For ICP 3: "Your December 2027 EU AI
Act Art. 12 evidence preparation should start now. Here is the attestation report."

---

## Sources

- LLM observability market size: https://blog.aimactgrow.com/high-llm-observability-and-analysis-platforms-in-2026-langfuse-langsmith-braintrust-arize-and-extra-in-contrast/
- ClickHouse acquires Langfuse (January 2026): https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability
- Langfuse at ClickHouse acquisition: https://www.infoworld.com/article/4118621/clickhouse-buys-langfuse-as-data-platforms-race-to-own-the-ai-feedback-loop.html
- LangSmith / Braintrust pricing comparison: https://www.respan.ai/market-map/compare/braintrust-vs-langsmith
- Braintrust Langfuse alternatives 2026: https://www.braintrust.dev/articles/langfuse-alternatives-2026
- Top LLM observability tools 2026: https://www.confident-ai.com/knowledge-base/compare/top-7-llm-observability-tools
- Datadog LLM pricing 2026: https://ecorpit.com/datadog-llm-observability-pricing-cap-costs-2026/
- HoneyHive pricing: https://en.ai-pedias.com/blog/ai-llm-observability-monitoring-2026
- Helicone maintenance mode / Mintlify: https://openobserve.ai/blog/llm-observability-tools/
- Traceloop pricing: https://aicalculatorpro.com/ai-stack/llm-observability/traceloop/
- Arize Phoenix alternatives: https://laminar.sh/article/arize-phoenix-alternatives-2026
- Gartner Magic Quadrant AI Governance (Credo AI, Holistic AI): https://www.kosmoy.com/resources/blog/credo-ai-vs-holistic-ai/
- Credo AI review 2026: https://aicompliancevendors.com/vendors/credo-ai
- AI governance tools buyer guide 2026: https://www.modulos.ai/best-ai-governance-platforms/
- Sigstore / Rekor: https://github.com/sigstore/rekor
- TestifySec / Witness SLSA 2026: https://cloudsmith.com/blog/the-2026-guide-to-software-supply-chain-security-from-static-sboms-to-agentic-governance
- Codenotary AgentMon 3 launch (July 2026): https://www.businesswire.com/news/home/20260707200686/en/Codenotary-Launches-AgentMon-3-with-Adaptive-Runtime-Security-Policies-Expands-Availability-on-AWS-Marketplace
- Codenotary immudb 1.11 audit logging (May 2026): https://www.businesswire.com/news/home/20260505298955/en/Open-Source-Tamper-Proof-Database-Adds-Immutable-Audit-Logging-and-Expands-PostgreSQL-Compatibility
- WitnessAI $58M (January 2026): https://witness.ai/resources/witnessai-raises-58-million-for-global-expansion-and-announces-new-ways-to-secure-ai-agents/
- Geordie AI $30M Series A (May 2026): https://fortune.com/2026/05/28/geordie-security-governance-ai-agents/
- Microsoft Agent Governance Toolkit (April 2026): https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/
- Microsoft AGT audit and compliance: https://microsoft.github.io/agent-governance-toolkit/tutorials/04-audit-and-compliance/
- EU AI Act Digital Omnibus deferral: https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-deadline-omnibus-20260/
- EU AI Act Omnibus White and Case: https://www.whitecase.com/insight-alert/eu-ai-omnibus-enters-force-amending-ai-act
- EU AI Act enforcement timeline: https://euaiactchecklist.com/eu-ai-act-august-2026-deadline.html
- EU AI Act Art. 50 in force August 2, 2026: https://www.cooley.com/news/insight/2026/2026-08-03-eu-ai-act-transparency-obligations-take-effect-2-august-2026
- EC guidelines on transparency obligations (July 20, 2026): https://digital-strategy.ec.europa.eu/en/library/guidelines-transparency-obligations-providers-and-deployers-ai-systems
- EU AI Act Art. 50 scope: https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act
- Product Liability Directive: https://www.reedsmith.com/articles/eu-product-liability-directive-software-digital-products-cybersecurity/
- PLD AI and software: https://euverify.com/resource/eu-product-liability-directive-2026-changes/
- DORA enforcement 2026: https://compliancehub.wiki/dora-nis2-2026-enforcement-eu-financial-cyber-resilience-compliance/
- DORA overview: https://digital.nemko.com/regulations/digital-operational-resilience-act
- EU procurement and AI Act compliance clauses: https://www.secondtalent.com/resources/eu-ai-act-vendor-compliance/
- NIS2 DORA AI Act convergence: https://www.kiteworks.com/regulatory-compliance/nis2-dora-eu-ai-compliance/
