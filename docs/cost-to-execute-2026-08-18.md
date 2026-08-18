# Provenrail: Cost to Execute
## Status: 2026-08-18

Research conducted 2026-08-18. Every external number is cited.
Where a number could not be verified it is labelled UNVERIFIED with a range and reasoning.
Currency conversions use 1 USD = 0.93 EUR (approximate, August 2026).

Scope: solo founder, Lithuania, individuali veikla (sole proprietorship, no liability
shield). This document is structured around what he can actually do without forming a
company and without becoming a GDPR processor for customer agent logs.

---

## SUMMARY TABLE: 7 Moves from the Competitive Study

| Move | One-off EUR | Monthly EUR | Founder-days | Blocker |
|---|---|---|---|---|
| 1. Launch managed cloud (anchor-only variant; see section below) | 0 | 28-45 | 3-5 | None: anchor-only avoids GDPR processor trigger |
| 1. Launch managed cloud (full records variant) | 0 | 28-45 | 10-15 | Legal: GDPR processor without company |
| 2. Freelancer / agency page | 0 | 0 | 2-3 | None |
| 3. Claude Code plugin marketplace | 0 | 0 | 1-2 | None |
| 4. Microsoft AGT compare page | 0 | 0 | 1-2 | None |
| 5. Go verifier | 0 | 0 | 5-10 | Time |
| 6. IETF SCITT submission | 0 | 0 | 2-4 | None |
| 7. 21 CFR Part 11 validation pack | 0 | 0 | 5-10 | None: document sale, not data processing |

Moves 2, 3, 4, 6, and 7 cost zero cash, are not blocked, and can start today.
Move 1 in anchor-only form costs nothing to start and ~30-45 EUR/month to run.
Move 5 is time only.

---

## THE ANCHOR-ONLY SERVICE

### What it is

The server already has two architecturally separate concerns. The records layer
(storage.py `records` table, the ingest endpoint) receives full client records --
the `client_record TEXT NOT NULL` column is the GDPR processor trigger. The anchoring
layer (anchor.py, tlog.py) receives only a list of SHA-256 hex strings, computes a
Merkle root, timestamps it via RFC 3161, and writes the receipt and the tlog checkpoint.
The anchor layer never touches the content of any record.

In anchor-only mode, the architecture is:
- Customer runs the AGPL sink themselves on their own infrastructure.
- The customer sink processes records and computes a Merkle root over a batch
  of receipt hashes (the exact operation in `anchor.py::merkle_root()`).
- The customer sink posts only `{stream_id, merkle_root_hex, covers_up_to}` to
  Provenrail's anchor API.
- Provenrail timestamps that root (RFC 3161 or QTSP), writes it to the
  transparency log, and returns the AnchorReceipt.
- Provenrail never sees the underlying records.

What Provenrail stores in this model: stream_id (a UUID), merkle_root_hex (32 bytes,
a SHA-256 hash of SHA-256 hashes), covers_up_to (integer), the RFC 3161 timestamp
token, and the tlog commitment. None of this is personal data under GDPR Recital 26:
reversing a SHA-256 Merkle root over record hashes is computationally infeasible, and
there is no inversion key held by Provenrail. The stream_id is a UUID the customer
assigns; Provenrail cannot link it to a natural person without additional information
it does not hold.

### Is this buildable today?

The anchor.py and tlog.py modules are complete and standalone. The server's existing
anchor scheduler (which calls RFC3161Anchor for streams it hosts) already implements
the RFC 3161 + tlog pipeline. What does not exist is:

1. A lightweight HTTP endpoint that accepts `{stream_id, merkle_root, covers_up_to}` 
   from an external (customer-operated) sink, validates the API key, rate-limits by
   plan, calls the anchor + tlog pipeline, and returns the AnchorReceipt.
2. A per-account usage counter for anchor calls (the `usage` table already has an
   `anchors` column; it just needs to be wired to the external endpoint).
3. Billing plan enforcement: free tier N anchors/month, Builder tier more.

Estimated founder-days to build: 3-5 days including tests and deploy. The existing
anchor.py and tlog.py code is reused unchanged. The endpoint is 150-250 lines.

### Infrastructure cost for anchor-only at three scales

Assumptions:
- Anchoring cadence: customer chooses batch intervals; realistic is 1 anchor/15 minutes
  or every N events.
- Provenrail performs one tlog checkpoint per anchor batch (not per customer per call).
- FreeTSA (free RFC 3161) used unless QTSP upgrade is purchased.

**10 customers**
- Supabase Pro (auth, accounts DB, edge functions): $25/month = ~23 EUR
- Cloudflare Workers paid plan (anchor API endpoint): $5/month = ~5 EUR
- R2 storage (receipts, tlog data, negligible volume): <1 EUR
- Total: 28-30 EUR/month
- Staging (Supabase free project + CF Workers dev subdomain): 0 EUR

**100 customers**
- Supabase Pro: $25/month = ~23 EUR (100 accounts well within free MAU and storage)
- Cloudflare Workers: $5/month base; anchor call volume at 100 customers x 4/hour x
  720 hours = ~288,000 calls/month, within the $5 tier
- R2: ~1 GB of receipts + tlog checkpoints = 0.015 EUR/GB = <1 EUR
- Total: 30-35 EUR/month

**1000 customers**
- Supabase Pro: $25/month; may need Small compute add-on ($10) for concurrent
  connections at peak = ~33 EUR
- Cloudflare Workers: $5/month base; 1000 customers x 4/hour x 720 hours =
  ~2.88M calls/month, still within $5 tier (10M included)
- R2: ~10 GB = 0.15 EUR
- Total: 40-45 EUR/month

Comparison (Hetzner VPS + Fly.io managed Postgres):
- Hetzner CPX11 equivalent after June 2026 price increase: ~3.79-5 EUR/month for
  shared vCPU server. Source: https://northflank.com/blog/hetzner-cloud-server-price-increases
- Fly.io Managed Postgres Basic: $38/month = ~35 EUR
- Total: ~40-45 EUR/month; similar cost but substantially more ops work (patching,
  backups, SSL certs, WAL). Not recommended for a solo founder at this stage.

### Timestamping cost at scale

**FreeTSA (RFC 3161, not eIDAS qualified)**
Cost: free. No rate limits published; donation-supported.
Source: https://freetsa.org; https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
Legal status: not eIDAS qualified. Sufficient for most non-regulated buyers.

**Sectigo TSA (RFC 3161, not eIDAS qualified)**
Cost: free public endpoint http://timestamp.sectigo.com
Legal status: not eIDAS qualified. Production-grade and used by major open-source
projects. Significantly more reliable than FreeTSA.

**OpenTimestamps / Bitcoin calendar**
Cost: free, donation-supported. Three calendar servers: alice.btc.calendar, bob.btc.calendar.
No published rate limits. Source: https://opentimestamps.org
Legal status: not RFC 3161, not eIDAS. Bitcoin inclusion provides blockchain-level
immutability but no legal presumption of integrity under eIDAS.
Lag: 10-60 minutes for Bitcoin block confirmation. Good for the moat layer (anchoring
history), not for real-time verification SLAs.

**eIDAS Qualified QTSP timestamp**
Providers serving the EU/Baltics: ADACOM (Greece), GlobalTrust (Austria), AlfaTrust/
qtsa.eu (Baltic-adjacent), Evrotrust (Bulgaria), Entrust, Sectigo (for qualified).
All are on the EU Trusted List at https://eidas.ec.europa.eu/efts/

Pricing: UNVERIFIED. No QTSP publishes per-timestamp pricing publicly. Based on
industry knowledge and comparable services, the range is approximately:
- 0.10-0.50 EUR per timestamp for B2B volume (1,000-10,000/month range)
- Annual subscription with included volume: estimated 500-3,000 EUR/year UNVERIFIED
- Contact required: ADACOM (tss.adacom.com), GlobalTrust (globaltrust.eu), AlfaTrust
  (qtsa.eu/purchase). ADACOM and GlobalTrust both have "Contact Sales" gates.

At 1,000 customers with hourly per-customer anchoring (no batching): 720,000
timestamps/month x 0.10 EUR = 72,000 EUR/month. Unaffordable.

At 1,000 customers with batched anchoring (one tlog checkpoint per epoch, all customers'
roots included in one Merkle tree, one RFC 3161 stamp per checkpoint, every 15 minutes):
4 x 24 x 30 = 2,880 timestamps/month x 0.10 EUR = 288 EUR/month.

The batching architecture is the correct production design and is compatible with the
existing tlog_checkpoints table. A single checkpoint covers all accounts' streams for
that epoch. This is how the moat compounds: one externally-witnessed checkpoint is
timestamped globally, not per customer.

**Practical recommendation:** Ship with FreeTSA or Sectigo (free, reliable). Add QTSP
as a paid upgrade tier for buyers who need eIDAS qualified presumption. Price the QTSP
tier to cover the 0.10-0.50 EUR/timestamp cost plus margin.

---

## LIABILITY LADDER

Ranked by legal exposure, lowest first. Each row states: GDPR role, DPA needed,
insurance needed, company needed.

### 1. Selling compliance evidence-pack content (GDPR templates, control-mapping docs)

What it is: a ZIP of Word/PDF templates mapping Provenrail's controls to EU AI Act
Art. 12, ISO 42001, 21 CFR Part 11, PCI DSS 10. One-time or subscription sale.
The buyer receives documents. Provenrail never touches their data.

- GDPR role: none. This is sale of IP/content, not processing of personal data.
  Provenrail collects the buyer's email for delivery via Polar (Polar is controller
  for payment data). GDPR basis for email: contract performance, Art. 6(1)(b).
- DPA: not required. No data processing agreement needed between Provenrail and buyer.
- Insurance: not legally required. Professional indemnity would be prudent if a buyer
  claims the templates were wrong and caused loss, but no EU law mandates it for a
  software documentation sale.
- Company: not required. Sole proprietor can sell and invoice for IP.
- Revenue ceiling: low (one-time €50-2,000 per pack). Recurring only if subscription.

### 2. Commercial license for the AGPL server

What it is: a perpetual or annual license allowing a company to run or embed the
Provenrail server without AGPL obligations. Pure IP transaction.

- GDPR role: none. Provenrail grants a license; the buyer runs the software themselves.
  No data flows to Provenrail.
- DPA: not required.
- Insurance: not legally required. A licensing agreement typically includes a warranty
  disclaimer and liability cap (standard boilerplate).
- Company: not required. A sole proprietor can be the copyright holder and licensor.
  The LICENSING.md note about "Provenrail pending formal entity formation" is already
  correctly documented.
- Revenue ceiling: medium (€500-50,000 per deal). Largest deals eventually require
  a legal entity for contract counterparty comfort, not legal necessity.

### 3. Integration, setup, and support retainers

What it is: the founder installs and configures Provenrail on the customer's
infrastructure, writes integration glue code, and provides ongoing support.

- GDPR role: data processor (limited). The founder will likely access the customer's
  production environment and therefore their data. Basis: Art. 6(1)(b) (contract
  performance) for the work; Art. 28 DPA required when accessing personal data.
- DPA: YES, required when the work involves accessing the customer's personal data
  on their systems. A standard Art. 28 DPA template (1-2 pages) covers this. The
  DPA governs Provenrail's access to the customer's data, not hosting.
- Insurance: professional indemnity is advisable for retainers; enterprise customers
  frequently ask for it. A sole proprietor can buy it. See insurance section.
- Company: not required. A sole proprietor can sign service agreements and DPAs.
- Revenue ceiling: medium (€1,000-10,000/month for active retainers). Hard cap on
  time; one founder scales to roughly 2-3 concurrent retainer clients maximum.

### 4. Anchor-only API (receive Merkle roots, stamp and witness them)

What it is: the customer self-hosts the AGPL sink; they send only Merkle roots to
Provenrail's API for external timestamping and transparency-log witnessing.

- GDPR role: Provenrail receives stream_id (UUID, not personally identifying by itself)
  and a SHA-256 Merkle root (computationally irreversible). Under Recital 26 ("all
  means reasonably likely to be used"), reversing a SHA-256 Merkle root over already-
  hashed records is not feasible. This is effectively anonymous data.
  The EDPB position (Guidelines 01/2025 on pseudonymisation) draws a distinction
  between keyed pseudonymisation (reversible, stays personal data) and one-way hashing
  with no inversion key (closer to anonymisation). Provenrail holds no inversion key.
  Practical position: treat as pseudonymous to be conservative; document the processing;
  no DPA with the customer is required because Provenrail is not processing the
  customer's agent-record personal data on the customer's behalf.
  Source: https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf
- DPA: not required for the anchor data. Provenrail's own privacy policy covers
  account registration data (email, billing).
- Insurance: not legally required. Advisable if revenue scales.
- Company: not required. This is the highest-margin recurring revenue stream available
  to a sole proprietor without crossing the GDPR processor line.
- Revenue ceiling: high. 100 customers at 29 EUR/month = 2,900 EUR/month at 30 EUR
  infra cost. Near-100% gross margin on the anchor data; cost is only infra + TSA.

### 5. Managed sink hosting hashes only (store-hash-not-content mode)

What it is: Provenrail hosts the full sink server but the agent is configured to store
SHA-256 hashes of payload content rather than the content itself. The records table
contains hashed payloads.

- GDPR role: Provenrail IS a data processor, even with hashes. The EDPB position on
  pseudonymisation applies: if the customer holds the pre-hash originals, the hashes
  are pseudonymous relative to the customer and remain personal data under GDPR.
  Provenrail processes personal data on behalf of the customer (controller).
  Source: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/pseudonymisation/
- DPA: YES, required. Art. 28 DPA between customer (controller) and Provenrail
  (processor). Standard template, but must be in place before any customer data lands.
- Insurance: professional indemnity and cyber liability strongly advised.
- Company: NOT strictly required by law, but personal liability for a GDPR breach falls
  on the sole proprietor personally. A data breach involving customer agent records
  (even hashed) can result in supervisory authority investigation, fines up to 2% of
  worldwide turnover (Art. 83(4)), and civil claims from data subjects. Without an LLC,
  the founder's personal assets are exposed. BUSINESS.md correctly identifies this as
  the LLC trigger.
- Revenue ceiling: high. But legal exposure is real without a company.

### 6. Managed sink hosting full records (content stored)

The strongest legal exposure. Full records containing prompts, tool outputs, filenames,
and potentially ePHI or other personal data land in Provenrail's database.

- GDPR role: unambiguously a data processor. Art. 28 DPA mandatory. Data transfer
  impact assessment likely needed for non-EU customers.
- DPA: YES, mandatory before first record.
- Insurance: mandatory in practice for any enterprise buyer. Required by procurement.
- Company: DO NOT proceed without an LLC. Personal liability for a breach at this
  tier is ruinous for a sole proprietor. Even with an LLC, the company needs GDPR
  compliance infrastructure (privacy notices, breach procedures, DPO assessment,
  records of processing activities under Art. 30).

### The line he must not cross without a company

The line is Tier 5: hosting anything on behalf of a customer that the customer's
subjects could consider personal data, even if the records are hashed. The safe zone
is Tiers 1-4. The anchor-only API (Tier 4) is the highest-revenue option in the safe
zone and is the correct move for a sole proprietor.

---

## WHAT CONVERTS: the buying process for low-liability streams

### Which low-liability stream closes fastest

The 21 CFR Part 11 validation pack (Tier 1, pure content) requires zero technical work
beyond document writing. A life-sciences QA manager searching for compliance tooling
will recognize the value immediately and has budget authority for a one-time €500-2,000
purchase. But finding that buyer cold requires a warm introduction; this is not the
fastest first sale.

The Claude Code plugin + Builder subscription (Tier 4 anchor-only) is the fastest
conversion path. The buyer is a developer; they install the plugin in two commands,
see it working, and convert to Builder ($29/month) without involving procurement.
The anchor-only model means no DPA, no legal review, no company required.

The commercial AGPL license (Tier 2) requires a company to have a legal reason to pay:
they are running the Provenrail server in a proprietary product and want clean IP. This
is a slow sale (company legal review) but high-value.

### Can a company buy from individuali veikla?

Yes, with caveats. Individuali veikla is a registered activity in Lithuania, recorded
at the State Tax Inspectorate (VMI) and searchable by registration number.
Source: https://remoteworkeurope.eu/insights/lithuania-individuali-veikla-business-licence-uab/

The invoice is valid under Lithuanian law. For EU B2B transactions, the reverse charge
mechanism applies: if both seller and buyer are VAT-registered, the seller issues an
invoice with no Lithuanian VAT, the buyer accounts for VAT in their own country (EU
VAT directive, implemented uniformly across member states).

If Provenrail's annual turnover is below 45,000 EUR, VAT registration is not mandatory
in Lithuania. Source: https://www.globalvatcompliance.com/globalvatnews/lithuania-vat-threshold-increase-2026/
Below that threshold, a sole proprietor selling to a VAT-registered EU company
includes a note on the invoice: "VAT not charged -- seller below registration threshold;
buyer applies reverse charge per [local VAT directive article]." The buyer's accounts
team handles this routinely for small EU vendor invoices.

Practical buying experience by deal size:
- Under 5,000 EUR/year: department-level buy, purchase card, no procurement involvement.
  An invoice from "Rokas [surname], individuali veikla, Vilnius, Lithuania" clears
  without legal review at most tech companies.
- 5,000-20,000 EUR/year: procurement asks for a vendor questionnaire. Questions will
  include entity type, registration number, bank details, insurance certificate,
  and sometimes a DPA or privacy policy. A Tier 4 (anchor-only) product answers all
  of these without needing a company. Insurance certificate is the soft barrier here;
  see insurance section below.
- 20,000-100,000 EUR/year: enterprise procurement cycle. At this level, most EU
  enterprise buyers will ask for an LLC or equivalent. Not legally required from
  their side, but their standard vendor risk framework expects it. A sole proprietor
  can still win this deal; it adds friction.
- Above 100,000 EUR/year: assume company required. A solo founder at this revenue
  level should have the LLC anyway.

### What the buying process looks like for the fastest-converting ICP

ICP 1 (freelancer/agency delivering AI work to an EU client):
1. Developer finds the plugin via Claude Code marketplace, Indie Hackers, or Twitter.
2. Two-command install: `claude mcp add provenrail` + configure stream endpoint.
3. Free tier: developer runs a session, gets a bundle, verifies it with the verifier.
4. Decision: if they self-host the sink (AGPL), they pay nothing to Provenrail
   beyond considering the anchor-only API. If they want Provenrail to be the
   independent third-party anchor, they pay 29 EUR/month Builder.
5. The credit card is the buying process. No procurement, no DPA, no contract review.
   Time from discovery to first payment: hours to one day.

ICP 2 (startup building an AI product for a regulated vertical):
1. Their enterprise client asks "can you give me an audit trail?" -- this is the trigger.
2. Startup finds Provenrail via the comparison page against Microsoft AGT or SCITT search.
3. They evaluate: does it satisfy the requirement? The auditor verification portal
   and the regime attestation report are the sales artifacts.
4. Buying decision is one person (CTO or tech lead). Deal is 99-499 EUR/month.
   DPA required if using managed hosting. For anchor-only, DPA not required.
5. Time to close: one to two weeks from discovery. The blocker is usually "prove it
   works with our stack" -- a 30-minute integration call closes this.

---

## THREE SCENARIOS

### Scenario A: Maximum revenue as sole proprietor (the actual plan)

**Constraint:** No GDPR processor for customer agent records. No company needed.
**Revenue streams available:** Tiers 1-4 of the liability ladder.

**Revenue at steady state (optimistic but not delusional):**
- 50 Builder subscriptions at 29 EUR/month (anchor-only): 1,450 EUR/month
- 10 Team subscriptions at 99 EUR/month (anchor-only, larger teams): 990 EUR/month
- 2 commercial AGPL licenses at 2,000 EUR/year each: 333 EUR/month
- 2 compliance evidence pack sales at 500 EUR each, 6/year: 500 EUR/month
- 1 integration/support retainer at 2,500 EUR/month: 2,500 EUR/month
- Total: ~5,773 EUR/month gross

**Monthly costs:**
- Infrastructure (Supabase Pro + CF Workers + R2): 35-45 EUR
- FreeTSA or Sectigo TSA: 0 EUR
- OpenTimestamps Bitcoin anchoring: 0 EUR
- Accounting (individuali veikla, no VAT required below 45K EUR): optional; VMI tax
  calculator handles simple cases; professional accountant ~80 EUR/month if needed
- Domain + email (already live): 0 additional
- Total burn: 35-125 EUR/month

**Up-front cash required to start:**
- 0 EUR. Infrastructure is free-tier until first customer. Cloudflare Pages is live.
  Supabase free tier handles initial customers. Worker endpoint for anchor-only API
  is 5 EUR/month on paid plan.
- Upgrade to Supabase Pro ($25/month) on first paid customer.

**Time to first euro:** 2-4 weeks (build anchor API endpoint + publish plugin +
freelancer page).

**What it unlocks:** Up to approximately 6,000-8,000 EUR/month recurring before
hitting the "sole proprietor needs a company" friction wall at enterprise deals above
20,000 EUR/year per customer.

**Break-even:** 2 Builder subscribers (2 x 29 = 58 EUR/month) covers infra. One
retainer covers the founder's living costs. First paying customer needed to reach
break-even: 1 customer at 29 EUR/month (above infra cost if using free TSA).

---

### Scenario B: Form the company and launch managed cloud (if/when revenue justifies)

This is not the current plan. It is a conditional path: execute Scenario A first,
take the first 2,000-3,000 EUR/month recurring as the signal, then form the company.

**Company formation (UAB, Lithuania):**
- Minimum share capital: 1,000 EUR (25% = 250 EUR required before registration,
  remainder within 12 months). Source: https://www.thompsonstein.com/en/how-much-does-a-uab-company-in-lithuania-cost-in-2026-full-breakdown/
- Notary and registration fees: approximately 72-290 EUR notary + 57 EUR Registru
  centras = 129-347 EUR for DIY. Service provider package (1Office, Thompson&Stein):
  650-2,100 EUR all-in.
  Source: https://1office.co/blog/company-formation-in-lithuania-guide/
  Source: https://balticincorp.com/blog/price-to-register-a-company-in-lithuania
- Timeline: 3-7 business days at the registry; 2-3 weeks total with service provider.
- Remote registration: yes, via notarised power of attorney or e-signature.
- Recommended service: 1Office or similar (balticincorp.com starts at 700 EUR);
  do not use a Thompson&Stein-class provider (2,100 EUR) for a first company.

**Alternative: MB (mazoji bendrija, small partnership)**
- Minimum share capital: 1 EUR. No notary required for formation.
  Source: https://lawhill.lt/blog/starting-a-business-in-lithuania/
- Formation costs: approximately 200-400 EUR (service) or self-registration via RC.lt.
- Liability shield: YES (limited to share capital, which is 1 EUR, but the entity
  is a separate legal person).
- Limitation: MB cannot issue shares to investors; not suitable if outside capital is
  planned. For a bootstrapped solo founder, MB is cheaper and equally valid.
- MB recommendation: if forming a company now, MB is the right choice at this stage.

**Ongoing company costs:**
- Registered address: ~600 EUR/year (mandatory for UAB or MB in Lithuania).
  Source: https://www.thompsonstein.com/en/how-much-does-a-uab-company-in-lithuania-cost-in-2026-full-breakdown/
- Accountant for micro company (0 employees, few transactions): 80-150 EUR/month
  (1Office, ELV Projektai, nexa.tax). Source: https://elvprojektai.lt/en/accounting-services/uab-apskaita/
- CIT: 0% first year (under 10 employees, under 300,000 EUR revenue), 7% after.
  Source: https://workinlithuania.com/blog/lithuania-tax-system/

**Social contributions delta versus individuali veikla:**
- Individuali veikla 2026: social contributions (SoDra) base is NOW 90% of taxable
  income (increased from 50% in 2025). Rate 19.5%.
  Source: https://kpmg.com/xx/en/our-insights/gms-flash-alert/flash-alert-2025-202.html
  Example: 40,000 EUR IV profit -> SoDra base = 36,000 EUR -> SoDra = 7,020 EUR.
  Plus GPM (income tax) on the remainder.
- UAB with minimum salary + dividends: salary of ~12,456 EUR/year (minimum wage
  1,038 EUR/month x 12) incurs employee+employer SoDra of ~21.27% = ~2,650 EUR.
  Dividends (remainder after 7% CIT) taxed at 15% GPM, no SoDra.
  Source: https://taxsummaries.pwc.com/lithuania/individual/other-taxes
  Example: 40,000 EUR UAB revenue -> 7% CIT on ~27,544 EUR profit after salary =
  ~1,928 EUR CIT; remaining 25,616 EUR as dividend at 15% = 3,842 EUR GPM.
  Total tax: ~1,928 + 3,842 + 2,650 = ~8,420 EUR vs IV ~12,000+ EUR.
  Net saving on 40K revenue: approximately 3,500-4,000 EUR/year.
  At lower revenue (under ~20K), the saving is smaller and may not justify the
  1,000-2,000 EUR/year accounting overhead.

**Managed cloud additional infrastructure:**
- Supabase Pro: ~23 EUR/month (handles first 100-200 customers' full records)
- Cloudflare Workers (ingest + dashboard API): ~5-30 EUR/month depending on volume
- R2 (bundle storage): ~1-15 EUR/month depending on retention
- Staging environment: Supabase free tier (1 project) + CF dev subdomain = 0 EUR
- Total additional infra for managed cloud vs anchor-only: ~5-25 EUR/month more

**Insurance (for managed cloud with full records):**
- Professional indemnity (E&O): UNVERIFIED; EU IT professional indemnity from Exali
  (pan-EU provider, regulated in Germany) starts at approximately 200-400 EUR/year
  for a solo developer with low annual revenue and a 250,000 EUR limit.
  Source: https://www.exali.com/professional-indemnity-for-digital-professions/developer/
  For audit-evidence tooling (higher professional liability risk), budget 500-1,500 EUR/year.
- Cyber liability: UNVERIFIED; 300-800 EUR/year for a solo developer at this scale.
  Source: UK market data from https://www.kingsbridge.co.uk/freelance-developer-insurance/
  EU market typically 10-30% higher than UK for equivalent cover.
- Total insurance: 800-2,300 EUR/year UNVERIFIED.

**Scenario B up-front cash:**
- MB formation: 200-400 EUR
- Registered address year 1: 600 EUR
- Share capital: 1 EUR (MB) or 250 EUR now + 750 EUR deferred (UAB)
- Insurance: ~1,000 EUR/year (first year)
- Total up-front: ~1,800-2,000 EUR (MB) or ~2,500-3,100 EUR (UAB)

**Scenario B monthly burn:**
- Accounting: ~100 EUR
- Registered address: 50 EUR (600/12)
- Insurance: ~100 EUR
- Infrastructure (managed cloud, 100 customers): ~50-70 EUR
- TSA (batched QTSP for enterprise buyers): ~50-200 EUR UNVERIFIED
- Total: ~350-520 EUR/month

**Break-even:** 6-10 paying customers at 29-99 EUR/month covers the full burn.

**Months to first euro:** Scenario B adds 4-8 weeks over Scenario A for company
formation before the managed cloud can be offered to customers with GDPR processor
obligations. Revenue from Tiers 1-4 can start during that window.

---

### Scenario C: Certifications for regulated/enterprise buyers (appendix only)

Not the current plan. Costs are here for reference.

- SOC 2 Type I: automation platform (Sprinto at ~7,000 EUR/year) + CPA audit
  (15,000-30,000 EUR). Total: 22,000-37,000 EUR year 1.
  Source: https://xorabyte.com/blog/soc-2-cost-guide/
- SOC 2 Type II: same platform + 12-month observation period + audit: 30,000-70,000 EUR.
- ISO 27001: 15,000-50,000 EUR total year 1 (audit + consulting for solo founder
  using a consultant). Source: https://hightable.io/iso-27001-certification-cost/
- ISO 42001 (AI management): UNVERIFIED; relatively new standard, fewer auditors;
  estimate 20,000-60,000 EUR year 1, similar structure to ISO 27001.
- 21 CFR Part 11 validation pack for buyers: NOT a certification requirement for the
  SELLER. It is a set of documents (IQ/OQ/PQ templates, control mapping) that the
  BUYER uses in their validated system. No external certification is required to sell it.
  The founder writes the documents; the buyer uses them. Pure content sale.

None of these certifications are needed before first revenue. They are gating
requirements for specific enterprise deals (regulated industry procurement) and are
funded from existing revenue.

---

## BREAK-EVEN ANALYSIS

The competitive study states pricing: Free / Builder 29 EUR/month / Team 99 EUR/month /
Enterprise custom. Price points below are in EUR.

| Scenario | Monthly burn | Break-even customers |
|---|---|---|
| A (sole prop, anchor-only) | 35-125 EUR | 2 Builder customers covers infra; 1 retainer covers founder living costs |
| B (company, managed cloud, 100 customers) | 350-520 EUR | 4 Builder OR 4 Team customers |
| C (+ SOC 2 Type I amortised over 12 months) | 2,200-3,600 EUR | 23-37 Builder OR 7-12 Team customers |

The anchor-only variant of Scenario A has the most favorable unit economics: infrastructure
cost of 35 EUR/month means a single Builder subscriber (29 EUR) almost covers it;
FreeTSA costs zero; gross margin on anchor calls is approximately 95%+ above one customer.

---

## CHEAPEST CREDIBLE PATH TO THE FIRST PAYING CUSTOMER

Build the anchor-only HTTP endpoint in the existing server (3-5 days). Ship the
Claude Code plugin to the public marketplace (1-2 days). Publish the freelancer and
agency page with a direct CTA to the Builder tier (2-3 days). Post on Indie Hackers,
LangChain Discord, and the Claude Code community. The target buyer is a freelancer
or small agency delivering AI agent work to an EU client who needs to prove what their
agent did. The purchase is a credit card transaction at 29 EUR/month; no contract,
no DPA, no company required from either side. The only infrastructure cost before that
customer exists is zero (Supabase free tier + Cloudflare Pages free tier). Total cash
outlay to reach the first paying customer: 0 EUR. Total founder-days: 6-10 days.
Upgrade Supabase to Pro ($25/month) when the first customer signs up.

The anchor-only model means Provenrail charges for being the independent party that
timestamps and witnesses the Merkle root of the customer's self-hosted log. The customer
gets: an RFC 3161 timestamp from a neutral third party, a C2SP-format tlog checkpoint,
and an independently verifiable receipt. That is the core of the moat, productized
at 29 EUR/month, with no GDPR processor exposure, no company, and no up-front cash.

---

## DISTRIBUTION COSTS (Move 6 from the study)

- AWS Marketplace: 3% SaaS listing fee on every transaction, no upfront listing fee.
  Source: https://aws.amazon.com/about-aws/whats-new/2024/01/aws-marketplace-simplified-reduced-listing-fees/
  Note: AWS Marketplace requires an entity (can be individuali veikla in theory, but
  marketplace onboarding in practice asks for a legal entity and a US bank account
  or a global payments partner). Treat as Scenario B item.
- Polar MoR fee: 5% + 0.50 USD per transaction (Starter plan, as of May 2026 rate
  increase). Provenrail signed up before May 27, 2026; confirm whether the early-
  member rate (4% + 0.40 USD) was grandfathered.
  Source: https://dodopayments.com/blogs/polar-sh-review
  Source: https://polar.sh/blog/introducing-polar-plans
  On 29 EUR/month Builder: fee is 1.45-1.50 EUR per transaction.
- PyPI, npm: free.
- Claude Code plugin marketplace: free listing.
- ProductHunt, Hacker News Show HN, Indie Hackers: free.
- Paid amplification: UNVERIFIED; a sponsored spot in a developer newsletter (e.g.
  TLDR, The Pragmatic Engineer) costs 1,000-4,000 USD per issue. Not recommended
  before organic conversion is proven.

---

## SOURCES

- UAB formation, Thompson&Stein 2026: https://www.thompsonstein.com/en/how-much-does-a-uab-company-in-lithuania-cost-in-2026-full-breakdown/
- 1Office UAB guide 2026: https://1office.co/blog/company-formation-in-lithuania-guide/
- Baltic Incorp registration cost: https://balticincorp.com/blog/price-to-register-a-company-in-lithuania
- Lithuanian business types: https://lawhill.lt/blog/starting-a-business-in-lithuania/
- UAB/MB accounting (ELV Projektai): https://elvprojektai.lt/en/accounting-services/uab-apskaita/
- Lithuania tax rates 2026: https://workinlithuania.com/blog/lithuania-tax-system/
- Lithuanian individuali veikla SoDra 2026 (KPMG): https://kpmg.com/xx/en/our-insights/gms-flash-alert/flash-alert-2025-202.html
- PWC Lithuania individual taxes: https://taxsummaries.pwc.com/lithuania/individual/other-taxes
- Lithuania VAT threshold 2026: https://www.globalvatcompliance.com/globalvatnews/lithuania-vat-threshold-increase-2026/
- Individuali veikla structure: https://remoteworkeurope.eu/insights/lithuania-individuali-veikla-business-licence-uab/
- Supabase Pro pricing 2026: https://makerkit.dev/blog/saas/supabase-pricing
- Cloudflare Workers pricing 2026: https://toolradar.com/tools/cloudflare-workers/pricing
- Cloudflare R2 pricing (zero egress): https://egresscost.com/cloudflare/
- Hetzner price increases June 2026: https://northflank.com/blog/hetzner-cloud-server-price-increases
- Fly.io managed Postgres pricing: https://fly.io/mpg/
- FreeTSA RFC 3161: https://freetsa.org
- Free RFC 3161 servers list: https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
- OpenTimestamps: https://opentimestamps.org
- Sectigo TSA (free public endpoint): https://www.sectigo.com/resource-library/time-stamping-server
- ADACOM QTSP timestamping: https://tss.adacom.com/qtss
- EU Trusted List of QTSPs: https://eidas.ec.europa.eu/efts/
- Polar MoR fee 2026 (Dodo): https://dodopayments.com/blogs/polar-sh-review
- Polar pricing announcement: https://polar.sh/blog/introducing-polar-plans
- AWS Marketplace fee reduction 2024: https://aws.amazon.com/about-aws/whats-new/2024/01/aws-marketplace-simplified-reduced-listing-fees/
- AWS Marketplace professional services fee June 2026: https://aws.amazon.com/about-aws/whats-new/2026/06/reduce-listing-fee-professional-services-aws-marketplace/
- SOC 2 cost 2026: https://xorabyte.com/blog/soc-2-cost-guide/
- Sprinto pricing: https://g2.com/products/sprinto-inc/pricing
- ISO 27001 cost 2026: https://hightable.io/iso-27001-certification-cost/
- EDPB pseudonymisation guidelines 2025: https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf
- ICO pseudonymisation guidance: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/pseudonymisation/
- GDPR Recital 26: https://gdpr-info.eu/recitals/no-26/
- Exali EU professional indemnity: https://www.exali.com/professional-indemnity-for-digital-professions/developer/
- Kingsbridge freelance developer insurance: https://www.kingsbridge.co.uk/freelance-developer-insurance/
