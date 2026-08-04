# Provenrail: Regulatory Hooks and Standards Alignment

Status date: 2026-06-09. This maps Provenrail's technical controls to the regulations and standards
that require, or reward, tamper-evident, independently verifiable, externally-anchored logs. It
separates what is legally required *now* from what is advisable, and states only claims we can make
truthfully. It is a sales/auditor artifact and the backbone of the auditor-codependency moat
(MOAT.md section 3).

Provenrail is evidence tooling, not a compliance certification. We provide the verifiable record;
your team (and your auditor) provide the attestation. We never claim completeness.

---

## 1. In-force mandates (immediate, concrete)

### 21 CFR Part 11 11.10(e) (FDA electronic records) -- strongest existing tamper-evidence mandate
Requires "secure, computer-generated, time-stamped audit trails to independently record ... operator
entries and actions" and that "record changes shall not obscure previously recorded information,"
retained at least as long as the records and available for agency review.
- **Provenrail control:** append-only hash chain + independent off-box server receipt chain (changes
  cannot obscure prior records; recording is independent of the agent) + RFC 3161 timestamps +
  standalone verifier for agency review.
- **Truthful claim:** "Satisfies 21 CFR 11.10(e)'s independent, time-stamped, non-obscuring audit
  trail requirement." High value for life-sciences (GxP, clinical, manufacturing); EMA Annex 22 is
  extending Part 11 principles to AI.

### PCI DSS v4.0.1 Requirement 10 (cardholder data environments)
Requires log integrity protection with "cryptographic protections" or WORM, file-integrity
monitoring, and 12-month retention.
- **Provenrail control:** SHA-256 hash chain + Ed25519 signatures provide the cryptographic protection
  and change-detection in one mechanism, no separate WORM tier required.
- **Truthful claim:** "Implements the cryptographic log-integrity and change-detection controls
  required by PCI DSS Requirement 10."

### eIDAS / eIDAS 2.0 (EU legal presumption of integrity)
A qualified RFC 3161 timestamp from a QTSP binds time to data such that modification is detectable and
confers a statutory *presumption of integrity*, reversing the burden of proof.
- **Provenrail control:** RFC 3161 anchoring today (FreeTSA default); QTSP integration is on the
  roadmap to unlock the qualified presumption.
- **Truthful claim now:** "Anchors to RFC 3161 trusted timestamps." **After QTSP integration:**
  "Optionally anchored by eIDAS-qualified timestamps conferring statutory presumption of integrity."

### HIPAA 45 CFR 164.312(b) and SOC 2 CC7.2
Audit controls over ePHI access/modification (HIPAA) and tamper-resistant, retained audit logging
(SOC 2). Hash chaining is accepted by auditors as the integrity control that DB permissions cannot
provide.
- **Truthful claim:** "Produces the tamper-evident audit-log evidence expected under HIPAA 164.312(b)
  and SOC 2 CC7.2," with content-hash-by-default so logs do not leak ePHI/prompts.

## 2. The large future market: EU AI Act

Articles 12 and 19 require high-risk AI systems to automatically record events over their lifetime,
retained at least six months, to enable post-market monitoring and authority review. The text does
**not** specify a format or mandate the word "tamper-evident" -- but logs that can be silently altered
have no evidentiary value, so integrity is implicit in the purpose. Enforcement for Annex III
high-risk systems was moved to **2 December 2027** by the Digital Omnibus (May 2026); the logging
obligations themselves were not weakened, and harmonized standards (CEN-CENELEC `prEN ISO/IEC 24970`
on AI logging) are **still unpublished**.
- **Truthful claim:** "Provides the automatic, tamper-evident, retained event log required as
  technical evidence under EU AI Act Articles 12 and 19," with the honest caveat that certification is
  the deployer's responsibility.
- **Moat move:** the format is undefined and the window is open. Engage JTC 21 and the IETF drafts now
  (MOAT.md section 6) so the standard is shaped around what we already build.

## 3. Standards alignment

| Standard | Status (2026-06) | Provenrail alignment |
|---|---|---|
| IETF SCITT (`draft-ietf-scitt-architecture`) | RFC-imminent | We emit COSE receipts as a SCITT Transparency Service profile (SPEC 18) |
| `draft-ietf-cose-merkle-tree-proofs` | Active | RFC9162_SHA256 inclusion proofs in our receipts |
| IETF AIVS (`draft-stone-aivs`) | draft-00 | Our bundle is a superset (chain + signatures + offline verifier) |
| VAP (`draft-kamimura-vap-framework`) | draft-00 | External anchoring + completeness signals map to its Integrity Layer |
| ISO/IEC 42001 A.6.2.8 (AI event logging) | Published | Our bundle is the "retained records" + "configuration proof" evidence |
| C2SP tlog-checkpoint / cosignature / witness | Stable | Adopted verbatim for the witness log (SPEC 9-11) |

Do **not** claim conformance to `prEN ISO/IEC 24970` or "harmonized standard" status: those are not yet
published. SCITT/AIVS/VAP are drafts -- claim "aligned to / profiled on," not "conformant to an RFC."

## 4. Control-to-requirement quick map (for an auditor)

| Requirement theme | Provenrail mechanism | SPEC |
|---|---|---|
| Independent recording | off-box server receipt chain | 4 |
| Non-obscuring / append-only | hash chain + append-only DB triggers | 1-4 |
| Time-stamped, no back-dating | RFC 3161 Merkle anchoring | 5 |
| Independently verifiable | standalone Python + JS verifier, offline | 7 |
| Anti-equivocation | RFC 6962 witnessed transparency log | 9-11 |
| Standards-interoperable receipt | SCITT COSE receipt | 18 |
| Right-to-erasure vs immutability | selective-disclosure redaction | 17 |
| Privacy by default | store-hash-not-content | 1 |

## 5. What to build for auditor codependency (sequenced)

1. A one-page control-mapping export inside the evidence pack (this table, per regime).
2. A free auditor verification portal (upload a bundle, get a signed verdict + control mapping).
3. eIDAS QTSP timestamp option and a 21 CFR Part 11 validation pack (life-sciences accelerant).
4. SCITT receipt registration with a public Transparency Service for cross-checkable receipts.
