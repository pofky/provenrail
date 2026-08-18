# PRD: the anchor-only trust service, and a price list that matches it

Status: in implementation. Opened 2026-08-18. Type C.
Companions: `docs/cost-to-execute-2026-08-18.md` (liability ladder),
`docs/competitive-study-2026-08-18.md` (market), `BUSINESS.md` (revenue model).

## Problem

Two problems, and they are the same problem seen from two ends.

**The legal end.** The operator trades as a Lithuanian `individuali veikla`. There is no
liability shield. `BUSINESS.md` draws the line clearly: hosting other people's agent records
makes him a GDPR processor with personal liability, and that is deferred until a company exists.
But `web/pricing.html` already sells exactly that. Builder is "500k events per month" and Team is
"2M events per month" of hosted ingestion, and the FAQ says paid plans buy "hosted convenience".
One tier row promises evidence packs "mapped to EU AI Act Article 12 and HIPAA audit-control
requirements", and `BUSINESS.md` explicitly says no HIPAA posture before the company. The site
sells a liability the seller cannot carry. That is the highest-severity open item in the project,
higher than any bug found in the flow audit, because a sale under those terms is worse than no
sale.

**The product end.** The thing a self-hoster structurally cannot do for themselves is be their
own neutral third party. `BUSINESS.md` already names that as the moat. But today the only way to
get Provenrail's independence is to send Provenrail your records, which is the very thing that
creates the liability. The moat and the liability are welded together, and they should not be.

## The insight

They come apart cleanly, because of a fact already true in the code: what makes a record
verifiable is its hash, not its content. `capture_content` defaults to `False`
(`src/provenrail/sdk.py:90`) so prompts and outputs never leave the customer's process, and
`anchor.py` already computes a Merkle root over record hashes alone.

So sell the root. The customer self-hosts the AGPL sink and keeps every record. They compute a
Merkle root over their own record hashes and send Provenrail only that root, plus how far it
covers. Provenrail timestamps it, signs it, keeps an append-only history of it, and will attest
to it for a third party. A SHA-256 root over hashes is not personal data by any route: it is not
identifiable, not reversible, and not linkable to a person without data the operator never holds.
No processing of personal data, no DPA, no processor status, no company needed.

The customer gets the one thing they cannot manufacture: an independent party who wrote down what
their log looked like at a time they cannot influence, and who will say so later. That is the
product, and it was always the product. Hosting was only ever the delivery mechanism.

## Scope

**In.**

- `POST /v1/anchors`: accept `{stream_id, merkle_root, covers_up_to}` from a customer-hosted
  sink. Store the root, the coverage, and a timestamp receipt. Never accept a record.
- Monotonic coverage per stream. An anchor that covers less than the previous one is rejected.
  This is what makes the history evidence rather than a log: the operator cannot quietly rewind,
  and neither can the customer.
- `GET /v1/anchors/{anchor_id}`: public, unauthenticated attestation lookup. This is the auditor
  portal in its smallest honest form. It returns a root, a time, a receipt, and nothing else,
  because there is nothing else.
- `GET /v1/anchors?stream_id=`: the coverage history for a stream, authenticated.
- `anchor_root()` on the anchor classes, so a precomputed root can be timestamped without
  inventing leaves for it.
- `pr anchor push`: compute the root from a local bundle or a local sink and send it.
- `pr anchor verify`: given a bundle and a receipt, prove the receipt covers this bundle. Checks
  the root recomputes from the bundle's own record hashes, the signature or RFC 3161 token is
  valid, and the coverage claim is consistent with the bundle's length.
- Rewrite `web/pricing.html` so every paid tier is something the operator can legally sell today,
  and remove the HIPAA claim.

**Out.**

- Hosted record ingestion stays exactly as it is, self-host only, and is no longer sold as a
  hosted service. `/v1/ingest` is not changed or removed: it is what a self-hoster runs.
- No company formation, no certification, no insurance. Deliberately.
- Bitcoin/OTS submission of anchor roots. The verifier already checks OTS proofs; server-side
  submission stays deferred.

## Milestones

- **M0** `anchor_root()` on `LocalAnchor`, `RFC3161Anchor`, `MultiTSAAnchor`, with `anchor()`
  reduced to `anchor_root(merkle_root(leaves))`. Tests prove the two paths agree.
- **M1** Storage: `external_anchors` table, append with monotonic coverage enforcement, read by
  id and by stream.
- **M2** The three endpoints, with auth on write and history, none on the public attestation.
- **M3** `pr anchor push` and `pr anchor verify`.
- **M4** `web/pricing.html` repositioned, JSON-LD, FAQ and compare table consistent with it.
- **M5** Independent flow test of the whole path on a real server, by an agent that did not write
  it.

## Gates

Full chain. Security scanner matters most here: the write path takes a key and must never accept
a record, and the public read path must never leak one. The SEO/CRO auditor gets the pricing page.

## Risks

- **The root could be argued to be personal data.** Mitigated by never accepting anything else,
  by not holding a key that could link roots to people, and by saying plainly on the page what is
  and is not sent. If a regulator disagreed, the remedy is deleting a table of hashes.
- **"Anchoring" is harder to explain than "hosting".** The page has to earn it in one sentence.
  The demo is the argument: the customer keeps everything and still gets a receipt a stranger can
  check.
- **Repositioning could lose the two paying tiers.** They have no customers today, so the cost of
  changing them is zero and the cost of leaving them is unbounded.
- **A customer sends a root computed over the wrong thing.** `pr anchor verify` is the answer, and
  it must be run against the customer's own bundle, not ours.
