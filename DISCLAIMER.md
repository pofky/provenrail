# Disclaimer

Provenrail is **evidence tooling, not legal advice and not a compliance guarantee.**

- **No warranty.** The software is provided "as is", without warranty of any kind, to the fullest
  extent permitted by law. See `LICENSE` (MIT) and `LICENSE-AGPL` (AGPL-3.0).
- **What it proves and does not.** Provenrail makes records that reach the sink tamper-evident and
  independently verifiable. It does **not** and **cannot** prove completeness: an agent that never
  calls the SDK will not appear in the record. This limitation is stated throughout the product and
  the specification, not hidden in fine print.
- **Compliance.** References to the EU AI Act, HIPAA 164.312(b), 21 CFR Part 11, PCI DSS, ISO 42001,
  SOC 2, or eIDAS describe how Provenrail's technical controls map to those frameworks as supporting
  evidence. They are not certifications. Your organization remains responsible for its own
  compliance, certification, and attestation. Provenrail does not act as a HIPAA business associate.
- **"Take to court."** This describes the design goal of producing independently verifiable evidence.
  Admissibility and weight of any evidence are decided by the relevant court or authority, not by us.
- **Legal advice.** Nothing in this repository or on the website is legal advice. Consult qualified
  counsel in your jurisdiction.

## Approval links

The out-of-band approval feature sends single-use, time-limited links to the notification
endpoint you configure. Opening a link shows the pending action; the decision is only recorded
when the button on that page is submitted.

It authenticates the token, not the person. Provenrail cannot tell who clicked, only that a
valid link was submitted before it expired, so the security of an approval is the security of
the channel you deliver it over. Where a regulatory or contractual requirement calls for an
identified or authenticated approver, add that control outside this product.

The record of the approval is written and signed by the agent, not by the sink. The sink
cannot forge one. It can, however, tell the waiting agent that a request was approved when
nobody clicked, and the agent will then sign a genuine oversight record. Approvals are
therefore only as trustworthy as the sink the agent is pointed at. Run your own if that
matters to you.
