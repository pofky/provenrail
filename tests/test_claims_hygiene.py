"""Phrases that promise an authority we do not hold.

Every one of these was in shipped copy at some point. They are cheap to write and expensive to
defend: each implies a certification, an assurance opinion, or a legal outcome decided by
someone other than us. Under the EU Unfair Commercial Practices Directive the test is the
overall impression on the average reader, not whether a disclaimer exists elsewhere on the
site, so a qualification two pages away does not rescue the claim.

This is a test rather than a review note because copy drifts back. A grep in CI is the only
thing that has ever stopped it.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: phrase -> why it cannot be said, and what to say instead.
BANNED = {
    "take to court": "promises an outcome a court decides; say what the record proves instead",
    "court-grade": "there is no such grade, and it implies admissibility we cannot promise",
    "audit-grade": "implies conformance to an audit standard nobody has certified us against",
    "auditor-grade": "the same claim with one more syllable; no auditor has graded anything here",
    "audit-ready": "readiness is the auditor's determination, not ours",
    "legally binding": "we make nothing legally binding",
    "guarantees compliance": "compliance is never guaranteed here",
    "ensures compliance": "same",
    "fully compliant": "same",
    "certified by": "nobody has certified this",
    "we certify": "we issue no certification",
    "nobody can forge": "true only for records that reached the sink; say that",
    "impossible to forge": "same",
}

#: Files whose whole purpose is to say what we do NOT claim. A denial has to be able to quote
#: the phrase it is denying.
EXEMPT = {"DISCLAIMER.md", "disclaimer.html", "COMPLIANCE.md", "STRATEGY.md",
          "test_claims_hygiene.py",
          # These two have to be able to name the things they forbid ("do not offer to be a
          # HIPAA business associate", "the page used to say hosted convenience"). Both are
          # internal, neither is shipped copy, and in both the phrase appears inside the rule
          # against it. A test that fired on its own rulebook would teach the next session to
          # delete the test.
          "BUSINESS.md", "HANDOFF.md"}


def _shipped_files():
    for pattern in ("web/*.html", "src/provenrail/**/*.py", "*.md"):
        for path in ROOT.glob(pattern):
            if path.name in EXEMPT or not path.is_file():
                continue
            yield path


def test_no_shipped_copy_promises_authority_we_do_not_hold():
    offences = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for phrase, why in BANNED.items():
            if phrase in text:
                line = next((n for n, ln in enumerate(text.splitlines(), 1) if phrase in ln), 0)
                offences.append(f"{path.relative_to(ROOT)}:{line} says {phrase!r}: {why}")
    assert not offences, "copy claims authority we do not hold:\n  " + "\n  ".join(offences)


def test_attestation_is_not_used_as_a_product_noun():
    """In assurance, an attestation report is a formal opinion from a licensed practitioner
    under a standard such as ISAE 3000. We issue no opinion and hold no licence, so the word
    cannot name what `pr report` produces. It stays legal only where we say we do NOT provide
    one, and in its unrelated cryptographic sense (an OpenTimestamps Bitcoin attestation)."""
    # Both orders: "regulatory attestation" and "attestation report/pack/evidence". The first
    # version of this test only caught the adjective form, and three occurrences of the noun
    # form sat in the homepage and its JSON-LD, which is what search engines and LLMs read.
    pattern = re.compile(r"(regulatory|regime|compliance)\s+attestation"
                         r"|attestation\s+(report|pack|evidence)", re.IGNORECASE)
    offences = []
    for path in _shipped_files():
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if pattern.search(line) and "not" not in line.lower():
                offences.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not offences, "attestation used as a product noun:\n  " + "\n  ".join(offences)


def test_the_completeness_boundary_is_stated_where_the_strong_claim_is_made():
    """The one thing this product can never prove is that a hostile agent recorded everything.
    The page that makes the strongest integrity claim is the one that most needs to say so."""
    index = (ROOT / "web" / "index.html").read_text(encoding="utf-8").lower()
    assert "completeness is never claimed" in index


# The operator trades as a Lithuanian individuali veikla with no liability shield. Hosting other
# people's agent records would make him a GDPR processor with personal exposure, so BUSINESS.md
# defers that until a company exists. The site sold it anyway for months: Builder was "500k events
# per month" of what read like hosted capacity, the FAQ said paid plans buy "hosted convenience",
# and one tier claimed evidence packs mapped to HIPAA audit controls. None of it was true of the
# code, and all of it was a promise he could not carry. A grep is the only thing that keeps copy
# on the right side of a line that costs this much to cross.
# Note what is NOT banned: naming HIPAA 164.312(b) as a control a report maps to. A mapping is
# content, and selling content is the safest thing on the ladder. The line is offering to be a
# business associate, or implying the product delivers HIPAA compliance, because that attracts a
# buyer whose expectations the operator cannot meet and whose breach becomes his.
SELLING_WHAT_WE_CANNOT_CARRY = {
    "hosted convenience": "there is no hosted tier; the customer runs the sink either way",
    "we host your records": "hosting customer records is the processor line; we do not cross it",
    "we store your records": "same",
    "business associate": "no BAA exists or can be signed before a company does",
    "baa": "same",
    "hipaa compliant": "we deliver evidence, never compliance; the covered entity owns that",
    "hipaa-compliant": "same",
    "gdpr compliant": "same claim, different regime",
    "gdpr-compliant": "same",
    "we are a processor": "the whole design exists so that we are not one",
}


def test_no_page_sells_a_liability_the_operator_cannot_carry():
    offences = []
    # Word boundaries, not substrings: "baa" as a substring would fire on ordinary words, and a
    # test that cries wolf gets deleted rather than obeyed.
    patterns = {phrase: re.compile(rf"\b{re.escape(phrase)}\b", re.IGNORECASE)
                for phrase in SELLING_WHAT_WE_CANNOT_CARRY}
    for path in _shipped_files():
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            for phrase, why in SELLING_WHAT_WE_CANNOT_CARRY.items():
                if patterns[phrase].search(line):
                    offences.append(f"{path.relative_to(ROOT)}:{n} says {phrase!r}: {why}")
    assert not offences, ("copy sells something the operator cannot legally provide:\n  "
                          + "\n  ".join(offences))


def test_the_pricing_page_still_says_where_records_live():
    """The positive half of the rule. Removing the false claim is not enough: the page has to say
    plainly that records stay with the customer, because that is the reason the paid tiers are
    sellable at all."""
    pricing = (ROOT / "web" / "pricing.html").read_text(encoding="utf-8").lower()
    assert "your own sink" in pricing or "your own infrastructure" in pricing
    assert "no. provenrail hosts identity and billing only" in pricing


def test_no_page_points_a_customer_at_a_host_that_does_not_exist():
    """README told people to run `pr anchor-push --url https://anchor.provenrail.com`. That host
    has never existed. An instruction that cannot work is worse than a missing one: the reader
    assumes they got it wrong.

    This is deliberately a check on hostnames rather than on availability, because a test cannot
    ask the internet. When the service does open, add its host here in the same commit that
    starts advertising it, which is the point: the two facts move together or the build fails."""
    live_hosts = {"provenrail.com", "www.provenrail.com", "github.com", "pypi.org",
                  "npmjs.com", "www.npmjs.com", "freetsa.org", "docs.astral.sh"}
    promised = re.compile(r"https://([a-z0-9.-]*provenrail\.com)")
    offences = []
    for path in _shipped_files():
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            for host in promised.findall(line):
                if host not in live_hosts:
                    offences.append(f"{path.relative_to(ROOT)}:{n} points at {host}, which does "
                                    f"not exist. Do not ship an instruction that cannot work.")
    assert not offences, "copy names a host we do not run:\n  " + "\n  ".join(offences)


def test_a_page_that_asks_for_a_root_says_that_is_all_we_get():
    """The hosted anchor service opened, and the risk on these pages inverted.

    Until it did, the danger was selling something nobody operated, and the test here required
    every page listing anchoring to say it was not open. The danger now is the opposite: a page
    that invites a customer to send us something and leaves them to guess what "something" is.
    They will assume the normal thing, which is that a service holding your evidence holds your
    evidence. This one holds a 64-character fingerprint and a count, and cannot hold more, and
    that is the entire basis on which a sole proprietor can operate it at all.

    So any page that points a customer at our anchor URL has to say, on that page, what actually
    travels and what stays with them.
    """
    offences = []
    for path in sorted((ROOT / "web").glob("*.html")):
        page = path.read_text(encoding="utf-8")
        if "--url https://provenrail.com" not in page:
            continue
        flat = " ".join(page.split()).lower()
        says_root_only = ("root of your chain" in flat or "fingerprint of your records" in flat
                          or "root only" in flat)
        says_you_keep = "keep every record" in flat or "you keep every record" in flat
        if not (says_root_only and says_you_keep):
            offences.append(f"{path.name} tells a customer to push to our anchor service without "
                            f"saying on the same page that only the root travels and they keep "
                            f"every record")
    assert not offences, "\n  ".join(offences)


def test_no_page_says_we_hold_records_we_are_not_sent():
    """The one claim that would be both false and legally load-bearing.

    Provenrail's whole position is that the operator never becomes a processor of anyone's agent
    records. A page describing the hosted service as storing, keeping, or hosting records would
    contradict what the service does and describe a business the operator cannot lawfully run
    without a company.
    """
    import re

    bad = re.compile(r"\bwe (store|keep|host|retain|hold) (your |their )?(agent )?records\b", re.I)
    offences = []
    for path in sorted((ROOT / "web").glob("*.html")) + [ROOT / "README.md"]:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if bad.search(line):
                offences.append(f"{path.name}:{n}: {line.strip()[:120]}")
    assert not offences, "copy claims we hold records we never receive:\n  " + "\n  ".join(offences)
