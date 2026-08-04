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
          "test_claims_hygiene.py"}


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
