"""The auditor sees one of two pages, and they must say the same thing.

A customer who self-hosts the sink hands an auditor a page rendered by src/provenrail/server/app.py.
A customer who uses the hosted anchor service hands them a page rendered at the Cloudflare edge by
functions/v1/anchors/[id].js. Same claim, same audience, two files.

The sentences below are the honest limits of what an anchor proves. If one page keeps them and the
other quietly loses one, the customer who picked the wrong hosting option hands their auditor a
page that oversells the evidence, and nobody finds out until it matters.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).parent.parent
PY_PAGE = ROOT / "src" / "provenrail" / "server" / "app.py"
JS_PAGE = ROOT / "functions" / "v1" / "anchors" / "[id].js"

# Whitespace-normalised on both sides: each file wraps these sentences to its own line length, and
# a test that depends on where a line breaks fails on reflow rather than on drift.
SHARED_CLAIMS = [
    # what it does prove
    "Coverage of a stream can only grow here.",
    "we refuse two different fingerprints for the same length",
    "We never received their records.",
    "There is no field in the request their data could have travelled in",
    # what it does not prove, which is the half that gets dropped
    "That they recorded everything.",
    "It cannot show that an action was never written down in the first place.",
    "That the records say what they told you.",
    # the honest label on a self-signed time
    "Self-asserted time.",
    "not independent proof of the calendar date",
    # how to check without trusting either party
    "pr anchor-verify bundle.json anchor-receipt.json",
    "an id that does not resolve is not evidence of anything, in either direction",
    # the standing disclaimer
    "It is not legal advice, a compliance guarantee, or an audit opinion.",
]


def _flat(p: pathlib.Path) -> str:
    """Collapse whitespace, then close the seams where a source file split a sentence.

    Both pages wrap these sentences to their own line length, and Python does it by ending one
    string literal and starting another mid-sentence. Without stitching those back together the
    test fails on where a line happened to break rather than on a claim actually going missing.
    """
    text = " ".join(p.read_text(encoding="utf-8").split())
    return re.sub(r"""(["'`])\s*[fr]?\1""", "", text)


def test_both_auditor_pages_make_the_same_claims():
    py, js = _flat(PY_PAGE), _flat(JS_PAGE)
    missing_py = [c for c in SHARED_CLAIMS if c not in py]
    missing_js = [c for c in SHARED_CLAIMS if c not in js]
    assert not missing_py, f"the self-hosted anchor page lost: {missing_py}"
    assert not missing_js, f"the hosted anchor page lost: {missing_js}"


def test_the_hosted_page_does_not_claim_an_independent_timestamp_it_did_not_get():
    """The hosted service signs with its own key against its own clock. If the page ever renders
    the green "independently timestamped" line for a receipt that is not RFC 3161, it is telling
    an auditor a third party vouched for the date when none did."""
    js = _flat(JS_PAGE)
    assert 'receipt.kind === "rfc3161"' in js, "the hosted page no longer gates on receipt kind"
    green = js.index("Independently timestamped.")
    gate = js.index('receipt.kind === "rfc3161"')
    assert gate < green, "the green timestamp line is no longer behind the rfc3161 check"


def test_the_hosted_page_is_not_indexable():
    """An anchor id is unguessable but public. Letting search engines index one would turn "give
    this link to your auditor" into "publish that you anchored 4,000 records on this date"."""
    js = _flat(JS_PAGE)
    assert "name=robots content='noindex'" in js
    assert '"x-robots-tag": "noindex"' in js


def test_the_proxy_holds_no_rules_of_its_own():
    """The coverage rules, the signing key and the account lookup live upstream. A second copy at
    the edge is a copy that can disagree with the one that actually decides."""
    post = _flat(ROOT / "functions" / "v1" / "anchors.js")
    for leak in ("covers_up_to <", "merkle_root !==", "api_key_hash", "ANCHOR_SIGNING_KEY"):
        assert leak not in post, f"the edge proxy has started making its own decisions: {leak}"
