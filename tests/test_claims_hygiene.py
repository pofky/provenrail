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

import pytest

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


# ---------------------------------------------------------------- AI authorship attestation
#
# `pr attest` reintroduces the word "attestation" on purpose, in the software-supply-chain
# sense the industry already uses for a signed statement about an artefact (in-toto, SLSA,
# sigstore), and NOT in the assurance sense the test above forbids. The line between them is
# thin enough to be worth pinning: the moment the copy says "compliance attestation" or
# "attestation report" it is claiming a licensed practitioner's opinion, and the rule above
# already fails the build for that. What these tests add is the other half, the claims this
# particular feature must never make and the list it must never quietly diverge from.


def _attestation_pages():
    for name in ("ai-code-attribution.html", "index.html", "pricing.html", "docs.html"):
        path = ROOT / "web" / name
        if path.is_file():
            yield path


def test_no_page_says_the_attestation_proves_the_findings_are_true():
    """The whole feature rests on being straight about this. A page that implies a signature
    makes a finding TRUE has sold the reader something no signature can buy, and it is the one
    misreading a lawyer would be entitled to rely on."""
    banned = re.compile(
        r"prov(es|e|ing) (that )?(the )?(findings|attribution|disclosure)"
        r"[^.]{0,40}\b(true|correct|accurate|complete)\b"
        r"|guarantee[sd]? (the )?(findings|attribution)"
        r"|certif(y|ies|ied) (that )?(the )?(code|findings)",
        re.IGNORECASE)
    # The denials say the same words in the opposite direction, and the page is full of them
    # on purpose, so a match only counts when nothing negates it and it is not a question.
    negation = re.compile(r"\b(not|never|no|cannot|neither|nothing|does not|is not)\b",
                          re.IGNORECASE)
    offences = []
    for path in _attestation_pages():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = banned.search(line)
            if not match:
                continue
            lead = line[max(0, match.start() - 60):match.start()]
            if negation.search(lead) or negation.search(match.group(0)) or "?" in line:
                continue
            offences.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not offences, ("copy claims an attestation proves its findings:\n  " +
                          "\n  ".join(offences))


def test_the_attribution_page_states_the_limit_it_would_be_relied_on_for():
    """Every claim on that page is defensible only next to this sentence. If a redesign drops
    it, the page becomes the kind of evidence-shaped document this product exists to replace."""
    path = ROOT / "web" / "ai-code-attribution.html"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8").lower()
    assert "does not prove the findings are true" in text
    assert "strips the trailer" in text or "removed that metadata" in text
    assert "understated rather than overstated" in text


def test_the_advertised_detector_list_matches_the_code():
    """A page naming a tool the detector does not know is a promise the software breaks in
    silence: the customer reads "Cursor is detected", ships a Cursor-written commit, and the
    document reports it as human-authored."""
    path = ROOT / "web" / "ai-code-attribution.html"
    if not path.is_file():
        return
    from provenrail.attest import AGENT_SIGNATURES

    text = path.read_text(encoding="utf-8")
    for signature in AGENT_SIGNATURES:
        assert signature.tool in text, (
            f"{signature.tool} is detected by the code but not named on the page")
    # And the reverse: nothing is advertised that the code does not detect. Checked against the
    # sentence that lists them, so an incidental mention elsewhere does not count as a promise.
    known = {s.tool.lower() for s in AGENT_SIGNATURES}
    for candidate in ("continue.dev", "roo code", "augment", "amazon q", "tabnine", "sourcegraph"):
        if candidate not in known:
            assert candidate not in text.lower(), (
                f"the page names {candidate}, which the detector does not know about")


def test_no_page_offers_to_receive_the_customers_code():
    """The anchor service has no field a record or a file could arrive in, and that absence is
    the entire reason a sole proprietor can operate it. Copy that offers to take a repository
    would be selling a liability that does not exist in the code."""
    banned = re.compile(r"(upload|send|share) (us |your )?(the )?(repo|repository|codebase|source code)"
                        r"|we (store|keep|hold) your (code|repository)", re.IGNORECASE)
    offences = []
    for path in _attestation_pages():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if banned.search(line) and " never " not in line.lower() and " no " not in line.lower():
                offences.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not offences, ("copy offers to receive customer code:\n  " + "\n  ".join(offences))


def test_the_advertised_rule_counts_match_the_catalogue():
    """Two numbers appear on the guardrails page and in the plugin README, and both are the
    kind of number that goes stale the first time a rule is added. A page that says 26 rules
    are armed while 24 are is a small lie in the one place this product cannot afford one."""
    from provenrail import rulesets
    from provenrail.guard import DEFAULT_PACKS

    armed = len(rulesets.resolve(DEFAULT_PACKS))
    total = len(rulesets.all_rules())
    for name in ("web/claude-code-guardrails.html", "web/index.html",
                 "plugins/provenrail-guard/README.md", "README.md"):
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        if "rules are armed" not in text and "rules armed" not in text:
            continue
        assert f"{armed} rules are armed" in text or f"{armed} rules armed" in text, (
            f"{name} does not say {armed} rules are armed by default")
    # The pack count goes stale the same way the rule count does, so it is spelled out of the
    # catalogue rather than written into this test.
    words = {4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
             11: "eleven", 12: "twelve"}
    packs = words[len(rulesets.CATALOG)]
    guardrails = (ROOT / "web" / "claude-code-guardrails.html").read_text(encoding="utf-8")
    assert f"{total} rules across {packs} packs" in guardrails


# (page, the exact command as it is written on the page, the verdict the page shows)
# A terminal demo is a claim like any other. `rm -rf ./src` sat in the homepage demo captioned
# "blocked" for a release after the rule stopped denying it, which is the drift this catches:
# the string has to still be on the page AND still produce that verdict.
DEMOED = [
    ("web/index.html", "git reset --hard origin/main", "ask"),
    ("web/index.html", "rm -rf ~/Projects", "deny"),
    ("web/claude-code-guardrails.html", "git reset --hard", "ask"),
    ("web/claude-code-guardrails.html", "git checkout -- .", "ask"),
    ("web/claude-code-guardrails.html", "git clean -fd", "ask"),
    ("web/claude-code-guardrails.html", "git stash drop", "ask"),
    ("web/claude-code-guardrails.html", "rm -rf ~/", "deny"),
    ("web/claude-code-guardrails.html", "rm -rf /usr/local", "deny"),
    ("web/claude-code-guardrails.html", "prisma migrate reset", "ask"),
    ("web/claude-code-guardrails.html", "supabase db reset", "ask"),
    ("web/claude-code-guardrails.html", "pulumi destroy", "ask"),
    ("web/claude-code-guardrails.html", "docker compose down -v", "ask"),
    ("web/claude-code-guardrails.html", "chmod 777", "deny"),
]


@pytest.mark.parametrize(("page", "command", "expected"), DEMOED,
                         ids=[f"{c}" for _, c, _ in DEMOED])
def test_every_command_shown_on_the_site_still_gets_the_verdict_shown(tmp_path_factory, page,
                                                                     command, expected):
    import subprocess

    from provenrail import guard
    from provenrail.easy import load_policy

    text = (ROOT / page).read_text(encoding="utf-8")
    assert command in text, f"{page} no longer shows {command!r}; update this list deliberately"

    # The git rules ask only where there is work to lose, so the claim is checked where there is.
    work = tmp_path_factory.mktemp("demoed")
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=work, check=True)
    (work / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")

    policy = load_policy({"use": guard.DEFAULT_PACKS})
    got = guard.decide(policy, "Bash", {"command": command}, None, str(work))
    assert got["verdict"] == expected, (
        f"{page} shows {command!r} as {expected}, engine says {got['verdict']} ({got['rule']})")
