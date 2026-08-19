"""Extensible TSA trust roots and the failover anchor.

Roots: an operator can register the exact root of a commercial or internal TSA we do not
bundle, so timestamps from it verify, without us shipping a CA we cannot vouch for.
Failover: anchoring tries a list of TSAs and uses the first that responds, so one TSA being
down or rotating its root does not stall anchoring. This is robustness, not multi-proof.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from provenrail import trust
from provenrail.anchor import AnchorReceipt, MultiTSAAnchor

BUNDLED_CERT = Path(trust.__file__).parent / "freetsa_cacert.pem"


# ---- extensible trust roots ----

def test_add_root_by_path_then_resolves():
    try:
        trust.add_root("internal-tsa.corp", str(BUNDLED_CERT))
        cert = trust.root_for_tsa("https://internal-tsa.corp/tsr")
        assert cert is not None and hasattr(cert, "public_bytes")
        assert "internal-tsa.corp" in trust.registered_hosts()
    finally:
        trust._EXTRA_ROOTS.pop("internal-tsa.corp", None)


def test_add_root_by_certificate_object():
    from cryptography import x509
    cert_obj = x509.load_pem_x509_certificate(BUNDLED_CERT.read_bytes())
    try:
        returned = trust.add_root("acme-tsa", cert_obj)
        assert returned is cert_obj
        assert trust.root_for_tsa("https://acme-tsa.example/tsr") is cert_obj
    finally:
        trust._EXTRA_ROOTS.pop("acme-tsa", None)


def test_unknown_tsa_has_no_root():
    assert trust.root_for_tsa("https://nobody-knows-this-tsa.test/tsr") is None
    assert trust.root_for_tsa(None) is None


def test_extra_root_takes_precedence_over_bundled():
    from cryptography import x509
    sentinel = x509.load_pem_x509_certificate(BUNDLED_CERT.read_bytes())
    try:
        trust.add_root("freetsa.org", sentinel)  # override the bundled freetsa root
        assert trust.root_for_tsa("https://freetsa.org/tsr") is sentinel
    finally:
        trust._EXTRA_ROOTS.pop("freetsa.org", None)


# ---- failover anchor ----

def _fake_receipt(url):
    return AnchorReceipt(kind="rfc3161", merkle_root="ab" * 32,
                         gen_time="2026-01-01T00:00:00.000000Z", token_b64="x", tsa_url=url)


def test_failover_uses_first_responding_tsa():
    calls = []

    class _Stub:
        def __init__(self, url):
            self.url = url

        def anchor(self, leaves):
            calls.append(self.url)
            if self.url.endswith("down"):
                raise RuntimeError("TSA down")
            return _fake_receipt(self.url)

    a = MultiTSAAnchor(["https://a.down", "https://b.up", "https://c.up"], _factory=_Stub)
    receipt = a.anchor(["aa" * 32])
    assert receipt.tsa_url == "https://b.up"      # first that responded
    assert calls == ["https://a.down", "https://b.up"]  # c never tried


def test_failover_raises_when_all_fail():
    class _Boom:
        def __init__(self, url):
            pass

        def anchor(self, leaves):
            raise RuntimeError("nope")

    a = MultiTSAAnchor(["https://x", "https://y"], _factory=_Boom)
    with pytest.raises(RuntimeError, match="all 2 TSAs failed"):
        a.anchor(["aa" * 32])


def test_empty_tsa_list_rejected():
    with pytest.raises(ValueError):
        MultiTSAAnchor([])


def test_a_receipt_cannot_display_a_date_its_token_does_not_say():
    """The date beside an RFC 3161 token used to be taken on trust.

    The verifier decoded the token, checked the imprint, validated the certificate chain, and
    then printed `receipt["gen_time"]` as the trusted time. That field is not covered by the
    TSA's signature. An issuer could therefore hand an auditor a receipt whose token said one
    date and whose visible time said another, and the verifier would report the invented one
    under the words "trusted timestamp ... validated" while every cryptographic check passed.

    The point of the RFC 3161 path is that the party being audited does not get to choose the
    date, so the date has to be read out of the signed evidence.
    """
    import copy
    import json
    import pathlib

    from provenrail.verifier.verify import verify_bundle

    bundle = json.loads(
        (pathlib.Path(__file__).parent / "fixtures" / "rfc3161_bundle.json").read_text("utf-8"))

    honest = verify_bundle(copy.deepcopy(bundle))
    assert honest.ok, [f.detail for f in honest.findings if f.severity == "fail"]
    # The reported time comes from the token, so it survives the field being removed entirely.
    reported = [f.detail for f in honest.findings if f.code == "anchor_rfc3161"]
    assert reported, "the trusted-timestamp finding disappeared"

    forged = copy.deepcopy(bundle)
    forged["anchors"][0]["receipt"]["gen_time"] = "2019-01-01T00:00:00.000000Z"
    rep = verify_bundle(forged)
    assert not rep.ok, "a receipt back-dated by seven years still verified"
    codes = {f.code for f in rep.findings}
    assert "anchor_time_mismatch" in codes, codes
    said = " ".join(f.detail for f in rep.findings if f.code == "anchor_time_mismatch")
    assert "2019-01-01" in said and "the token the TSA signed says" in said


def test_padding_the_microseconds_is_not_a_forgery():
    """A TSA that reports whole seconds and a receipt that writes .000000 describe one moment.

    Failing a bundle over trailing zeroes would train operators to ignore anchor_time_mismatch,
    which is the finding that has to be believed the one time it is real.
    """
    import copy
    import json
    import pathlib

    from provenrail.verifier.verify import verify_bundle

    bundle = json.loads(
        (pathlib.Path(__file__).parent / "fixtures" / "rfc3161_bundle.json").read_text("utf-8"))
    same = copy.deepcopy(bundle)
    stamp = same["anchors"][0]["receipt"]["gen_time"]
    assert stamp.endswith(".000000Z")
    same["anchors"][0]["receipt"]["gen_time"] = stamp.replace(".000000Z", "Z")
    rep = verify_bundle(same)
    assert rep.ok, [f.detail for f in rep.findings if f.severity == "fail"]


def test_a_validated_timestamp_is_not_reported_as_a_warning(tmp_path, capsys):
    """`pr anchor-verify` used to bucket findings as fail-or-warning, with no third case.

    The strongest result the command can produce, an RFC 3161 timestamp whose signature and
    certificate chain both validated, is an info-level finding. Printed as [warn] it read as a
    caution about the evidence, to the one audience least able to tell that it was not.
    """
    import json
    import pathlib

    from provenrail.cli import main as cli_main

    src = json.loads((pathlib.Path(__file__).parent / "fixtures" / "rfc3161_bundle.json")
                     .read_text("utf-8"))
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(src), encoding="utf-8")

    anchor = src["anchors"][0]
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps({
        "anchor_id": anchor.get("anchor_id", "anc_fixture"),
        "merkle_root": anchor["receipt"]["merkle_root"],
        "covers_up_to": len(src["records"]),
        "receipt": anchor["receipt"],
    }), encoding="utf-8")

    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(receipt_path)]) == 0
    out = capsys.readouterr().out
    assert "RFC3161 trusted timestamp" in out
    trusted_line = next(ln for ln in out.splitlines() if "RFC3161 trusted timestamp" in ln)
    assert trusted_line.startswith("[info]"), trusted_line
    assert "the time is proved by a third party" in out
