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
