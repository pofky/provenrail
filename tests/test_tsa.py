"""Hermetic verification of a real RFC 3161 timestamp (captured fixture, no network)."""
import json
import pathlib

from provenrail.trust import root_for_tsa
from provenrail.verifier.verify import verify_bundle

FIX = pathlib.Path(__file__).parent / "fixtures"


def _bundle():
    return json.loads((FIX / "rfc3161_bundle.json").read_text())


def test_real_rfc3161_bundle_verifies():
    rep = verify_bundle(_bundle())
    assert rep.ok, rep.to_dict()
    assert any(f.code == "anchor_rfc3161" for f in rep.findings)


def test_rfc3161_with_pin_verifies():
    pin = json.loads((FIX / "rfc3161_pin.json").read_text())
    rep = verify_bundle(_bundle(), pin=pin)
    assert rep.ok


def test_tampered_merkle_root_fails_tsa_check():
    b = _bundle()
    b["anchors"][0]["receipt"]["merkle_root"] = "00" * 32
    rep = verify_bundle(b)
    assert not rep.ok
    codes = {f.code for f in rep.findings}
    assert "anchor_root_mismatch" in codes or "anchor_imprint_mismatch" in codes


def test_corrupted_token_fails():
    b = _bundle()
    import base64
    tok = bytearray(base64.b64decode(b["anchors"][0]["receipt"]["token_b64"]))
    tok[-20] ^= 0xFF  # flip a byte in the signature region
    b["anchors"][0]["receipt"]["token_b64"] = base64.b64encode(bytes(tok)).decode()
    rep = verify_bundle(b)
    assert not rep.ok


def test_trust_store_knows_freetsa():
    assert root_for_tsa("https://freetsa.org/tsr") is not None
    assert root_for_tsa("https://unknown-tsa.example/tsr") is None
