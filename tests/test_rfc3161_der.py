"""The hosted service's own RFC 3161 code, checked against Python's on real bytes.

The anchor service runs on Deno, where rfc3161-client does not exist, so it encodes the timestamp
request and reads the signed time back out with about a hundred lines of hand-written DER. Hand-
written DER that is only exercised by the code that wrote it is how a service ends up storing
tokens nobody can verify, and finding out when an auditor tries.

So these run the service's actual module (not a copy of it) under Node, against the same real
FreeTSA token the Python verifier is tested with, and require the two to agree.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).parent
RUNNER = HERE / "js" / "parse_tsr.mjs"
FIXTURE = HERE / "fixtures" / "rfc3161_bundle.json"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _node(payload: dict) -> dict:
    res = subprocess.run(["node", str(RUNNER), json.dumps(payload)],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(res.stdout)


def _receipt() -> dict:
    return json.loads(FIXTURE.read_text("utf-8"))["anchors"][0]["receipt"]


def test_the_service_reads_the_same_signed_time_python_does():
    """The time an auditor is shown comes out of the token. If the two implementations disagree
    about where it is, one of them is showing a date the authority did not sign."""
    from rfc3161_client import decode_timestamp_response

    receipt = _receipt()
    raw = base64.b64decode(receipt["token_b64"])
    tst = decode_timestamp_response(raw)

    from datetime import UTC
    python_time = tst.tst_info.gen_time.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    node_time = _node({"token_b64": receipt["token_b64"]})["genTime"]
    assert node_time == python_time


def test_the_service_reads_the_same_imprint_python_does():
    """The imprint is the only thing tying the signed time to a particular chain. The service
    refuses to store a token whose imprint is not the digest it sent, so it has to find the same
    bytes there that the verifier will later compare against."""
    receipt = _receipt()
    expected = hashlib.sha512(bytes.fromhex(receipt["merkle_root"])).hexdigest()
    assert _node({"token_b64": receipt["token_b64"]})["imprintHex"] == expected


def test_the_request_it_builds_is_the_request_python_builds():
    """Encoded by hand against a library that has done this for years. A malformed request is not
    a silent failure (the authority rejects it), but a subtly wrong one, certReq dropped, is: the
    token comes back without the signing certificate and quietly stops chaining to a trusted root.
    """
    from rfc3161_client import TimestampRequestBuilder

    data = b"provenrail rfc3161 encoding check"
    digest = hashlib.sha512(data).digest()
    reference = TimestampRequestBuilder().data(data).build().as_bytes()

    ours = bytes.fromhex(_node({"request_for": digest.hex(), "nonce": "0011223344556677"})["der"])

    # The nonce differs by design (it is random), so compare everything around it: the version,
    # the SHA-256 algorithm identifier, the imprint, and the certReq flag that actually matters.
    assert ours[0] == 0x30, "a TimeStampReq is a DER SEQUENCE"
    sha512_oid = bytes.fromhex("0609608648016503040203")
    assert sha512_oid in ours, "SHA-512 algorithm identifier missing"
    assert sha512_oid in reference, "the reference builder changed its imprint algorithm"
    assert digest in ours, "the imprint is not the digest we asked for"
    assert digest in reference
    assert ours.endswith(bytes.fromhex("0101ff")), "certReq TRUE is not set"
    assert reference.endswith(bytes.fromhex("0101ff")), "the reference builder changed certReq"


@pytest.mark.parametrize("gt,iso", [
    ("20260819054417Z", "2026-08-19T05:44:17.000000Z"),
    ("20260819054417.5Z", "2026-08-19T05:44:17.500000Z"),
    ("20260819054417.123456Z", "2026-08-19T05:44:17.123456Z"),
])
def test_generalized_time_becomes_the_shape_the_receipt_carries(gt, iso):
    """A TSA may report whole seconds or fractions. Both have to land in the microsecond form the
    rest of the system writes, or the verifier's time cross-check fires on formatting."""
    assert _node({"gentime": gt})["iso"] == iso
