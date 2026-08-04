"""OpenTimestamps (Bitcoin) proof verification.

Two layers of assurance:

1. A FROZEN real .ots proof (built once with the reference `opentimestamps` library) is parsed and
   verified by our dependency-free verifier with no library present. This locks the on-wire format
   and our verification behavior the same way tests/vectors/ locks the bundle format.
2. A live cross-implementation conformance check: when the reference library is installed, we build
   fresh proofs with it, serialize, and confirm our parser recovers the identical block height and
   Merkle root. This proves we track the real OpenTimestamps format, not only our own fixture.
"""

from __future__ import annotations

import hashlib

import pytest

from provenrail import ots

# A real detached .ots proof produced by the reference opentimestamps library: a SHA-256 file
# digest, an append/prepend/double-sha256 path to a Bitcoin block Merkle root, one Bitcoin block
# header attestation at height 812345, and one pending calendar attestation on the root node.
_FROZEN_OTS_HEX = (
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401083d950d169fa50ca4b2"
    "e329680f93ac60f0289b4c20047620807421efa48cbe2fff0083dfe30d2ef90c8e2e2d68747470733a2f"
    "2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267f0050102"
    "030405f103aabbcc0808000588960d73d7190103b9ca31"
)
_FROZEN_DATA_SHA256 = "3d950d169fa50ca4b2e329680f93ac60f0289b4c20047620807421efa48cbe2f"
_FROZEN_MERKLE_ROOT = "3ec6bc2d3a279449244f2a4334cba1291a77413cb92f897bd3f936ded6b9ada4"
_FROZEN_HEIGHT = 812345


def _frozen() -> bytes:
    return bytes.fromhex(_FROZEN_OTS_HEX)


def test_parse_frozen_proof():
    parsed = ots.parse_ots(_frozen())
    assert parsed["file_digest_hex"] == _FROZEN_DATA_SHA256
    assert parsed["bitcoin"] == [{"height": _FROZEN_HEIGHT, "merkle_root_hex": _FROZEN_MERKLE_ROOT}]
    assert parsed["pending"] == ["https://alice.btc.calendar.opentimestamps.org"]


def test_verify_confirmed_against_trusted_header():
    v = ots.verify_ots(_frozen(), _FROZEN_DATA_SHA256,
                       bitcoin_block_merkle_roots={_FROZEN_HEIGHT: _FROZEN_MERKLE_ROOT})
    assert v["ok"] is True
    assert v["data_matches"] is True
    assert v["bitcoin_attested"] is True
    assert v["bitcoin"][0]["confirmed"] is True


def test_verify_accepts_reversed_byte_order():
    """Block explorers display the Merkle root reversed; the verifier accepts either order."""
    reversed_root = bytes.fromhex(_FROZEN_MERKLE_ROOT)[::-1].hex()
    v = ots.verify_ots(_frozen(), _FROZEN_DATA_SHA256,
                       bitcoin_block_merkle_roots={_FROZEN_HEIGHT: reversed_root})
    assert v["ok"] is True and v["bitcoin"][0]["confirmed"] is True


def test_verify_without_headers_is_attested_but_not_ok():
    """No trusted header supplied: structurally valid and Bitcoin-attested, but we refuse to
    assert a Bitcoin fact we did not check, so ok stays False."""
    v = ots.verify_ots(_frozen(), _FROZEN_DATA_SHA256)
    assert v["structurally_valid"] is True
    assert v["bitcoin_attested"] is True
    assert v["bitcoin"][0]["confirmed"] is None
    assert v["ok"] is False


def test_verify_wrong_data_fails():
    v = ots.verify_ots(_frozen(), hashlib.sha256(b"different").hexdigest(),
                       bitcoin_block_merkle_roots={_FROZEN_HEIGHT: _FROZEN_MERKLE_ROOT})
    assert v["data_matches"] is False and v["ok"] is False


def test_verify_wrong_header_fails():
    v = ots.verify_ots(_frozen(), _FROZEN_DATA_SHA256,
                       bitcoin_block_merkle_roots={_FROZEN_HEIGHT: "00" * 32})
    assert v["bitcoin"][0]["confirmed"] is False and v["ok"] is False


def test_tampered_proof_changes_root_or_fails():
    raw = bytearray(_frozen())
    # Flip a byte inside the appended argument (0102030405); the replayed root must change.
    idx = raw.find(bytes.fromhex("0102030405"))
    assert idx != -1
    raw[idx] ^= 0x01
    v = ots.verify_ots(bytes(raw), _FROZEN_DATA_SHA256,
                       bitcoin_block_merkle_roots={_FROZEN_HEIGHT: _FROZEN_MERKLE_ROOT})
    assert v["ok"] is False


def test_bad_magic_fails():
    v = ots.verify_ots(b"not an ots proof at all, definitely", _FROZEN_DATA_SHA256)
    assert v["structurally_valid"] is False and v["error"]


def test_truncated_fails():
    v = ots.verify_ots(_frozen()[:40], _FROZEN_DATA_SHA256)
    assert v["structurally_valid"] is False and v["ok"] is False


# --- live conformance against the reference library -------------------------------------------

def _build_with_lib(height: int, data: bytes):
    ots_lib = pytest.importorskip("opentimestamps")  # noqa: F841
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpPrepend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    file_digest = hashlib.sha256(data).digest()
    ts = Timestamp(file_digest)
    ts.attestations.add(PendingAttestation("https://calendar.example.org"))
    o1 = OpAppend(b"\x11\x22")
    m1 = o1(file_digest)
    t1 = Timestamp(m1)
    ts.ops[o1] = t1
    o2 = OpPrepend(b"\x33")
    m2 = o2(m1)
    t2 = Timestamp(m2)
    t1.ops[o2] = t2
    o3 = OpSHA256()
    m3 = o3(m2)
    t3 = Timestamp(m3)
    t2.ops[o3] = t3
    t3.attestations.add(BitcoinBlockHeaderAttestation(height))
    detached = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes(), file_digest.hex(), m3.hex()


def test_conformance_with_reference_library():
    pytest.importorskip("opentimestamps")
    for height in (1, 127, 128, 300000, 812345):
        ots_bytes, data_hex, root_hex = _build_with_lib(height, f"sample {height}".encode())
        parsed = ots.parse_ots(ots_bytes)
        assert parsed["file_digest_hex"] == data_hex
        assert parsed["bitcoin"] == [{"height": height, "merkle_root_hex": root_hex}]
        assert "https://calendar.example.org" in parsed["pending"]
        v = ots.verify_ots(ots_bytes, data_hex, bitcoin_block_merkle_roots={height: root_hex})
        assert v["ok"] is True
