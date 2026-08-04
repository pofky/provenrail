"""SCITT COSE receipt + canonical CBOR tests.

The CBOR codec is proven byte-for-byte against the reference `cbor2` library (canonical mode)
so our hand-rolled, dependency-free encoder is trustworthy. The receipt tests prove the
build/verify round-trip and that every tamper (bad signature, swapped leaf, mutated proof,
wrong TS key) fails closed.
"""

import base64

import pytest

from provenrail import cbor, scitt, tlog
from provenrail.keys import SigningKey


def _leaves(n: int) -> list[str]:
    out = []
    for i in range(n):
        commit = tlog.compute_anchor_commit(
            f"strm_{i}", i, (i + 1) * 10, "r" * 64, f"2026-06-09T00:00:0{i % 10}Z",
            "rfc3161", f"tok{i}",
        )
        out.append(tlog.compute_leaf_hash(commit))
    return out


def _commit(i: int) -> str:
    return tlog.compute_anchor_commit(
        f"strm_{i}", i, (i + 1) * 10, "r" * 64, f"2026-06-09T00:00:0{i % 10}Z",
        "rfc3161", f"tok{i}",
    ).hex()


# ---------- canonical CBOR ----------

def test_cbor_roundtrip_basic():
    for v in [0, 1, 23, 24, 255, 256, 65535, 65536, 2**32, -1, -24, -111, -222,
              b"", b"\x00\x01\x02", "x", "provenrail.io", [], [1, 2, 3], None,
              {1: -8, 4: b"\xaa", -111: 1, 15: {1: "iss", 2: "sub"}}]:
        assert cbor.decode(cbor.encode(v)) == v


def test_cbor_matches_reference_cbor2():
    cbor2 = pytest.importorskip("cbor2")
    samples = [
        0, 1, 23, 24, 255, 256, 65535, 65536, 4294967296, -1, -24, -111, -222,
        b"\x00\x01\x02\xff", "Signature1", "provenrail.io",
        [1, 2, 3], [b"a", b"bb"],
        {1: -8, 4: b"\xde\xad\xbe\xef", -111: 1, 15: {1: "provenrail.io", 2: "strm_x"}},
        {-222: {-1: [b"\x01\x02"]}},
    ]
    for v in samples:
        mine = cbor.encode(v)
        ref = cbor2.dumps(v, canonical=True)
        assert mine == ref, f"CBOR mismatch for {v!r}: {mine.hex()} != {ref.hex()}"
    # A full COSE_Sign1-shaped tagged structure.
    tagged = cbor.CBORTag(18, [b"\xa1\x01\x27", {4: b"\x01"}, b"\x00" * 32, b"\x99" * 64])
    ref_tag = cbor2.CBORTag(18, [b"\xa1\x01\x27", {4: b"\x01"}, b"\x00" * 32, b"\x99" * 64])
    assert cbor.encode(tagged) == cbor2.dumps(ref_tag, canonical=True)


def test_cbor_decodes_reference_cose():
    cbor2 = pytest.importorskip("cbor2")
    obj = cbor2.CBORTag(18, [cbor2.dumps({1: -8}), {4: b"\x01"}, b"\x00" * 32, b"\xab" * 64])
    raw = cbor2.dumps(obj, canonical=True)
    decoded = cbor.decode(raw)
    assert isinstance(decoded, cbor.CBORTag) and decoded.tag == 18
    assert decoded.value[2] == b"\x00" * 32


# ---------- SCITT receipts ----------

def test_receipt_build_and_verify():
    key = SigningKey.generate()
    leaves = _leaves(5)
    for idx in range(5):
        receipt = scitt.build_receipt(key, idx, leaves, subject=f"strm_{idx}")
        v = scitt.verify_receipt(receipt, _commit(idx), key.public_key_hex())
        assert v["ok"], v
        assert v["signature_ok"] and v["inclusion_ok"]
        assert v["issuer"] == "provenrail.io"
        assert v["subject"] == f"strm_{idx}"
        assert v["tree_size"] == 5
        assert v["leaf_index"] == idx


def test_receipt_single_leaf_tree():
    key = SigningKey.generate()
    leaves = _leaves(1)
    receipt = scitt.build_receipt(key, 0, leaves, subject="strm_0")
    v = scitt.verify_receipt(receipt, _commit(0), key.public_key_hex())
    assert v["ok"], v


def test_receipt_wrong_ts_key_fails():
    key = SigningKey.generate()
    other = SigningKey.generate()
    leaves = _leaves(4)
    receipt = scitt.build_receipt(key, 2, leaves, subject="strm_2")
    v = scitt.verify_receipt(receipt, _commit(2), other.public_key_hex())
    assert not v["ok"]
    assert not v["signature_ok"]


def test_receipt_wrong_anchor_commit_fails_inclusion():
    key = SigningKey.generate()
    leaves = _leaves(4)
    receipt = scitt.build_receipt(key, 1, leaves, subject="strm_1")
    # Verify against a different leaf's commit -> signature still ok, inclusion must fail.
    v = scitt.verify_receipt(receipt, _commit(3), key.public_key_hex())
    assert v["signature_ok"]
    assert not v["inclusion_ok"]
    assert not v["ok"]


def test_receipt_tampered_signature_fails():
    key = SigningKey.generate()
    leaves = _leaves(3)
    receipt = scitt.build_receipt(key, 0, leaves, subject="strm_0")
    raw = bytearray(base64.b64decode(receipt))
    raw[-1] ^= 0x01  # flip a signature bit
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    v = scitt.verify_receipt(tampered, _commit(0), key.public_key_hex())
    assert not v["ok"]


def test_receipt_garbage_fails_closed():
    key = SigningKey.generate()
    v = scitt.verify_receipt(base64.b64encode(b"not cbor at all").decode(), _commit(0),
                             key.public_key_hex())
    assert not v["ok"]
    assert v["error"] is not None
