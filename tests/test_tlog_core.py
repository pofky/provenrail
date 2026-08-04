"""Step 1: transparency-log core crypto and storage atomicity.

Proofs are generated with the recursive RFC 6962 PATH/PROOF spec and verified with the
independent iterative verification spec, so a passing roundtrip cross-checks two separate
implementations of the same algorithm.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from provenrail import tlog
from provenrail.anchor import _leaf
from provenrail.keys import SigningKey
from provenrail.server.storage import Storage


def _commit(i: int, token: str = "tok") -> bytes:
    return tlog.compute_anchor_commit("s1", i, i, "ab" * 32, "2026-06-08T00:00:00.000000Z",
                                      "rfc3161", token)


def _leaves(n: int) -> list[str]:
    return [tlog.compute_leaf_hash(_commit(i)) for i in range(n)]


def test_leaf_hash_domain_separation():
    # The same 32 bytes hashed as a per-stream anchor leaf vs a tlog leaf must differ.
    commit = _commit(0)
    tlog_leaf = tlog.compute_leaf_hash(commit)
    anchor_leaf = _leaf(commit).hex()
    assert tlog_leaf != anchor_leaf


def test_anchor_commit_binds_receipt():
    # Two anchors identical except for the RFC 3161 token bytes must commit differently.
    a = tlog.compute_anchor_commit("s", 0, 0, "cd" * 32, "t", "rfc3161", "tokenA")
    b = tlog.compute_anchor_commit("s", 0, 0, "cd" * 32, "t", "rfc3161", "tokenB")
    assert a != b
    assert tlog.compute_leaf_hash(a) != tlog.compute_leaf_hash(b)


def test_merkle_root_empty():
    assert tlog.merkle_root_from_leaf_hashes([]) == hashlib.sha256(b"").hexdigest()
    assert tlog.merkle_root_from_leaf_hashes([]) == tlog.EMPTY_ROOT


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31])
def test_inclusion_proof_roundtrip(n):
    leaves = _leaves(n)
    root_b64 = base64.b64encode(bytes.fromhex(tlog.merkle_root_from_leaf_hashes(leaves))).decode()
    for i in range(n):
        proof = tlog.make_inclusion_proof(i, leaves)
        assert tlog.verify_inclusion(_commit(i).hex(), i, n, proof, root_b64)
    # A proof for the wrong index must fail.
    if n > 1:
        proof0 = tlog.make_inclusion_proof(0, leaves)
        assert not tlog.verify_inclusion(_commit(1).hex(), 1, n, proof0, root_b64)


@pytest.mark.parametrize("m,n", [(1, 4), (2, 4), (3, 7), (4, 7), (1, 8), (5, 9), (6, 16)])
def test_consistency_proof_roundtrip(m, n):
    leaves = _leaves(n)
    old_root = base64.b64encode(
        bytes.fromhex(tlog.merkle_root_from_leaf_hashes(leaves[:m]))).decode()
    new_root = base64.b64encode(
        bytes.fromhex(tlog.merkle_root_from_leaf_hashes(leaves))).decode()
    proof = tlog.make_consistency_proof(m, n, leaves)
    assert tlog.verify_consistency(m, old_root, n, new_root, proof)
    # A tampered proof hash must fail.
    if proof:
        bad = list(proof)
        bad[0] = base64.b64encode(b"\x00" * 32).decode()
        assert not tlog.verify_consistency(m, old_root, n, new_root, bad)


def test_consistency_proof_detects_fork():
    # Two trees that diverge at index 3 are not consistent.
    base = _leaves(5)
    forked = list(base)
    forked[3] = tlog.compute_leaf_hash(_commit(3, token="EVIL"))
    old_root = base64.b64encode(
        bytes.fromhex(tlog.merkle_root_from_leaf_hashes(base[:3]))).decode()
    forked_root = base64.b64encode(
        bytes.fromhex(tlog.merkle_root_from_leaf_hashes(forked))).decode()
    # Proof built against the honest tree cannot prove the forked tree extends base[:3].
    proof = tlog.make_consistency_proof(3, 5, base)
    assert not tlog.verify_consistency(3, old_root, 5, forked_root, proof)


def test_checkpoint_body_format():
    body = tlog.build_checkpoint("flightrecorder.io/v1/anchors/acct", 5, "ab" * 32)
    lines = body.split("\n")
    assert lines[0] == "flightrecorder.io/v1/anchors/acct"
    assert lines[1] == "5"
    assert base64.b64decode(lines[2]) == bytes.fromhex("ab" * 32)
    assert body.endswith("\n")


def test_sign_and_parse_note():
    key = SigningKey.generate()
    name = "flightrecorder.io/v1/anchors/acct"
    body = tlog.build_checkpoint(name, 3, "cd" * 32)
    note = tlog.sign_checkpoint(body, key, name)
    parsed = tlog.parse_signed_note(note)
    assert parsed["body"] == body
    assert len(parsed["signatures"]) == 1
    sig = parsed["signatures"][0]
    assert sig["key_name"] == name
    assert tlog.verify_log_signature(body, sig["payload"], key.public_key_hex(), name) == "ok"


def test_log_signature_key_id_mismatch():
    key = SigningKey.generate()
    other = SigningKey.generate()
    name = "log"
    body = tlog.build_checkpoint(name, 1, "ef" * 32)
    note = tlog.sign_checkpoint(body, key, name)
    parsed = tlog.parse_signed_note(note)
    payload = parsed["signatures"][0]["payload"]
    # Verifying against the wrong pubkey: the key_id won't match -> key_id_mismatch (hard fail).
    assert tlog.verify_log_signature(body, payload, other.public_key_hex(), name) == "key_id_mismatch"


def test_verify_cosignature():
    wkey = SigningKey.generate()
    wname = "witness-1"
    body = tlog.build_checkpoint("log", 4, "12" * 32)
    line = tlog.make_cosignature_line(body, wkey, wname, 1_700_000_000)
    note = body + "\n" + line
    parsed = tlog.parse_signed_note(note)
    cosig = parsed["signatures"][0]
    valid, ts = tlog.verify_cosignature(cosig["payload"], wkey.public_key_hex(), body, wname)
    assert valid and ts == 1_700_000_000
    # Mutating the body breaks the cosignature.
    valid2, _ = tlog.verify_cosignature(cosig["payload"], wkey.public_key_hex(),
                                        body.replace("4", "5", 1), wname)
    assert not valid2


def test_parse_note_with_log_sig_and_cosignatures():
    lk, w1, w2 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    body = tlog.build_checkpoint("log", 2, "ab" * 32)
    note = tlog.sign_checkpoint(body, lk, "log")
    note += tlog.make_cosignature_line(body, w1, "w1", 1_700_000_001)
    note += tlog.make_cosignature_line(body, w2, "w2", 1_700_000_002)
    parsed = tlog.parse_signed_note(note)
    assert parsed["body"] == body
    names = [s["key_name"] for s in parsed["signatures"]]
    assert names == ["log", "w1", "w2"]


def test_storage_appends_tlog_leaf_with_anchor():
    st = Storage(":memory:")
    st.create_account("acct", "h")
    st.create_stream("s1", owner_account="acct")
    receipt = {"kind": "local", "merkle_root": "ab" * 32, "gen_time": "t", "signature": "sig",
               "anchor_pubkey": "pk"}
    seq = st.store_anchor("s1", receipt, covers_up_to=0)
    assert seq == 0
    origin = st.origin_for_stream("s1", tlog.DEFAULT_ORIGIN_PREFIX)
    assert origin.endswith("/acct")
    assert st.tlog_size(origin) == 1
    leaf = st.find_tlog_leaf(origin, "s1", 0)
    assert leaf is not None and leaf["leaf_index"] == 0


def test_storage_atomicity_rolls_back_both_rows(monkeypatch):
    # Simulate a crash after the anchor INSERT but before the tlog leaf is hashed/inserted:
    # the whole transaction must roll back so no orphan anchor is left out of the log.
    st = Storage(":memory:")
    st.create_stream("s1", owner_account=None)
    receipt = {"kind": "local", "merkle_root": "ab" * 32, "gen_time": "t", "signature": "x"}

    def boom(_commit_bytes):
        raise RuntimeError("simulated crash between inserts")

    monkeypatch.setattr(tlog, "compute_leaf_hash", boom)
    with pytest.raises(RuntimeError):
        st.store_anchor("s1", receipt, covers_up_to=0)
    # Neither the anchor nor the leaf should have committed.
    assert st.get_anchors("s1") == []
    assert st.tlog_size(st.origin_for_stream("s1", tlog.DEFAULT_ORIGIN_PREFIX)) == 0


def test_append_tlog_leaf_uniqueness():
    st = Storage(":memory:")
    st.create_stream("s1")
    receipt = {"kind": "local", "merkle_root": "ab" * 32, "gen_time": "t", "signature": "x"}
    st.store_anchor("s1", receipt, covers_up_to=0)
    # Forcing a duplicate (anchor_stream_id, anchor_seq) violates the UNIQUE constraint.
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        st._db.execute(
            "INSERT INTO tlog_leaves(log_origin, leaf_index, anchor_stream_id, anchor_seq, "
            "covers_up_to, anchor_commit, leaf_hash, added_at) VALUES (?,?,?,?,?,?,?,?)",
            ("o", 99, "s1", 0, 0, "c", "h", "t"))
        st._db.commit()


def test_tlog_leaves_append_only_trigger():
    st = Storage(":memory:")
    st.create_stream("s1")
    st.store_anchor("s1", {"kind": "local", "merkle_root": "a" * 64, "gen_time": "t",
                           "signature": "x"}, covers_up_to=0)
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        st._db.execute("UPDATE tlog_leaves SET leaf_hash='z'")
    with pytest.raises(sqlite3.IntegrityError):
        st._db.execute("DELETE FROM tlog_leaves")
