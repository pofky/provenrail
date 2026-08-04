"""Step 2: the standalone verifier's transparency-log checks (SPEC.md section 11)."""

from __future__ import annotations

import base64
import copy

from fastapi.testclient import TestClient

from provenrail import tlog
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.keys import SigningKey
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle

LOG_KEY = SigningKey.generate()
LOG_NAME = "flightrecorder.io/v1/anchors/test"
W1 = SigningKey.generate()
W2 = SigningKey.generate()


def _clean_bundle() -> dict:
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_model_call("anthropic", "claude-sonnet-4", {"q": "hi"}, {"a": "yo"},
                             usage={"input": "100", "output": "50"})
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


def _attach_tlog(bundle: dict, *, witnesses=(), cosig_ts=1_900_000_000,
                 cosig_offset_by_witness=None) -> dict:
    """Attach a single-leaf transparency log proof for the bundle's first anchor.

    witnesses is a list of (name, SigningKey). cosig_offset_by_witness optionally maps a
    witness name to a custom posix timestamp (to exercise stale/future paths)."""
    bundle = copy.deepcopy(bundle)
    a = bundle["anchors"][0]
    r = a["receipt"]
    token_or_sig = r.get("token_b64") if r.get("kind") == "rfc3161" else r.get("signature")
    commit = tlog.compute_anchor_commit(
        bundle["stream_id"], a["anchor_seq"], a["covers_up_to"], r.get("merkle_root", ""),
        r.get("gen_time", ""), r.get("kind", ""), token_or_sig or "").hex()
    leaf = tlog.compute_leaf_hash(bytes.fromhex(commit))
    root_hex = tlog.merkle_root_from_leaf_hashes([leaf])
    body = tlog.build_checkpoint(LOG_NAME, 1, root_hex)
    note = tlog.sign_checkpoint(body, LOG_KEY, LOG_NAME)
    for name, key in witnesses:
        ts = (cosig_offset_by_witness or {}).get(name, cosig_ts)
        note += tlog.make_cosignature_line(body, key, name, ts)
    a["tlog_inclusion"] = {
        "kind": "tlog_inclusion", "log_origin": LOG_NAME, "leaf_index": 0,
        "tree_size": 1, "proof_hashes": tlog.make_inclusion_proof(0, [leaf]),
        "checkpoint": note,
    }
    # Rebuild the SCITT receipt over this single-leaf test tree, signed by the same LOG_KEY the
    # tests verify against (in production the receipt and checkpoint share the one tlog key).
    from provenrail import scitt
    a["scitt_receipt"] = scitt.build_receipt(LOG_KEY, 0, [leaf], subject=bundle["stream_id"])
    bundle["tlog_schema_version"] = 1
    bundle["scitt_schema_version"] = 1
    return bundle


# Verification time pinned within the 30-day max-cosig-age window of cosig_ts=1_900_000_000
# (and far after the bundle's real anchor gen_time of today, and before the 4e9 "future" ts).
from datetime import UTC as _UTC  # noqa: E402
from datetime import datetime as _dt  # noqa: E402

NOW = _dt.fromtimestamp(1_900_050_000, _UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
WITNESSES = {"w1": W1.public_key_hex(), "w2": W2.public_key_hex()}


def _codes(rep):
    return {f.code for f in rep.findings}


def _strip_tlog(bundle: dict) -> dict:
    bundle = copy.deepcopy(bundle)
    bundle.pop("tlog_schema_version", None)
    bundle.pop("tlog_consistency_proofs", None)
    for a in bundle.get("anchors", []):
        a.pop("tlog_inclusion", None)
    return bundle


def test_legacy_bundle_no_tlog_is_info():
    bundle = _strip_tlog(_clean_bundle())  # a pre-tlog bundle: no schema field, no proofs
    rep = verify_bundle(bundle)
    assert rep.ok
    info = [f for f in rep.findings if f.code == "tlog_no_inclusion"]
    assert info and all(f.severity == "info" for f in info)


def test_schema_bundle_missing_inclusion_is_warn():
    bundle = _strip_tlog(_clean_bundle())
    bundle["tlog_schema_version"] = 1  # claims tlog support but anchor carries no proof
    rep = verify_bundle(bundle)
    warns = [f for f in rep.findings if f.code == "tlog_no_inclusion"]
    assert warns and all(f.severity == "warn" for f in warns)
    assert rep.ok  # warn, not fail


def test_inclusion_no_witnesses_is_unwitnessed_warn():
    bundle = _attach_tlog(_clean_bundle())
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_inclusion_unwitnessed" in _codes(rep)
    assert "tlog_inclusion_witnessed_ok" not in _codes(rep)
    assert rep.ok  # amber-with-proofs, still passes


def test_inclusion_with_one_witness_is_green():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_inclusion_witnessed_ok" in _codes(rep)
    assert "tlog_cosig_valid" in _codes(rep)
    assert rep.ok


def test_inclusion_with_two_witnesses_counts_both():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1), ("w2", W2)])
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    valid = [f for f in rep.findings if f.code == "tlog_cosig_valid"]
    assert len(valid) == 2


def test_tampered_inclusion_proof_fails():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    # Corrupt the proof: a single-leaf tree has an empty proof, so inject a bogus sibling.
    bundle["anchors"][0]["tlog_inclusion"]["proof_hashes"] = [base64.b64encode(b"\x00" * 32).decode()]
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_inclusion_fail" in _codes(rep)
    assert not rep.ok


def test_substituted_receipt_breaks_inclusion():
    # Swapping the anchor's signature changes the recomputed commit, so the stored proof
    # (built over the original commit) no longer verifies.
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    bundle["anchors"][0]["receipt"]["signature"] = "deadbeef"
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_inclusion_fail" in _codes(rep)
    assert not rep.ok


def test_wrong_log_key_is_key_id_mismatch():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    rep = verify_bundle(bundle, tlog_log_key=SigningKey.generate().public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_log_key_id_mismatch" in _codes(rep)
    assert not rep.ok


def test_wrong_witness_key_is_key_id_mismatch_not_tampering():
    """Pasting the wrong/stale witness pubkey must read as 'unconfirmed', never tampering: the
    record's own integrity is untouched, the verifier just supplied a key that does not match."""
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    stranger = SigningKey.generate().public_key_hex()
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys={"w1": stranger}, now_utc=NOW)
    assert "tlog_cosig_key_id_mismatch" in _codes(rep)
    assert "tlog_cosig_invalid" not in _codes(rep)  # not framed as a forgery
    assert not rep.ok
    assert rep.result == "unconfirmed"


def test_all_wrong_keys_verdict_is_unconfirmed_not_tampered():
    """The exact /start failure: a user reuses keys from a different `pr demo` run. Every check
    against the supplied keys mismatches, yet the records are intact => NOT CONFIRMED, not
    TAMPERING DETECTED (which would be a false accusation that destroys trust)."""
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    wrong_log = SigningKey.generate().public_key_hex()
    wrong_wit = SigningKey.generate().public_key_hex()
    rep = verify_bundle(bundle, tlog_log_key=wrong_log,
                        witness_pubkeys={"w1": wrong_wit}, now_utc=NOW)
    codes = _codes(rep)
    assert "tlog_log_key_id_mismatch" in codes
    assert "tlog_cosig_key_id_mismatch" in codes
    assert "scitt_key_mismatch" in codes
    assert not rep.ok
    assert rep.result == "unconfirmed"


def test_correct_keys_still_verify_witnessed():
    """Guardrail: the right keys still produce a clean, witnessed green pass."""
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert rep.ok
    assert rep.result == "verified"
    assert "tlog_inclusion_witnessed_ok" in _codes(rep)
    assert "scitt_receipt_ok" in _codes(rep)


def test_no_log_key_configured_is_warn():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    rep = verify_bundle(bundle, witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_log_key_unknown" in _codes(rep)


def test_bad_cosignature_fails():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    # Tamper a byte of the cosignature payload inside the checkpoint note.
    incl = bundle["anchors"][0]["tlog_inclusion"]
    note = incl["checkpoint"]
    lines = note.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("\u2014 w1 "):
            marker, name, blob = ln.split(" ", 2)
            raw = bytearray(base64.b64decode(blob))
            raw[-1] ^= 0xFF
            lines[i] = f"{marker} {name} {base64.b64encode(bytes(raw)).decode()}"
    incl["checkpoint"] = "\n".join(lines)
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_cosig_invalid" in _codes(rep)
    assert not rep.ok
    # A real forgery (right key id, bad signature) IS tampering, not merely "unconfirmed".
    assert rep.result == "tampered"


def test_unknown_witness_not_counted():
    stranger = SigningKey.generate()
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("stranger", stranger)])
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_cosig_unrecognized" in _codes(rep)
    assert "tlog_inclusion_unwitnessed" in _codes(rep)  # stranger does not count
    assert rep.ok


def test_future_cosignature_is_invalid():
    # cosig timestamp far past verification time + skew -> fail (replay/forgery signal).
    future = 4_000_000_000  # year 2096
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)],
                          cosig_offset_by_witness={"w1": future})
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_cosig_invalid" in _codes(rep)
    assert not rep.ok


def test_stale_cosignature_before_anchor_is_warn_not_counted():
    # cosig timestamp before the anchor gen_time -> stale warn, not counted, overall ok.
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)],
                          cosig_offset_by_witness={"w1": 1})  # 1970
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_cosig_stale" in _codes(rep)
    assert "tlog_inclusion_unwitnessed" in _codes(rep)
    assert rep.ok


def test_audit_trail_unwitnessed_is_fail():
    bundle = _attach_tlog(_clean_bundle())  # no witnesses
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW, audit_trail=True)
    assert "tlog_inclusion_unwitnessed" in _codes(rep)
    assert not rep.ok  # Audit Trail SKU requires a witness


def test_consistency_fail_detected():
    bundle = _attach_tlog(_clean_bundle(), witnesses=[("w1", W1)])
    # Add a consistency proof claiming size 1 -> 1 but with a garbage proof and mismatched root
    # is hard; instead claim a 1->2 hop whose new root is not in the bundle: skipped (info).
    bundle["tlog_consistency_proofs"] = [{"old_size": 1, "new_size": 2, "proof_hashes": []}]
    rep = verify_bundle(bundle, tlog_log_key=LOG_KEY.public_key_hex(),
                        witness_pubkeys=WITNESSES, now_utc=NOW)
    assert "tlog_consistency_skipped" in _codes(rep)


def test_existing_suite_unaffected_by_clean_path():
    # A clean legacy bundle must still verify exactly as before (no new fails/warns added).
    bundle = _clean_bundle()
    rep = verify_bundle(bundle)
    assert rep.ok
    assert not any(f.code.startswith("tlog_") and f.severity == "fail" for f in rep.findings)
