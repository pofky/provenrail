"""Cross-implementation conformance: the JavaScript verifier (web/verify.js) must agree with
the Python verifier on clean and tampered bundles. Run via Node; skipped if Node is absent.

That the JS verifier reports a *clean* bundle as ok already proves byte-for-byte
canonicalization agreement: any divergence would surface as a hash mismatch.
"""
import copy
import json
import pathlib
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from provenrail import GENESIS_PREV_HASH
from provenrail.anchor import LocalAnchor
from provenrail.canonical import canonicalize, sha256_hex
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app

HERE = pathlib.Path(__file__).parent
CONFORMANCE = HERE / "js" / "conformance.mjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _clean_bundle_and_pin(tmp_path):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    pin_file = tmp_path / "src_pin.json"
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        pin_path=str(pin_file))

    @fr.tool("search")
    def search(q):
        return {"hits": 2}

    with fr.session({"agent": "demo", "task": "résumé café"}):
        fr.record_model_call("anthropic", "claude-opus-4-8", {"prompt": "café"}, {"text": "ok"},
                             usage={"input": "10", "output": "5"})
        search("x")
        fr.record_decision("proceed")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    pin = json.loads(pin_file.read_text())
    return bundle, pin


def test_js_verifier_matches_python(tmp_path):
    bundle, pin = _clean_bundle_and_pin(tmp_path)

    # tampered variants
    edit = copy.deepcopy(bundle)
    edit["records"][1]["record"]["payload"]["model"] = "evil"

    deletion = copy.deepcopy(bundle)
    del deletion["records"][2]

    rechain = copy.deepcopy(bundle)
    del rechain["records"][2]
    prev = GENESIS_PREV_HASH
    for i, sr in enumerate(rechain["records"]):
        sr["recv_seq"] = i
        sr["recv_hash"] = sha256_hex(canonicalize(sr["record"]))
        sr["server_prev_hash"] = prev
        sr["server_record_hash"] = sha256_hex(canonicalize(
            {"recv_seq": i, "recv_ts": sr["recv_ts"], "recv_hash": sr["recv_hash"],
             "server_prev_hash": prev}))
        prev = sr["server_record_hash"]

    truncated = copy.deepcopy(bundle)
    truncated["records"] = truncated["records"][:2]

    cases = {
        "clean.json": bundle,
        "edit.json": edit,
        "deletion.json": deletion,
        "rechain.json": rechain,
        "truncated.json": truncated,
        "pin.json": pin,
    }
    for name, obj in cases.items():
        (tmp_path / name).write_text(json.dumps(obj), encoding="utf-8")

    manifest = [
        {"name": "clean", "bundle": "clean.json", "expect_ok": True, "codes": ["local_anchor_only"]},
        {"name": "clean_with_pin", "bundle": "clean.json", "pin": "pin.json",
         "expect_ok": True, "codes": ["pin_ok"]},
        {"name": "content_edit", "bundle": "edit.json", "expect_ok": False,
         "codes": ["client_hash_mismatch"]},
        {"name": "deletion", "bundle": "deletion.json", "expect_ok": False},
        {"name": "coherent_rechain", "bundle": "rechain.json", "expect_ok": False,
         "codes": ["client_broken_link"]},
        {"name": "tail_truncation", "bundle": "truncated.json", "pin": "pin.json",
         "expect_ok": False, "codes": ["pin_truncated"]},
    ]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = subprocess.run(["node", str(CONFORMANCE), str(manifest_path)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS clean " in result.stdout


def _witnessed_bundle(tmp_path, with_witness=True):
    """A server-produced bundle carrying tlog inclusion (and a cosignature if with_witness)."""
    from provenrail.server.witness import LocalWitness
    witness = LocalWitness("witness-A", clock=lambda: 1_900_000_000)
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     tlog_witnesses=[witness] if with_witness else [])
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo", "task": "café"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    meta = c.get("/v1/meta").json()
    return bundle, meta["tlog_pubkey"], witness


def test_js_verifier_tlog_conformance(tmp_path):
    import copy as _copy
    from datetime import UTC, datetime

    from provenrail.verifier.verify import verify_bundle

    now = datetime.fromtimestamp(1_900_050_000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    witnessed, log_pubkey, witness = _witnessed_bundle(tmp_path, with_witness=True)
    unwitnessed, log_pubkey2, _ = _witnessed_bundle(tmp_path, with_witness=False)
    bad = _copy.deepcopy(witnessed)
    import base64 as _b64
    bad["anchors"][0]["tlog_inclusion"]["proof_hashes"] = [_b64.b64encode(b"\x00" * 32).decode()]

    wpk = {"witness-A": witness.public_key_hex()}
    # Python side must produce the expected codes (so the JS comparison is true conformance).
    rep_w = verify_bundle(witnessed, tlog_log_key=log_pubkey, witness_pubkeys=wpk, now_utc=now)
    assert "tlog_inclusion_witnessed_ok" in {f.code for f in rep_w.findings} and rep_w.ok
    rep_u = verify_bundle(unwitnessed, tlog_log_key=log_pubkey2, witness_pubkeys=wpk, now_utc=now)
    assert "tlog_inclusion_unwitnessed" in {f.code for f in rep_u.findings} and rep_u.ok
    rep_b = verify_bundle(bad, tlog_log_key=log_pubkey, witness_pubkeys=wpk, now_utc=now)
    assert not rep_b.ok

    for name, obj in {"w.json": witnessed, "u.json": unwitnessed, "b.json": bad}.items():
        (tmp_path / name).write_text(json.dumps(obj), encoding="utf-8")
    manifest = [
        {"name": "tlog_witnessed", "bundle": "w.json", "expect_ok": True,
         "codes": ["tlog_inclusion_witnessed_ok", "tlog_cosig_valid"],
         "tlog_log_key": log_pubkey, "witness_pubkeys": wpk, "now_utc": now},
        {"name": "tlog_unwitnessed", "bundle": "u.json", "expect_ok": True,
         "codes": ["tlog_inclusion_unwitnessed"],
         "tlog_log_key": log_pubkey2, "witness_pubkeys": wpk, "now_utc": now},
        {"name": "tlog_bad_proof", "bundle": "b.json", "expect_ok": False,
         "codes": ["tlog_inclusion_fail"],
         "tlog_log_key": log_pubkey, "witness_pubkeys": wpk, "now_utc": now},
    ]
    mpath = tmp_path / "tlog_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS tlog conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS tlog_witnessed " in result.stdout


def test_js_verifier_redaction_conformance(tmp_path):
    """The JS verifier must recompute the same salted commitments and reach the same disclosure
    verdict as Python: a valid opening verifies, a forged one is a hard fail, in BOTH verifiers."""
    import provenrail as fr
    from provenrail.verifier.verify import verify_bundle

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    rec = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with rec.session({"agent": "phi"}):
        rec.record_decision("done", note=fr.redactable("SSN 078-05-1120 café"))
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    openings = rec.openings()
    c0 = next(iter(openings))
    forged = {c0: {"alg": "sha256", "salt": openings[c0]["salt"], "value": "WRONG"}}

    # Python side establishes the expected verdicts (true cross-impl conformance).
    assert verify_bundle(bundle, disclosure_openings=openings).ok
    assert not verify_bundle(bundle, disclosure_openings=forged).ok

    (tmp_path / "r.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [
        {"name": "redaction_disclosed", "bundle": "r.json", "expect_ok": True,
         "codes": ["redaction_summary"], "openings": openings},
        {"name": "redaction_forged", "bundle": "r.json", "expect_ok": False,
         "codes": ["redaction_disclosure_invalid"], "openings": forged},
    ]
    mpath = tmp_path / "redaction_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS redaction conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS redaction_disclosed " in result.stdout
    assert "PASS redaction_forged " in result.stdout


def test_js_verifier_scitt_conformance(tmp_path):
    """SCITT COSE receipts (step 13) must verify identically in JS and Python: a genuine
    receipt verifies against the transparency-service key; a receipt with a corrupted COSE
    signature is a hard fail, in BOTH verifiers. This keeps the standards-aligned receipt
    inside the two-implementation lockstep, not only the base chain."""
    import base64 as _b64
    from datetime import UTC, datetime

    from provenrail.verifier.verify import verify_bundle

    now = datetime.fromtimestamp(1_900_050_000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    good, log_pubkey, witness = _witnessed_bundle(tmp_path, with_witness=True)
    assert good["anchors"] and good["anchors"][0].get("scitt_receipt"), \
        "server must emit a SCITT receipt per anchor"

    forged = copy.deepcopy(good)
    raw = bytearray(_b64.b64decode(forged["anchors"][0]["scitt_receipt"]))
    raw[-1] ^= 0x01  # flip the last byte of the COSE_Sign1 signature
    forged["anchors"][0]["scitt_receipt"] = _b64.b64encode(bytes(raw)).decode()

    wpk = {"witness-A": witness.public_key_hex()}
    rep_g = verify_bundle(good, tlog_log_key=log_pubkey, witness_pubkeys=wpk, now_utc=now)
    assert "scitt_receipt_ok" in {f.code for f in rep_g.findings} and rep_g.ok
    rep_f = verify_bundle(forged, tlog_log_key=log_pubkey, witness_pubkeys=wpk, now_utc=now)
    assert "scitt_receipt_invalid" in {f.code for f in rep_f.findings} and not rep_f.ok

    for name, obj in {"sg.json": good, "sf.json": forged}.items():
        (tmp_path / name).write_text(json.dumps(obj), encoding="utf-8")
    manifest = [
        {"name": "scitt_valid", "bundle": "sg.json", "expect_ok": True,
         "codes": ["scitt_receipt_ok"], "tlog_log_key": log_pubkey,
         "witness_pubkeys": wpk, "now_utc": now},
        {"name": "scitt_forged", "bundle": "sf.json", "expect_ok": False,
         "codes": ["scitt_receipt_invalid"], "tlog_log_key": log_pubkey,
         "witness_pubkeys": wpk, "now_utc": now},
    ]
    mpath = tmp_path / "scitt_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS SCITT conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS scitt_valid " in result.stdout
    assert "PASS scitt_forged " in result.stdout


def test_js_verifier_wrong_keys_are_unconfirmed_not_tampered(tmp_path):
    """Lockstep on the verdict semantics, not just pass/fail: when the verifier supplies the
    WRONG transparency-log / witness keys for an otherwise-intact bundle, BOTH Python and JS
    must report result='unconfirmed' (a key mismatch), never 'tampered'. This is the /start
    reuse-stale-keys footgun; reading it as tampering would be a false accusation."""
    from datetime import UTC, datetime

    from provenrail.keys import SigningKey
    from provenrail.verifier.verify import verify_bundle

    now = datetime.fromtimestamp(1_900_050_000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    good, log_pubkey, witness = _witnessed_bundle(tmp_path, with_witness=True)
    wrong_log = SigningKey.generate().public_key_hex()
    wrong_wit = {"witness-A": SigningKey.generate().public_key_hex()}

    rep = verify_bundle(good, tlog_log_key=wrong_log, witness_pubkeys=wrong_wit, now_utc=now)
    assert rep.result == "unconfirmed" and not rep.ok  # Python side

    (tmp_path / "wk.json").write_text(json.dumps(good), encoding="utf-8")
    manifest = [{"name": "wrong_keys", "bundle": "wk.json", "expect_ok": False,
                 "expect_result": "unconfirmed", "tlog_log_key": wrong_log,
                 "witness_pubkeys": wrong_wit, "now_utc": now,
                 "codes": ["tlog_log_key_id_mismatch", "tlog_cosig_key_id_mismatch",
                           "scitt_key_mismatch"]}]
    mpath = tmp_path / "wrong_keys_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS wrong-key conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS wrong_keys " in result.stdout


def test_js_verifier_matches_frozen_vectors(tmp_path):
    """The JS verifier must reach the manifest verdict on every FROZEN conformance vector,
    including the full-spec ones (witnessed tlog, SCITT receipt, redaction). This makes the
    public vector suite a two-implementation contract, not a Python-only one."""
    import shutil as _shutil

    vectors = HERE / "vectors"
    manifest = json.loads((vectors / "manifest.json").read_text(encoding="utf-8"))

    js_manifest = []
    for name, spec in manifest.items():
        _shutil.copy(vectors / spec["file"], tmp_path / spec["file"])
        ctx = spec.get("verify") or {}
        entry = {
            "name": name,
            "bundle": spec["file"],
            "expect_ok": spec["expect_ok"],
            "codes": [spec["defining_code"]] if spec.get("defining_code") else [],
        }
        if ctx.get("tlog_log_key"):
            entry["tlog_log_key"] = ctx["tlog_log_key"]
        if ctx.get("witness_pubkeys"):
            entry["witness_pubkeys"] = ctx["witness_pubkeys"]
        if ctx.get("now_utc"):
            entry["now_utc"] = ctx["now_utc"]
        if ctx.get("openings"):
            entry["openings"] = ctx["openings"]
        js_manifest.append(entry)

    mpath = tmp_path / "frozen_manifest.json"
    mpath.write_text(json.dumps(js_manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS frozen-vector conformance failed:\n{result.stdout}\n{result.stderr}"
    # Every vector must have passed.
    assert "FAIL" not in result.stdout, result.stdout


def test_js_verifier_ots_conformance(tmp_path):
    """OpenTimestamps (Bitcoin) proofs over a checkpoint root (step 14) must verify identically in
    Python and JS: a proof confirmed against a trusted header reports ots_bitcoin_confirmed and
    keeps the bundle ok; a proof contradicting the trusted header is a hard fail in BOTH verifiers.
    This keeps Bitcoin anchoring inside the two-implementation lockstep."""
    pytest.importorskip("opentimestamps")
    import base64 as _b64
    import hashlib as _hl

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    from provenrail.verifier.verify import verify_bundle

    bundle, _pin = _clean_bundle_and_pin(tmp_path)

    # Stamp a (raw 32-byte) checkpoint root: the OTS file is the root, so file_digest = sha256(root).
    root = _hl.sha256(b"provenrail checkpoint root vector").digest()
    root_hex = root.hex()
    height = 850000
    file_digest = _hl.sha256(root).digest()
    ts = Timestamp(file_digest)
    o1 = OpAppend(b"\xab")
    m1 = o1(file_digest)
    t1 = Timestamp(m1)
    ts.ops[o1] = t1
    o2 = OpSHA256()
    m2 = o2(m1)
    t2 = Timestamp(m2)
    t1.ops[o2] = t2
    merkle_hex = m2.hex()
    t2.attestations.add(BitcoinBlockHeaderAttestation(height))
    detached = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    ots_b64 = _b64.b64encode(ctx.getbytes()).decode()

    bundle["ots_proofs"] = [{"tree_size": 1, "root_hex": root_hex, "ots_b64": ots_b64}]

    good_headers = {height: merkle_hex}
    bad_headers = {height: "00" * 32}

    rep_ok = verify_bundle(bundle, bitcoin_headers=good_headers)
    assert "ots_bitcoin_confirmed" in {f.code for f in rep_ok.findings} and rep_ok.ok
    rep_bad = verify_bundle(bundle, bitcoin_headers=bad_headers)
    assert "ots_block_mismatch" in {f.code for f in rep_bad.findings} and not rep_bad.ok

    (tmp_path / "ots.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [
        {"name": "ots_confirmed", "bundle": "ots.json", "expect_ok": True,
         "codes": ["ots_bitcoin_confirmed"], "bitcoin_headers": {str(height): merkle_hex}},
        {"name": "ots_mismatch", "bundle": "ots.json", "expect_ok": False,
         "codes": ["ots_block_mismatch"], "bitcoin_headers": {str(height): "00" * 32}},
    ]
    mpath = tmp_path / "ots_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS OTS conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS ots_confirmed " in result.stdout
    assert "PASS ots_mismatch " in result.stdout
