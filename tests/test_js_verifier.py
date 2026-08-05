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


def _policy_bundle(tmp_path, policy, actions, enforce=True):
    """Record one session under a committed policy and return its bundle."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=policy, enforce=enforce)
    with fr.session({"agent": "pol"}):
        actions(fr)
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


def test_js_verifier_replays_the_committed_policy(tmp_path):
    """Lockstep on ENFORCEMENT, not just integrity.

    The guardrail packs are sold on "you can prove the rules were in force". Until the browser
    verifier replayed the committed policy too, that claim was only provable by the Python
    verifier, so the in-browser proof was strictly weaker than the CLI on the one property the
    product leads with.
    """
    from provenrail.policy import Budget, Policy, Rule
    from provenrail.verifier.verify import verify_bundle

    policy = Policy(
        rules=[Rule(id="no-danger", effect="deny", tool="danger_*"),
               Rule(id="cap-search", effect="limit", tool="search", max_per_session=2),
               Rule(id="no-secret", effect="deny", event_type="tool_call",
                    arg_contains="password")],
        budgets=[Budget(scope="session", limit_usd=100.0),
                 Budget(scope="day", limit_usd=500.0)])

    def acts(fr):
        fr.record_model_call("anthropic", "claude-sonnet-4-5", {"p": "hi"}, {"t": "yo"},
                             usage={"input_tokens": 1000, "output_tokens": 100})
        fr.record_tool_call("search", {"q": 1}, {})
        fr.record_tool_call("search", {"q": 2}, {})

    bundle = _policy_bundle(tmp_path, policy, acts)
    rep = verify_bundle(bundle)
    assert rep.ok
    detail = next(f.detail for f in rep.findings if f.code == "policy_verified")
    assert "content-gate" in detail and "cross-session budget" in detail

    (tmp_path / "pol.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [{"name": "policy_ok", "bundle": "pol.json", "expect_ok": True,
                 "codes": ["policy_verified"]}]
    mpath = tmp_path / "policy_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS policy conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS policy_ok " in result.stdout


def test_js_verifier_catches_an_edited_policy(tmp_path):
    """Loosening the committed guardrails after the fact must fail in BOTH implementations."""
    from provenrail.policy import Policy, Rule
    from provenrail.verifier.verify import verify_bundle

    policy = Policy(rules=[Rule(id="no-danger", effect="deny", tool="danger_*")])
    bundle = _policy_bundle(tmp_path, policy, lambda fr: fr.record_decision("fine"))
    tampered = copy.deepcopy(bundle)
    meta = tampered["records"][0]["record"]["payload"]["meta"]
    meta["policy"]["rules"][0]["tool"] = "nothing_*"   # quietly disarm the rule

    rep = verify_bundle(tampered)
    assert any(f.code in ("policy_commit_mismatch", "client_hash_mismatch") for f in rep.findings)

    (tmp_path / "pol_edit.json").write_text(json.dumps(tampered), encoding="utf-8")
    manifest = [{"name": "policy_edited", "bundle": "pol_edit.json", "expect_ok": False}]
    mpath = tmp_path / "policy_edit_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS policy-edit conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS policy_edited " in result.stdout


def test_js_verifier_flags_an_unenforced_policy_like_python(tmp_path):
    """A run that executed an action its own committed policy would deny: both verifiers must
    warn `policy_not_enforced`. This is the finding that catches a policy configured but not
    actually applied, which is indistinguishable from no policy at all if nobody checks."""
    from provenrail.policy import Policy, Rule
    from provenrail.verifier.verify import verify_bundle

    # enforce=False records the decision but lets the call through, which is exactly the
    # "policy present, not enforcing" shape the verifier must catch.
    policy = Policy(rules=[Rule(id="no-danger", effect="deny", tool="danger_*")])
    bundle = _policy_bundle(tmp_path, policy,
                            lambda fr: fr.record_tool_call("danger_delete", {"x": 1}, {}),
                            enforce=False)
    rep = verify_bundle(bundle)
    assert any(f.code == "policy_not_enforced" for f in rep.findings)

    (tmp_path / "pol_un.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [{"name": "policy_unenforced", "bundle": "pol_un.json", "expect_ok": True,
                 "codes": ["policy_not_enforced"]}]
    mpath = tmp_path / "policy_unenforced_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS unenforced conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS policy_unenforced " in result.stdout


def test_js_and_python_agree_on_a_blown_spend_cap(tmp_path):
    """The JS price table and cost arithmetic must match pricing.py closely enough that a
    session spend cap replays identically. A verifier that priced a call differently would
    accuse a clean run of not enforcing its own budget."""
    from provenrail.policy import Budget, Policy
    from provenrail.verifier.verify import verify_bundle

    # cap of $0.01 with a call that costs $3.00: enforce=False lets it through, so both
    # verifiers should independently notice the budget was not applied.
    policy = Policy(budgets=[Budget(scope="session", limit_usd=0.01, warn_at=0)])
    bundle = _policy_bundle(
        tmp_path, policy,
        lambda fr: fr.record_model_call("anthropic", "claude-sonnet-4-5", {"p": "x"}, {"t": "y"},
                                        usage={"input_tokens": 1_000_000, "output_tokens": 0}),
        enforce=False)
    rep = verify_bundle(bundle)
    assert any(f.code == "policy_not_enforced" for f in rep.findings)

    (tmp_path / "pol_budget.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [{"name": "policy_budget", "bundle": "pol_budget.json", "expect_ok": True,
                 "codes": ["policy_not_enforced"]}]
    mpath = tmp_path / "policy_budget_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)], capture_output=True, text=True)
    assert result.returncode == 0, f"JS budget conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS policy_budget " in result.stdout


def test_js_and_python_cost_estimation_agree(tmp_path):
    """Every model and usage shape must price identically in both implementations.

    Cached-token handling is where these drift: the two conventions (input inclusive of cache
    for OpenAI and Google, exclusive for Anthropic) are easy to implement one way in one
    language and the other way in the other, and the failure is silent until a budget replays
    differently in the browser than on the CLI.
    """
    import itertools

    from provenrail.pricing import cost_for

    models = ["claude-sonnet-4-5", "gpt-4.1", "gemini-2.5-pro", "gemini-2.5-flash",
              "claude-3-opus", "gpt-4o", "gpt-4o-mini", "deepseek-chat", "o3",
              "llama-3.1-70b", "unknown-model-xyz",
              # The whole current Anthropic line, because these resolve by longest substring
              # and a table that lists only some of them silently bills the rest at a retired
              # rate. Both verifiers must make the same mistake or the same correct choice.
              "claude-opus-4-5", "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
              "claude-opus-4-1", "claude-opus-4-20250514", "claude-opus-5", "claude-sonnet-5",
              "claude-fable-5", "claude-sonnet-4-6", "gemini-2.5-flash-lite", "gpt-5",
              # Mythos prices exactly like Fable; it was absent from both tables, so every call
              # to it priced at $0.00 with priced=False and no budget could bind.
              "claude-mythos-5", "claude-mythos-preview"]
    usages = [
        {"input_tokens": 1_000_000, "output_tokens": 250_000},
        # Google's two documented spellings, verified against the official REST reference and
        # the google-genai Python SDK. These priced at $0.00 with priced=True before.
        {"promptTokenCount": 1_000_000, "candidatesTokenCount": 200_000,
         "cachedContentTokenCount": 400_000},
        {"prompt_token_count": 900_000, "candidates_token_count": 100_000},
        {"input_tokens": -1_000_000, "output_tokens": -5},   # must clamp, never go negative
        {"prompt_tokens": 800_000, "completion_tokens": 10,
         "prompt_tokens_details": {"cached_tokens": 300_000}},
        {"input_tokens": 1000, "output_tokens": 0, "cache_read_input_tokens": 50_000,
         "cache_creation_input_tokens": 20_000},
        {"output_tokens_details": {"reasoning_tokens": 5000}, "completion_tokens": 9000},
        # Anthropic's TTL split: the 1h portion is inside cache_creation_input_tokens and is
        # billed at 2x rather than 1.25x.
        {"input_tokens": 0, "output_tokens": 0, "cache_creation_input_tokens": 800_000,
         "cache_creation": {"ephemeral_5m_input_tokens": 500_000,
                            "ephemeral_1h_input_tokens": 300_000}},
        # A 1h figure larger than the total it belongs to must not be able to inflate the bill.
        {"cache_creation_input_tokens": 100, "cache_creation": {"ephemeral_1h_input_tokens": 999}},
        # Gemini thinking tokens, billed on top of the candidate count at the output rate.
        {"promptTokenCount": 1000, "candidatesTokenCount": 1_000_000,
         "thoughtsTokenCount": 1_000_000},
        # Either side of Gemini 2.5 Pro's 200k prompt tier boundary.
        {"promptTokenCount": 200_000, "candidatesTokenCount": 100_000},
        {"promptTokenCount": 200_001, "candidatesTokenCount": 100_000},
        {},
    ]
    cases = [{"model": m, "usage": u, "py": cost_for(m, u)["cost_usd"]}
             for m, u in itertools.product(models, usages)]
    path = tmp_path / "cost_cases.json"
    path.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run(["node", str(HERE / "js" / "cost_parity.mjs"), str(path)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"cost parity failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS all" in result.stdout


def _policy_hash_cases():
    """Policy dicts whose committed hash is taken over Policy.to_dict(), in shapes a hand-built
    or older-SDK bundle really produces. Each one used to make the two verifiers disagree about
    whether the bundle had been tampered with."""
    base_rule = {"id": "r1", "effect": "deny", "event_type": "tool_call", "tool": "bash",
                 "resource": "*", "provider": "*", "arg_contains": "", "max_per_session": None,
                 "reason": ""}
    return [
        {"rules": [base_rule], "session_spend_cap_usd": None},
        # an explicit empty budgets list, which Policy.to_dict() omits entirely
        {"rules": [base_rule], "session_spend_cap_usd": None, "budgets": []},
        # a rule that omits every optional field, which from_dict fills with defaults
        {"rules": [{"id": "r1", "effect": "deny", "tool": "bash"}],
         "session_spend_cap_usd": None},
        # an unknown key, which Rule.from_dict and Policy.from_dict both drop
        {"rules": [{**base_rule, "_note": "ignored"}], "session_spend_cap_usd": None,
         "unknown_top_level": 1},
        {"rules": [base_rule], "session_spend_cap_usd": 5.0,
         "budgets": [{"id": "b", "scope": "day", "limit_usd": "10.000000", "warn_at": "0.8000"}]},
        {"rules": [], "session_spend_cap_usd": None, "on_unpriced": "deny"},
    ]


def test_policy_hash_is_computed_over_the_same_bytes_in_both_verifiers(tmp_path):
    """The committed hash is taken over Policy.to_dict(), not over whatever dict sits in the
    bundle. The browser verifier hashed the raw dict, so a genuine bundle carrying `budgets: []`
    or a rule with defaults omitted verified on the CLI and was reported as TAMPERED in the
    browser. Opposite verdicts on the same file is the one failure this product cannot have."""
    from provenrail.policy import Policy

    cases = [{"policy": p, "py": Policy.from_dict(p).policy_id()} for p in _policy_hash_cases()]
    path = tmp_path / "policy_hash_cases.json"
    path.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run(["node", str(HERE / "js" / "policy_hash_parity.mjs"), str(path)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"policy hash parity failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS all" in result.stdout


def _bundle_with_policy(tmp_path, policy_dict, rule_tool="bash"):
    """A real recorded session whose committed policy is `policy_dict`, with one tool call
    that the rule under test is meant to catch."""
    from provenrail.policy import Policy
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    policy = Policy.from_dict(policy_dict)
    with fr.session({"agent": "demo", "policy": policy.to_dict(),
                     "policy_sha256": policy.policy_id()}):
        fr.record_tool_call(rule_tool, {"cmd": "x"}, {"ok": True}, _skip_policy=True)
    return c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


def test_an_oversized_glob_is_skipped_and_reported_by_both_verifiers(tmp_path):
    """A bundle is an untrusted file handed to a public web page, so the browser verifier will
    not compile a 100k-character glob into a regex. The CLI's fnmatch had no such limit, so the
    same bundle came back "policy not enforced" on the CLI and "fully verified" in the browser.
    Both must now skip the rule and both must SAY they skipped it: a rule quietly dropped
    inside a green verdict is the exact shape of the audit failure this product exists to
    prevent."""
    from provenrail.verifier.verify import verify_bundle

    long_pattern = "bash" + "*" * 600
    bundle = _bundle_with_policy(tmp_path, {
        "rules": [{"id": "deny-bash", "effect": "deny", "event_type": "tool_call",
                   "tool": long_pattern, "resource": "*", "provider": "*",
                   "arg_contains": "", "max_per_session": None, "reason": ""}],
        "session_spend_cap_usd": None,
    })
    rep = verify_bundle(bundle)
    codes = {f.code for f in rep.findings}
    assert "policy_rule_not_rechecked" in codes
    assert "policy_not_enforced" not in codes

    path = tmp_path / "oversized.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [{"name": "oversized_glob", "bundle": "oversized.json", "expect_ok": rep.ok,
                 "codes": ["policy_rule_not_rechecked"]}]
    mpath = tmp_path / "oversized_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS disagreed on the oversized glob:\n{result.stdout}"


def test_a_normal_length_glob_is_still_enforced_and_re_checked(tmp_path):
    """The guard must not become an escape hatch: an ordinary rule still fires in both."""
    from provenrail.verifier.verify import verify_bundle

    bundle = _bundle_with_policy(tmp_path, {
        "rules": [{"id": "deny-bash", "effect": "deny", "event_type": "tool_call",
                   "tool": "bash*", "resource": "*", "provider": "*",
                   "arg_contains": "", "max_per_session": None, "reason": ""}],
        "session_spend_cap_usd": None,
    })
    rep = verify_bundle(bundle)
    codes = {f.code for f in rep.findings}
    assert "policy_not_enforced" in codes
    assert "policy_rule_not_rechecked" not in codes

    path = tmp_path / "normal.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    mpath = tmp_path / "normal_manifest.json"
    mpath.write_text(json.dumps([{"name": "normal_glob", "bundle": "normal.json",
                                  "expect_ok": rep.ok,
                                  "codes": ["policy_not_enforced"]}]), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS disagreed on a normal glob:\n{result.stdout}"


def test_a_float_in_a_record_is_a_verdict_not_a_traceback():
    """verify_bundle is the function a stranger's upload reaches. A float anywhere in a record
    escaped as an unhandled CanonicalError, so `pr verify` exited with a stack trace rather
    than a verdict, and the browser verifier returned "tampered" for the same file."""
    from provenrail.verifier.verify import verify_bundle

    bundle = {"format": "flightrecorder.bundle/1",
              "records": [{"recv_seq": 0, "recv_ts": "2026-08-04T00:00:00.000000Z",
                           "recv_hash": "0" * 64, "server_prev_hash": "0" * 64,
                           "server_record_hash": "0" * 64,
                           "record": {"seq": 0, "session_id": "s", "payload": {"cost": 1.5}}}]}
    rep = verify_bundle(bundle)          # must not raise
    assert not rep.ok
    assert "not_canonicalizable" in {f.code for f in rep.findings}


def test_coherence_signals_appear_in_both_verifiers(tmp_path):
    """Step 11 was missing from the browser verifier entirely, so someone auditing a bundle on
    the web page saw a clean verdict and never learned the run recorded no human governance at
    all, while the CLI told them. Both verifiers must surface the same seams."""
    from provenrail.verifier.verify import verify_bundle

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "unsupervised"}):
        # a model call with no usage, and no decision or oversight anywhere in the run
        fr.record_model_call("anthropic", "claude-sonnet-4-5", {"p": "x"}, {"t": "y"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()

    rep = verify_bundle(bundle)
    codes = {f.code for f in rep.findings}
    assert {"no_governance", "usage_missing"} <= codes

    path = tmp_path / "coherence.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    mpath = tmp_path / "coherence_manifest.json"
    mpath.write_text(json.dumps([{"name": "coherence", "bundle": "coherence.json",
                                  "expect_ok": rep.ok,
                                  "codes": ["no_governance", "usage_missing"]}]), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS missed the coherence signals:\n{result.stdout}"


def test_a_null_anchors_field_is_not_tampering_in_either_verifier(tmp_path):
    """`"anchors": null` passes a dict-default key check, so the Python default never fired and
    iterating it raised, which the outer guard reported as a malformed bundle and the headline
    called TAMPERED. The browser coerced null to empty and carried on. Same file, opposite
    verdicts, which is the one outcome two implementations exist to prevent."""
    from provenrail.verifier.verify import verify_bundle

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("ship")
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    bundle["anchors"] = None

    rep = verify_bundle(bundle)
    assert rep.result != "tampered"
    assert "malformed_bundle" not in {f.code for f in rep.findings}

    path = tmp_path / "null_anchors.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    mpath = tmp_path / "null_anchors_manifest.json"
    mpath.write_text(json.dumps([{"name": "null_anchors", "bundle": "null_anchors.json",
                                  "expect_ok": rep.ok, "expect_result": rep.result}]),
                     encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS disagreed on null anchors:\n{result.stdout}"


def test_both_verifiers_emit_the_same_finding_codes_on_a_clean_bundle(tmp_path):
    """Not just the same verdict: the same set of codes. The browser omitted the closing
    `summary` finding the CLI always emits, so any tool comparing the two implementations'
    output saw them differ on every single bundle, for a reason that had nothing to do with
    the record."""
    from provenrail.verifier.verify import verify_bundle

    bundle, _pin = _clean_bundle_and_pin(tmp_path)
    rep = verify_bundle(bundle)
    py_codes = sorted({f.code for f in rep.findings})

    path = tmp_path / "codes.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    mpath = tmp_path / "codes_manifest.json"
    mpath.write_text(json.dumps([{"name": "code_parity", "bundle": "codes.json",
                                  "expect_ok": rep.ok, "codes": py_codes}]), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, (
        f"JS is missing finding codes the CLI emits. Python emitted {py_codes}\n"
        f"{result.stdout}")


def _structural_mutations(bundle):
    """Every way a bundle can be structurally wrong, not only the two that were reported.

    Each entry is a whole-bundle shape a real user can produce: a hand-edit, a truncated
    download, a script that wrote `null` where a list belonged, an export from a different
    tool. A malformed file is not a trick input; it is Tuesday.
    """
    out = {}
    for key in ("anchors", "records"):
        for label, value in (("null", None), ("string", "not a list"), ("number", 7),
                             ("object", {"0": "x"}), ("bool", True)):
            m = copy.deepcopy(bundle)
            m[key] = value
            out[f"{key}_is_{label}"] = m
    for key in ("stream_id", "format", "server_head", "tlog_schema_version"):
        m = copy.deepcopy(bundle)
        m.pop(key, None)
        out[f"missing_{key}"] = m
        m2 = copy.deepcopy(bundle)
        m2[key] = None
        out[f"null_{key}"] = m2
    m = copy.deepcopy(bundle)
    m["records"] = [None]
    out["record_is_null"] = m
    m = copy.deepcopy(bundle)
    m["records"] = ["a string where a record belongs"]
    out["record_is_string"] = m
    m = copy.deepcopy(bundle)
    m["records"][1].pop("record", None)
    out["record_missing_inner"] = m
    m = copy.deepcopy(bundle)
    m["records"][1]["record"] = None
    out["inner_record_is_null"] = m
    m = copy.deepcopy(bundle)
    m["records"][1]["record"]["seq"] = "one"
    out["seq_is_string"] = m
    m = copy.deepcopy(bundle)
    m["records"][1]["record"]["payload"] = 3.14  # floats are banned by canonicalization
    out["float_in_payload"] = m
    m = copy.deepcopy(bundle)
    m["anchors"] = [None]
    out["anchor_is_null"] = m
    m = copy.deepcopy(bundle)
    if m["anchors"]:
        m["anchors"][0] = "a string where an anchor belongs"
    out["anchor_is_string"] = m
    return out


def test_the_two_verifiers_agree_on_every_malformed_shape(tmp_path):
    """A malformed bundle must reach the SAME verdict and the SAME finding codes in both
    implementations.

    This is the failure the second implementation exists to prevent, and it is worse than a
    plain bug: the CLI said TAMPERING DETECTED while the browser threw and showed a neutral
    "could not verify", so the same file got opposite readings depending on where you opened
    it. Python has always had a catch-all at its boundary that turns any structural error into
    a `malformed_bundle` verdict; the browser had none, so `"anchors": "x"` reached `.every`
    and a missing `stream_id` reached the canonicalizer, and both escaped as exceptions.

    Fixing the two shapes that were reported would leave the next one, so this asserts over the
    whole family, exact code sets, both directions.
    """
    from provenrail.verifier.verify import verify_bundle

    bundle, _pin = _clean_bundle_and_pin(tmp_path)
    mutations = _structural_mutations(bundle)
    assert len(mutations) >= 20, "the point of this test is breadth"

    js_manifest = []
    for name, obj in mutations.items():
        rep = verify_bundle(obj)
        (tmp_path / f"{name}.json").write_text(json.dumps(obj), encoding="utf-8")
        js_manifest.append({
            "name": name, "bundle": f"{name}.json",
            "expect_ok": rep.ok, "expect_result": rep.result,
            "exact_codes": sorted({f.code for f in rep.findings}),
        })

    mpath = tmp_path / "malformed_manifest.json"
    mpath.write_text(json.dumps(js_manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, (
        "the CLI and the browser disagree on a malformed bundle, which is the one outcome that "
        "makes two implementations worth less than one:\n"
        f"{result.stdout}\n{result.stderr}")


def test_the_browser_verifier_never_throws(tmp_path):
    """Whatever the file is, the page must end in a verdict.

    An uncaught exception surfaces to the user as a neutral "could not verify", which reads as
    "we could not tell" for a file the CLI calls tampered. Refusing to answer and answering
    wrongly are the same mistake here.
    """
    bundle, _pin = _clean_bundle_and_pin(tmp_path)
    shapes = dict(_structural_mutations(bundle))
    shapes.update({"empty_object": {}, "array": [1, 2], "string": "hello", "number": 5,
                   "null": None, "true": True,
                   "format_only": {"format": "flightrecorder.bundle/1"}})
    for name, obj in shapes.items():
        (tmp_path / f"nx_{name}.json").write_text(json.dumps(obj), encoding="utf-8")
    script = tmp_path / "nothrow.mjs"
    script.write_text(
        "import { readFileSync } from 'node:fs';\n"
        # as_uri(), not as_posix(): on Windows a POSIX-ised absolute path is "D:/..." and
        # node's ESM loader reads the drive letter as a URL scheme and refuses it. A file://
        # URI is the only form that works on both.
        f"import {{ verifyBundle }} from '{(HERE.parent / 'web' / 'verify.js').as_uri()}';\n"
        "const names = JSON.parse(process.argv[2]);\n"
        "let bad = 0;\n"
        "for (const n of names) {\n"
        f"  const b = JSON.parse(readFileSync('{tmp_path.as_posix()}/nx_' + n + '.json', 'utf8'));\n"
        "  try {\n"
        "    const rep = await verifyBundle(b, null, {});\n"
        "    if (!rep || typeof rep.result !== 'string') { console.log('NO VERDICT', n); bad++; }\n"
        "  } catch (e) { console.log('THREW', n, e.constructor.name + ': ' + e.message); bad++; }\n"
        "}\n"
        "process.exit(bad ? 1 : 0);\n", encoding="utf-8")
    result = subprocess.run(["node", str(script), json.dumps(sorted(shapes))],
                            capture_output=True, text=True)
    assert result.returncode == 0, (
        f"the browser verifier threw instead of returning a verdict:\n{result.stdout}\n"
        f"{result.stderr}")


def test_a_head_that_contradicts_the_chain_is_caught_by_both(tmp_path):
    """`server_head` names the tail of the receipt chain and neither verifier looked at it, so
    an export could claim any head at all, including one from a different stream, and both
    called the file verified. A field that is in the format and never checked is worse than no
    field: it reads as a binding and is not one."""
    from provenrail.verifier.verify import verify_bundle

    bundle, _pin = _clean_bundle_and_pin(tmp_path)
    assert verify_bundle(bundle).ok, "the unmodified bundle must still pass"

    wrong_hash = copy.deepcopy(bundle)
    wrong_hash["server_head"]["server_record_hash"] = "a" * 64
    wrong_seq = copy.deepcopy(bundle)
    wrong_seq["server_head"]["recv_seq"] = 99

    js_manifest = []
    for name, obj in {"head_hash": wrong_hash, "head_seq": wrong_seq}.items():
        rep = verify_bundle(obj)
        assert not rep.ok and "server_head_mismatch" in {f.code for f in rep.findings}, name
        (tmp_path / f"{name}.json").write_text(json.dumps(obj), encoding="utf-8")
        js_manifest.append({"name": name, "bundle": f"{name}.json", "expect_ok": False,
                            "expect_result": rep.result,
                            "exact_codes": sorted({f.code for f in rep.findings})})
    mpath = tmp_path / "head_manifest.json"
    mpath.write_text(json.dumps(js_manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(mpath)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS disagreed on server_head:\n{result.stdout}"
