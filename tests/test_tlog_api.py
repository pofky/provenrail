"""Step 3: the sink publishes checkpoints, exports inclusion proofs, and serves the log."""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail import tlog
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _run(c, label="demo"):
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": label}):
        fr.record_model_call("anthropic", "claude-sonnet-4", {"q": "hi"}, {"a": "yo"},
                             usage={"input": "100", "output": "50"})
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return prov


def _open_client():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    return TestClient(app)


def test_bundle_includes_tlog_inclusion():
    c = _open_client()
    prov = _run(c)
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    assert bundle["tlog_schema_version"] == 1
    assert bundle["anchors"]
    incl = bundle["anchors"][0]["tlog_inclusion"]
    assert incl["kind"] == "tlog_inclusion"
    assert incl["leaf_index"] == 0
    assert incl["tree_size"] >= 1
    assert "flightrecorder.io/v1/anchors/shared" in incl["log_origin"]


def test_bundle_verifies_with_server_log_key():
    c = _open_client()
    prov = _run(c)
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    log_pubkey = c.get("/v1/meta").json()["tlog_pubkey"]
    rep = verify_bundle(bundle, tlog_log_key=log_pubkey)
    assert rep.ok
    codes = {f.code for f in rep.findings}
    # Inclusion proof verifies; no witnesses configured -> amber (unwitnessed), not green.
    assert "tlog_inclusion_unwitnessed" in codes
    assert not any(f.code.startswith("tlog_") and f.severity == "fail" for f in rep.findings)


def test_checkpoint_endpoint_returns_signed_note():
    c = _open_client()
    _run(c)
    r = c.get("/v1/tlog/shared/checkpoint")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["x-witnessed"] == "false"
    assert int(r.headers["x-tree-size"]) >= 1
    parsed = tlog.parse_signed_note(r.text)
    assert parsed["body"].startswith("flightrecorder.io/v1/anchors/shared")
    assert len(parsed["signatures"]) == 1  # the log key, no witnesses yet


def test_inclusion_endpoint_matches_bundle():
    c = _open_client()
    prov = _run(c)
    r = c.get("/v1/tlog/shared/inclusion/0")
    assert r.status_code == 200
    body = r.json()
    assert body["leaf_index"] == 0 and body["tree_size"] >= 1
    # The proof from the endpoint must verify against the recomputed commit from the bundle.
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    a = bundle["anchors"][0]
    rec = a["receipt"]
    tos = rec.get("token_b64") if rec.get("kind") == "rfc3161" else rec.get("signature")
    commit = tlog.compute_anchor_commit(bundle["stream_id"], a["anchor_seq"], a["covers_up_to"],
                                        rec.get("merkle_root", ""), rec.get("gen_time", ""),
                                        rec.get("kind", ""), tos or "").hex()
    note = tlog.parse_signed_note(body["checkpoint"])
    root_b64 = note["body"].split("\n")[2]
    assert tlog.verify_inclusion(commit, 0, body["tree_size"], body["proof_hashes"], root_b64)


def test_inclusion_endpoint_out_of_range():
    c = _open_client()
    _run(c)
    assert c.get("/v1/tlog/shared/inclusion/9999").status_code == 404


def test_consistency_endpoint_growth():
    c = _open_client()
    # Two separate streams in the same (shared) account produce a growing log.
    _run(c, "a")
    _run(c, "b")
    cp = c.get("/v1/tlog/shared/checkpoint")
    size = int(cp.headers["x-tree-size"])
    assert size >= 2
    r = c.get(f"/v1/tlog/shared/consistency/1/{size}")
    assert r.status_code == 200
    proof = r.json()
    assert proof["old_size"] == 1 and proof["new_size"] == size


def test_consistency_endpoint_span_capped():
    c = _open_client()
    _run(c)
    assert c.get("/v1/tlog/shared/consistency/0/2000").status_code == 413


def test_tlog_endpoints_need_no_auth():
    c = _open_client()
    _run(c)
    # No Authorization header on any of the three public endpoints.
    assert c.get("/v1/tlog/shared/checkpoint").status_code == 200
    assert c.get("/v1/tlog/shared/inclusion/0").status_code == 200


def test_tlog_endpoint_rate_limited():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False, tlog_per_min=5)
    c = TestClient(app)
    _run(c)
    codes = [c.get("/v1/tlog/shared/checkpoint").status_code for _ in range(8)]
    assert 429 in codes


def test_log_grows_append_only_consistency_verifies():
    # The consistency proof the endpoint serves must actually verify between the two roots.
    c = _open_client()
    _run(c, "a")
    size1 = int(c.get("/v1/tlog/shared/checkpoint").headers["x-tree-size"])
    root1 = tlog.parse_signed_note(c.get("/v1/tlog/shared/checkpoint").text)["body"].split("\n")[2]
    _run(c, "b")
    cp2 = c.get("/v1/tlog/shared/checkpoint")
    size2 = int(cp2.headers["x-tree-size"])
    root2 = tlog.parse_signed_note(cp2.text)["body"].split("\n")[2]
    proof = c.get(f"/v1/tlog/shared/consistency/{size1}/{size2}").json()["proof_hashes"]
    assert tlog.verify_consistency(size1, root1, size2, root2, proof)
