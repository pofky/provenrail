"""End to end: SDK captures -> off-box sink -> export -> standalone verifier.

Also proves the verifier catches server-side tampering (deletion, reorder, backdating)
that the client chain alone would miss.
"""
import copy

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def run_session(capture_content=False):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    client = TestClient(app)
    prov = provision_stream("http://t", http=client)

    fr = FlightRecorder(
        endpoint="http://t",
        write_token=prov["write_token"],
        stream_id=prov["stream_id"],
        capture_content=capture_content,
        http=client,
    )

    @fr.tool("add")
    def add(a, b):
        return a + b

    with fr.session({"agent": "demo"}):
        fr.record_model_call("openai", "gpt-x", {"prompt": "hi"}, {"text": "hello"},
                             usage={"in": "5", "out": "3"})
        assert add(2, 3) == 5
        fr.record_decision("proceed", reason="looks good")

    # anchor + export via read token
    client.post(f"/v1/streams/{prov['stream_id']}/anchor",
                headers={"Authorization": f"Bearer {prov['read_token']}"})
    exp = client.get(f"/v1/streams/{prov['stream_id']}/export",
                     headers={"Authorization": f"Bearer {prov['read_token']}"})
    return exp.json()


def test_happy_path_verifies():
    bundle = run_session()
    rep = verify_bundle(bundle)
    assert rep.ok, rep.to_dict()
    # genesis, model_call, tool_call, decision, seal == 5 records
    assert len(bundle["records"]) == 5
    codes = {f.code for f in rep.findings}
    assert "anchor_root_mismatch" not in codes


def test_store_hash_not_content_by_default():
    bundle = run_session(capture_content=False)
    model_rec = next(r["record"] for r in bundle["records"]
                     if r["record"]["action_type"] == "model_call")
    # only a hash, no raw content
    assert "hash" in model_rec["payload"]["request"]
    assert "content" not in model_rec["payload"]["request"]


def test_capture_content_when_enabled():
    bundle = run_session(capture_content=True)
    model_rec = next(r["record"] for r in bundle["records"]
                     if r["record"]["action_type"] == "model_call")
    assert model_rec["payload"]["request"]["content"] == {"prompt": "hi"}


def test_verifier_catches_server_side_deletion():
    bundle = run_session()
    tampered = copy.deepcopy(bundle)
    del tampered["records"][2]  # drop a record after it was anchored
    rep = verify_bundle(tampered)
    assert not rep.ok
    codes = {f.code for f in rep.findings}
    assert "server_chain_break" in codes or "recv_gap" in codes


def test_verifier_catches_content_edit():
    bundle = run_session()
    tampered = copy.deepcopy(bundle)
    # edit a stored record's content without recomputing anything
    tampered["records"][1]["record"]["payload"]["model"] = "evil"
    rep = verify_bundle(tampered)
    assert not rep.ok
    codes = {f.code for f in rep.findings}
    assert "recv_hash_mismatch" in codes or "client_hash_mismatch" in codes


def test_verifier_catches_coherent_server_rechain():
    """A malicious sink deletes a record and perfectly re-chains its own receipts.
    The client signed chain must still expose the deletion."""
    from provenrail import GENESIS_PREV_HASH
    from provenrail.canonical import canonicalize, sha256_hex
    bundle = run_session()
    t = copy.deepcopy(bundle)
    del t["records"][2]
    prev = GENESIS_PREV_HASH
    for i, sr in enumerate(t["records"]):
        sr["recv_seq"] = i
        sr["recv_hash"] = sha256_hex(canonicalize(sr["record"]))
        sr["server_prev_hash"] = prev
        sr["server_record_hash"] = sha256_hex(canonicalize(
            {"recv_seq": i, "recv_ts": sr["recv_ts"], "recv_hash": sr["recv_hash"],
             "server_prev_hash": prev}))
        prev = sr["server_record_hash"]
    rep = verify_bundle(t)
    assert not rep.ok
    codes = {f.code for f in rep.findings}
    assert "client_broken_link" in codes and "client_seq_gap" in codes


def test_verifier_catches_backdating_after_anchor():
    bundle = run_session()
    tampered = copy.deepcopy(bundle)
    # set a client ts far in the future, after the anchor that covered it
    tampered["records"][1]["record"]["ts_utc"] = "2999-01-01T00:00:00.0Z"
    rep = verify_bundle(tampered)
    # editing ts_utc breaks the hash too, but the time check should also flag it
    assert not rep.ok
