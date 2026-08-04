"""The standalone, out-of-process witness server and the RemoteWitness sink adapter.

This is what makes the witnessed (green) path real for a hosted deployment: an independent
witness process the sink cosigns against over the C2SP add-checkpoint protocol. A co-located
witness proves nothing, so the deployment story is "run this on separate infrastructure".
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail import tlog
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.keys import SigningKey
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.server.witness import (
    PersistentWitness,
    RemoteWitness,
    WitnessClient,
    WitnessStore,
    create_witness_app,
)
from provenrail.verifier.verify import verify_bundle

FIXED_TS = 1_700_000_000


def _leafset(n):
    return [tlog.compute_leaf_hash(tlog.compute_anchor_commit(
        "s", i, i, "ab" * 32, "t", "local", f"sig{i}")) for i in range(n)]


def _signed(origin, size, leaves, log_key):
    root = tlog.merkle_root_from_leaf_hashes(leaves[:size])
    return tlog.sign_checkpoint(tlog.build_checkpoint(origin, size, root), log_key, origin)


def _verify_cosig(note, line, witness_pub, name):
    p = tlog.parse_signed_note(note + line)
    wsig = next(s for s in p["signatures"] if s["key_name"] == name)
    ok, _ = tlog.verify_cosignature(wsig["payload"], witness_pub, p["body"], name)
    return ok


def _witness(tmp_path=None, log_keys=None, name="w-prod"):
    store = WitnessStore(str(tmp_path / "w.db") if tmp_path else ":memory:")
    w = PersistentWitness(name, store, log_keys=log_keys, clock=lambda: FIXED_TS)
    return w, store


# ---- protocol round-trip ----

def test_http_round_trip_cosign_and_growth():
    log_key = SigningKey.generate()
    origin = "flightrecorder.io/v1/acct-1"
    w, _ = _witness(log_keys={origin: log_key.public_key_hex()})
    c = TestClient(create_witness_app(w))
    client = WitnessClient("http://w", w.public_key_hex(), w.name, http=c)
    leaves = _leafset(4)

    note1 = _signed(origin, 1, leaves, log_key)
    line1 = client.cosign(origin, 0, [], note1, 1)
    assert line1 and line1.startswith("\u2014")
    assert _verify_cosig(note1, line1, w.public_key_hex(), w.name)
    assert w.last_cosigned_size(origin) == 1

    proof = tlog.make_consistency_proof(1, 4, leaves)
    note4 = _signed(origin, 4, leaves, log_key)
    line4 = client.cosign(origin, 1, proof, note4, 4)
    assert line4 and _verify_cosig(note4, line4, w.public_key_hex(), w.name)
    assert w.last_cosigned_size(origin) == 4


def test_stale_old_size_returns_409_with_known_size():
    log_key = SigningKey.generate()
    origin = "log-x"
    w, _ = _witness(log_keys={origin: log_key.public_key_hex()})
    c = TestClient(create_witness_app(w))
    leaves = _leafset(2)
    note2 = _signed(origin, 2, leaves, log_key)
    # Drive it to size 2 first.
    c.post("/add-checkpoint", content=WitnessClient._build_body(0, [], note2))
    # Now submit with a stale old=0: the witness already holds 2, so it returns 409 + its size.
    resp = c.post("/add-checkpoint", content=WitnessClient._build_body(0, [], note2))
    assert resp.status_code == 409
    assert resp.headers.get("X-Tree-Size") == "2"


def test_pinned_witness_rejects_unknown_origin():
    log_key = SigningKey.generate()
    w, _ = _witness(log_keys={"known": log_key.public_key_hex()})
    c = TestClient(create_witness_app(w))
    note = _signed("unknown", 1, _leafset(1), log_key)
    resp = c.post("/add-checkpoint", content=WitnessClient._build_body(0, [], note))
    assert resp.status_code == 409
    assert "does not witness" in resp.text


def test_pinned_witness_rejects_forged_log_signature():
    real, attacker = SigningKey.generate(), SigningKey.generate()
    origin = "log"
    w, _ = _witness(log_keys={origin: real.public_key_hex()})
    c = TestClient(create_witness_app(w))
    # Note signed by the attacker key, not the pinned log key.
    note = _signed(origin, 1, _leafset(1), attacker)
    resp = c.post("/add-checkpoint", content=WitnessClient._build_body(0, [], note))
    assert resp.status_code == 409
    assert "not validly signed" in resp.text


def test_witness_state_survives_restart(tmp_path):
    log_key = SigningKey.generate()
    origin = "log"
    w1, store1 = _witness(tmp_path, log_keys={origin: log_key.public_key_hex()})
    c1 = TestClient(create_witness_app(w1))
    note2 = _signed(origin, 2, _leafset(2), log_key)
    c1.post("/add-checkpoint", content=WitnessClient._build_body(0, [], note2))
    pub1 = w1.public_key_hex()
    store1._db.close()

    # Reopen the same witness DB: it must remember its key and that it already cosigned size 2.
    store2 = WitnessStore(str(tmp_path / "w.db"))
    w2 = PersistentWitness("w-prod", store2, log_keys={origin: log_key.public_key_hex()},
                           clock=lambda: FIXED_TS)
    assert w2.public_key_hex() == pub1
    assert w2.last_cosigned_size(origin) == 2


# ---- end-to-end: hosted sink cosigns against an independent witness process ----

def test_hosted_sink_goes_green_against_remote_witness():
    sink = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    sc = TestClient(sink)
    prov = provision_stream("http://sink", http=sc)
    fr = FlightRecorder("http://sink", prov["write_token"], prov["stream_id"], http=sc)
    with fr.session({"agent": "remote-witness-demo"}):
        fr.record_decision("ship it")

    # Stand up the out-of-process witness, pinned to this sink's log key + origin.
    store = sink.state.store
    origin = store.origin_for_stream(prov["stream_id"], sink.state.scheduler.tlog_origin_prefix)
    log_pub = sink.state.scheduler.tlog_log_key.public_key_hex()
    w = PersistentWitness("independent-witness", WitnessStore(":memory:"),
                          log_keys={origin: log_pub})
    wc = TestClient(create_witness_app(w))
    remote = RemoteWitness("http://witness", w.public_key_hex(), "independent-witness",
                           store=store, http=wc)
    sink.state.scheduler.witnesses.append(remote)

    sc.post(f"/v1/streams/{prov['stream_id']}/anchor",
            headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = sc.get(f"/v1/streams/{prov['stream_id']}/export",
                    headers={"Authorization": f"Bearer {prov['read_token']}"}).json()

    report = verify_bundle(bundle, tlog_log_key=log_pub,
                           witness_pubkeys={"independent-witness": w.public_key_hex()})
    assert report.ok, report.to_dict()
    # The witness actually cosigned: it advanced its state for this origin.
    assert w.last_cosigned_size(origin) >= 1
