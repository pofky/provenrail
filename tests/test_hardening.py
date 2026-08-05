
from fastapi.testclient import TestClient

from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def client(**caps):
    caps.setdefault("require_account", False)
    return TestClient(create_app(":memory:", **caps))


def provision(c):
    return c.post("/v1/streams", json={}).json()


def rec(stream_id, seq, extra=""):
    return {"stream_id": stream_id, "seq": seq, "action_type": "tool_call",
            "record_hash": f"h{seq}{extra}", "ts_utc": "2026-06-08T00:00:00.0Z", "pad": extra}


def hdr(p):
    return {"Authorization": f"Bearer {p['write_token']}"}


def test_batch_cap_enforced():
    c = client(max_batch=2)
    p = provision(c)
    r = c.post("/v1/ingest", json={"records": [rec(p["stream_id"], i) for i in range(3)]}, headers=hdr(p))
    assert r.status_code == 413


def test_record_size_cap_enforced():
    c = client(max_record_bytes=200)
    p = provision(c)
    big = rec(p["stream_id"], 0, extra="x" * 500)
    r = c.post("/v1/ingest", json={"records": [big]}, headers=hdr(p))
    assert r.status_code == 413


def test_missing_required_fields_rejected():
    c = client()
    p = provision(c)
    bad = {"stream_id": p["stream_id"], "action_type": "x"}  # no record_hash / seq
    r = c.post("/v1/ingest", json={"records": [bad]}, headers=hdr(p))
    assert r.status_code == 422


def test_idempotent_dedupe():
    c = client()
    p = provision(c)
    one = rec(p["stream_id"], 0)
    c.post("/v1/ingest", json={"records": [one]}, headers=hdr(p))
    r2 = c.post("/v1/ingest", json={"records": [one]}, headers=hdr(p))
    assert r2.json()["receipts"][0].get("duplicate") is True
    exp = c.get(f"/v1/streams/{p['stream_id']}/export",
                headers={"Authorization": f"Bearer {p['read_token']}"}).json()
    assert len(exp["records"]) == 1  # not duplicated


def test_stream_record_cap():
    c = client(max_records_per_stream=2)
    p = provision(c)
    c.post("/v1/ingest", json={"records": [rec(p["stream_id"], 0), rec(p["stream_id"], 1)]}, headers=hdr(p))
    r = c.post("/v1/ingest", json={"records": [rec(p["stream_id"], 2)]}, headers=hdr(p))
    assert r.status_code == 429


def test_local_only_anchor_warns_but_passes():
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    rep = verify_bundle(exp)
    assert rep.ok
    assert any(f.code == "local_anchor_only" for f in rep.findings)


def test_share_badge_amber_for_local_anchor_only():
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    r = c.get(f"/share/{prov['share_token']}")
    assert r.status_code == 200
    # integrity is real but there is no third-party timestamp: amber, not green
    assert "badge amber" in r.text
    assert "no trusted timestamp" in r.text
    assert "Integrity verified</span>" not in r.text


def test_anchor_rate_limit_enforced():
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", require_account=False, anchor_per_min=1)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    h = {"Authorization": f"Bearer {prov['read_token']}"}
    first = c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=h)
    second = c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=h)
    assert first.status_code == 200
    assert second.status_code == 429


def test_an_uncanonicalizable_record_is_refused_not_a_crash():
    """A float or an out-of-JS-range integer anywhere in a record means the record can never be
    hashed, so it can never be verified. It reached the client as a 500, which reads as "our
    fault, retry", for a record that will never be accepted no matter how often it is sent."""
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.server.app import create_app

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    h = {"Authorization": f"Bearer {prov['write_token']}"}
    base = {"stream_id": prov["stream_id"], "record_hash": "bb" * 32, "seq": 0,
            "action_type": "model_call", "ts_utc": "2026-01-01T00:00:00Z"}
    for bad in ({**base, "seq": 0, "payload": {"cost": 1.5}},
                {**base, "seq": 1, "payload": {"tokens": 9007199254740992}},
                {**base, "seq": 2, "payload": {"nested": {"deep": [1, 2.25]}}}):
        r = c.post("/v1/ingest", json={"records": [bad]}, headers=h)
        assert r.status_code == 422, (r.status_code, r.text)
        assert "canonicaliz" in r.text


def test_rotating_with_the_wrong_old_key_changes_nothing():
    """A rotation is what someone does the hour they think a key was stolen, and the only
    question that matters is whether the old key is dead. It used to revoke nothing, add the new
    key anyway, and answer 200: the compromised key stayed active and a second live key
    appeared."""
    from provenrail.anchor import LocalAnchor
    from provenrail.server.app import create_app

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret="s")
    c = TestClient(app)
    key = c.post("/v1/accounts", json={}).json()["api_key"]
    h = {"Authorization": f"Bearer {key}"}
    real, other, new = "aa" * 32, "bb" * 32, "cc" * 32
    assert c.post("/v1/agents", json={"agent_id": "a", "pubkey": real}, headers=h).status_code == 200

    r = c.post("/v1/agents/a/rotate", json={"old_pubkey": other, "new_pubkey": new}, headers=h)
    assert r.status_code == 404, r.text
    keys = c.get("/v1/agents", headers=h).json()["agents"]
    assert [(k["pubkey"], k["status"]) for k in keys] == [(real, "active")], (
        "a failed rotation must add nothing and revoke nothing")

    ok = c.post("/v1/agents/a/rotate", json={"old_pubkey": real, "new_pubkey": new}, headers=h)
    assert ok.status_code == 200
    after = {k["pubkey"]: k["status"] for k in c.get("/v1/agents", headers=h).json()["agents"]}
    assert after == {real: "revoked", new: "active"}
