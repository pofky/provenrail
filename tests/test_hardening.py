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
