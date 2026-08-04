"""Accounts, API-key auth, ownership, rate limiting, auto-anchor."""
from fastapi.testclient import TestClient

from provenrail.server.app import create_app
from provenrail.server.security import RateLimiter


def app(**kw):
    return TestClient(create_app(":memory:", **kw))


def test_stream_creation_requires_api_key():
    c = app()  # require_account defaults True
    r = c.post("/v1/streams", json={})
    assert r.status_code == 401


def test_account_signup_and_owned_stream():
    c = app()
    acct = c.post("/v1/accounts", json={"label": "me"}).json()
    assert acct["api_key"].startswith("pr_sk_")
    h = {"Authorization": f"Bearer {acct['api_key']}"}
    s = c.post("/v1/streams", json={"label": "agent-1"}, headers=h)
    assert s.status_code == 200
    listing = c.get("/v1/streams", headers=h).json()
    assert any(st["stream_id"] == s.json()["stream_id"] for st in listing["streams"])


def test_other_account_cannot_see_streams():
    c = app()
    a = c.post("/v1/accounts", json={}).json()
    b = c.post("/v1/accounts", json={}).json()
    c.post("/v1/streams", json={}, headers={"Authorization": f"Bearer {a['api_key']}"})
    b_list = c.get("/v1/streams", headers={"Authorization": f"Bearer {b['api_key']}"}).json()
    assert b_list["streams"] == []


def test_invalid_api_key_rejected():
    c = app()
    r = c.post("/v1/streams", json={}, headers={"Authorization": "Bearer pr_sk_nope"})
    assert r.status_code == 401


def test_signup_rate_limited():
    c = app(signup_per_min=2)
    assert c.post("/v1/accounts", json={}).status_code == 200
    assert c.post("/v1/accounts", json={}).status_code == 200
    assert c.post("/v1/accounts", json={}).status_code == 429


def test_rate_limiter_window():
    rl = RateLimiter(2, 10.0)
    assert rl.allow("k", now=0)
    assert rl.allow("k", now=1)
    assert not rl.allow("k", now=2)
    assert rl.allow("k", now=11)  # window passed


def test_auto_anchor_scheduler_tick():
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    from provenrail.server.app import create_app as ca
    application = ca(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(application)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    # no manual anchor; drive the scheduler directly
    anchored = application.state.scheduler.tick()
    assert anchored == 1
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert len(exp["anchors"]) == 1
    # ticking again with no new records does nothing
    assert application.state.scheduler.tick() == 0
