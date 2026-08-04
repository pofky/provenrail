"""Usage metering, plan quotas, and the billing endpoints (the hosted billing surface).

Quotas are a commercial control, never a security control: they bound cost and abuse on a
hosted sink and have no bearing on the integrity guarantee. Open/dev streams (no owner
account) are unmetered.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_account, provision_stream
from provenrail.server import plans
from provenrail.server.app import create_app


def _acct_app():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True)
    c = TestClient(app)
    acct = provision_account("http://t", http=c)
    return app, c, acct["api_key"]


def _stream(c, api_key):
    return provision_stream("http://t", http=c, api_key=api_key)


def _records(stream_id, n, start=0):
    return [{"stream_id": stream_id, "record_hash": f"h{i:08x}", "seq": i}
            for i in range(start, start + n)]


def _ingest(c, write_token, records):
    return c.post("/v1/ingest", json={"records": records},
                  headers={"Authorization": f"Bearer {write_token}"})


# ---- unit: plan math ----

def test_plans_unit():
    assert plans.limit("free", "events") == 50_000
    assert plans.limit("enterprise", "events") is None  # unlimited
    assert plans.would_exceed("free", "streams", 1, 1) is True   # free = single project
    assert plans.would_exceed("free", "streams", 0, 1) is False
    assert plans.would_exceed("team", "streams", 999, 1) is False  # team = unlimited projects
    assert plans.would_exceed("enterprise", "events", 10**12, 10**12) is False
    d = plans.describe("free", {"events": 25_000, "anchors": 0, "streams": 1})
    assert d["percent"]["events"] == 50.0  # 25k of the 50k free cap
    assert d["plan"] == "free"


def test_feature_entitlements():
    # Free is integrity-only: no trusted time, no proof links, no exports, no reports.
    for f in ("trusted_time", "proof_links", "exports", "reports", "witnessed"):
        assert plans.feature("free", f) is False
    # Builder unlocks trusted time + proof links, but not exports/reports.
    assert plans.feature("builder", "trusted_time") is True
    assert plans.feature("builder", "proof_links") is True
    assert plans.feature("builder", "exports") is False
    assert plans.feature("builder", "reports") is False
    # Team unlocks everything the page claims for it.
    for f in ("trusted_time", "proof_links", "exports", "reports", "witnessed"):
        assert plans.feature("team", f) is True
    # Unknown plan falls back to free entitlements (deny by default).
    assert plans.feature("platinum", "exports") is False
    # No retention dimension exists anywhere (records are append-only; we host nothing).
    assert "retention_days" not in plans.PLANS["team"]


# ---- integration: metering + endpoints ----

def test_usage_counts_events_and_streams():
    app, c, key = _acct_app()
    prov = _stream(c, key)
    assert _ingest(c, prov["write_token"], _records(prov["stream_id"], 5)).status_code == 200
    body = c.get("/v1/usage", headers={"Authorization": f"Bearer {key}"}).json()
    assert body["usage"]["events"] == 5
    assert body["usage"]["streams"] == 1
    assert body["plan"] == "free"


def test_event_quota_blocks(monkeypatch):
    monkeypatch.setitem(plans.PLANS["free"], "events", 2)
    app, c, key = _acct_app()
    prov = _stream(c, key)
    sid = prov["stream_id"]
    assert _ingest(c, prov["write_token"], _records(sid, 2)).status_code == 200
    over = _ingest(c, prov["write_token"], _records(sid, 1, start=2))
    assert over.status_code == 402
    assert "quota" in over.text.lower()


def test_stream_quota_blocks(monkeypatch):
    monkeypatch.setitem(plans.PLANS["free"], "streams", 1)
    app, c, key = _acct_app()
    _stream(c, key)  # first stream ok
    r = c.post("/v1/streams", json={"label": "second"},
               headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 402


def test_anchor_quota_blocks(monkeypatch):
    monkeypatch.setitem(plans.PLANS["free"], "anchors", 0)
    app, c, key = _acct_app()
    prov = _stream(c, key)
    _ingest(c, prov["write_token"], _records(prov["stream_id"], 1))
    r = c.post(f"/v1/streams/{prov['stream_id']}/anchor",
               headers={"Authorization": f"Bearer {prov['read_token']}"})
    assert r.status_code == 402


def test_set_plan_lifts_limits():
    app, c, key = _acct_app()
    r = c.put("/v1/account/plan", json={"plan": "team"},
              headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    body = c.get("/v1/usage", headers={"Authorization": f"Bearer {key}"}).json()
    assert body["plan"] == "team"
    assert body["limits"]["events"] == plans.PLANS["team"]["events"]
    assert body["features"]["exports"] is True


def test_set_plan_rejects_unknown():
    app, c, key = _acct_app()
    r = c.put("/v1/account/plan", json={"plan": "platinum"},
              headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 422


def test_open_mode_is_unmetered(monkeypatch):
    # require_account=False: no owner account, so quotas never apply.
    monkeypatch.setitem(plans.PLANS["free"], "events", 1)
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    assert _ingest(c, prov["write_token"], _records(prov["stream_id"], 10)).status_code == 200


# ---- feature gates: each paid capability is actually withheld on free ----

def _set_plan(c, key, plan):
    return c.put("/v1/account/plan", json={"plan": plan},
                 headers={"Authorization": f"Bearer {key}"})


def test_exports_feature_gated():
    app, c, key = _acct_app()
    prov = _stream(c, key)
    sid = prov["stream_id"]
    _ingest(c, prov["write_token"], _records(sid, 1))
    h = {"Authorization": f"Bearer {key}"}
    # Free: bulk NDJSON export withheld.
    assert c.get(f"/v1/streams/{sid}/export.ndjson", headers=h).status_code == 402
    # Team: unlocked.
    _set_plan(c, key, "team")
    assert c.get(f"/v1/streams/{sid}/export.ndjson", headers=h).status_code == 200


def test_reports_feature_gated():
    app, c, key = _acct_app()
    prov = _stream(c, key)
    sid = prov["stream_id"]
    _ingest(c, prov["write_token"], _records(sid, 1))
    h = {"Authorization": f"Bearer {key}"}
    # Free / Builder: attestation evidence pack withheld.
    assert c.get(f"/v1/streams/{sid}/evidence", headers=h).status_code == 402
    _set_plan(c, key, "builder")
    assert c.get(f"/v1/streams/{sid}/evidence", headers=h).status_code == 402
    # Team: unlocked.
    _set_plan(c, key, "team")
    assert c.get(f"/v1/streams/{sid}/evidence?regime=hipaa", headers=h).status_code == 200


def test_proof_links_feature_gated():
    app, c, key = _acct_app()
    prov = _stream(c, key)
    sid, share = prov["stream_id"], prov["share_token"]
    _ingest(c, prov["write_token"], _records(sid, 1))
    # Free: the shareable proof page does not resolve.
    assert c.get(f"/share/{share}").status_code == 402
    # Builder: proof links unlocked.
    _set_plan(c, key, "builder")
    assert c.get(f"/share/{share}").status_code == 200


class _FakeTrustedAnchor:
    """Stand-in TSA backend whose receipts claim a trusted (rfc3161) timestamp."""
    def anchor(self, leaves_hex):
        from provenrail.anchor import AnchorReceipt, merkle_root
        return AnchorReceipt(kind="rfc3161", merkle_root=merkle_root(leaves_hex),
                             gen_time="2026-06-10T00:00:00.000000Z", token_b64="ZmFrZQ==")


def test_trusted_time_downgraded_on_free():
    app = create_app(":memory:", anchor=_FakeTrustedAnchor(), require_account=True)
    c = TestClient(app)
    acct = provision_account("http://t", http=c)
    key = acct["api_key"]
    prov = _stream(c, key)
    sid = prov["stream_id"]
    _ingest(c, prov["write_token"], _records(sid, 1))
    rh = {"Authorization": f"Bearer {prov['read_token']}"}
    # Free: no trusted_time entitlement -> anchor falls back to the local (hash-only) backend.
    r = c.post(f"/v1/streams/{sid}/anchor", headers=rh)
    assert r.status_code == 200
    assert r.json()["receipt"]["kind"] == "local"
    # Builder: trusted_time unlocked -> the configured TSA backend is used for the next anchor.
    _set_plan(c, key, "builder")
    _ingest(c, prov["write_token"], _records(sid, 1, start=1))
    r2 = c.post(f"/v1/streams/{sid}/anchor", headers=rh)
    assert r2.status_code == 200
    assert r2.json()["receipt"]["kind"] == "rfc3161"


# ---- seats / multi-user gating (Team+) ----

def _set_plan(c, key, plan):
    return c.put("/v1/account/plan", json={"plan": plan},
                 headers={"Authorization": f"Bearer {key}"})


def test_members_seats_and_sso_entitlements():
    # Free/Builder are single-user; Team unlocks members + SSO; Enterprise is unlimited seats.
    assert plans.feature("free", "members") is False
    assert plans.feature("builder", "members") is False
    assert plans.feature("team", "members") is True
    assert plans.feature("team", "sso") is True
    assert plans.feature("enterprise", "members") is True
    assert plans.limit("free", "seats") == 1
    assert plans.limit("builder", "seats") == 1
    assert plans.limit("team", "seats") == 10
    assert plans.limit("enterprise", "seats") is None


def test_invite_blocked_on_free_and_builder():
    app, c, key = _acct_app()  # free
    h = {"Authorization": f"Bearer {key}"}
    assert c.post("/v1/members", json={"role": "member"}, headers=h).status_code == 402
    assert _set_plan(c, key, "builder").status_code == 200
    assert c.post("/v1/members", json={"role": "member"}, headers=h).status_code == 402


def test_team_seat_cap_is_ten_including_owner():
    app, c, key = _acct_app()
    h = {"Authorization": f"Bearer {key}"}
    assert _set_plan(c, key, "team").status_code == 200
    # owner counts as 1 of 10 -> exactly 9 invitable members
    for i in range(9):
        r = c.post("/v1/members", json={"role": "member", "email": f"m{i}@x.co"}, headers=h)
        assert r.status_code == 200, (i, r.text)
    over = c.post("/v1/members", json={"role": "member", "email": "m9@x.co"}, headers=h)
    assert over.status_code == 402


def test_sso_config_gated_to_team():
    app, c, key = _acct_app()  # free
    h = {"Authorization": f"Bearer {key}"}
    cfg = {"issuer": "https://idp", "audience": "a", "jwks": {"keys": []}, "default_role": "member"}
    assert c.put("/v1/sso/config", json=cfg, headers=h).status_code == 402
    assert _set_plan(c, key, "team").status_code == 200
    assert c.put("/v1/sso/config", json=cfg, headers=h).status_code == 200
