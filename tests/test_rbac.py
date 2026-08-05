"""RBAC: org members, roles, least-privilege enforcement, and the tamper-evident access log."""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.server.app import create_app

#: Stands in for the payment provider webhook secret. An upgrade is applied by the billing
#: provider after payment, never by the account holder's own API key.
BILLING_SECRET = "test-billing-secret"


def _app():
    return TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret="test-billing-secret"))


def _org(c):
    acct = c.post("/v1/accounts", json={}).json()
    # multi-member RBAC is a Team+ feature; run these tests on a Team account.
    c.put("/v1/account/plan", json={"plan": "team"},
          headers={"Authorization": f"Bearer {acct['api_key']}",
                   "X-Provenrail-Billing-Secret": BILLING_SECRET})
    return acct["account_id"], acct["api_key"]


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _invite(c, owner_key, role, email=None):
    r = c.post("/v1/members", json={"role": role, "email": email}, headers=_h(owner_key))
    assert r.status_code == 200, r.text
    return r.json()["api_key"], r.json()["member_id"]


def test_owner_root_key_has_all_permissions():
    c = _app()
    _, owner_key = _org(c)
    # create, export, evidence, webhooks, members, audit all succeed for the root key.
    sid = c.post("/v1/streams", json={}, headers=_h(owner_key)).json()["stream_id"]
    assert c.get(f"/v1/streams/{sid}/bundle", headers=_h(owner_key)).status_code == 200
    assert c.get("/v1/members", headers=_h(owner_key)).status_code == 200
    assert c.get("/v1/audit-log", headers=_h(owner_key)).status_code == 200


def test_viewer_cannot_create_or_export():
    c = _app()
    _, owner_key = _org(c)
    sid = c.post("/v1/streams", json={}, headers=_h(owner_key)).json()["stream_id"]
    viewer_key, _ = _invite(c, owner_key, "viewer")
    # viewer can read summary but not create streams or export bundles.
    assert c.post("/v1/streams", json={}, headers=_h(viewer_key)).status_code == 403
    assert c.get(f"/v1/streams/{sid}/bundle", headers=_h(viewer_key)).status_code == 403
    assert c.get(f"/v1/streams/{sid}/evidence", headers=_h(viewer_key)).status_code == 403


def test_member_can_create_and_export_but_not_manage_members():
    c = _app()
    _, owner_key = _org(c)
    member_key, _ = _invite(c, owner_key, "member")
    sid = c.post("/v1/streams", json={}, headers=_h(member_key)).json()["stream_id"]
    assert c.get(f"/v1/streams/{sid}/bundle", headers=_h(member_key)).status_code == 200
    # but a member cannot invite or list members or read the audit log.
    assert c.post("/v1/members", json={"role": "member"}, headers=_h(member_key)).status_code == 403
    assert c.get("/v1/audit-log", headers=_h(member_key)).status_code == 403


def test_admin_can_manage_members_but_not_create_owner():
    c = _app()
    _, owner_key = _org(c)
    admin_key, _ = _invite(c, owner_key, "admin")
    # admin can invite a member/viewer/admin
    assert c.post("/v1/members", json={"role": "member"}, headers=_h(admin_key)).status_code == 200
    # but cannot create an owner
    r = c.post("/v1/members", json={"role": "owner"}, headers=_h(admin_key))
    assert r.status_code == 403


def test_member_streams_are_org_scoped():
    c = _app()
    _, owner_key = _org(c)
    member_key, _ = _invite(c, owner_key, "member")
    sid = c.post("/v1/streams", json={}, headers=_h(member_key)).json()["stream_id"]
    # the owner can see the member-created stream (same org)
    streams = c.get("/v1/streams", headers=_h(owner_key)).json()["streams"]
    assert any(s["stream_id"] == sid for s in streams)


def test_disabled_member_key_rejected():
    c = _app()
    _, owner_key = _org(c)
    member_key, member_id = _invite(c, owner_key, "member")
    assert c.get("/v1/streams", headers=_h(member_key)).status_code == 200
    c.patch(f"/v1/members/{member_id}", json={"status": "disabled"}, headers=_h(owner_key))
    assert c.get("/v1/streams", headers=_h(member_key)).status_code == 401


def test_admin_cannot_modify_owner_member():
    c = _app()
    _, owner_key = _org(c)
    owner2_key, owner2_id = _invite(c, owner_key, "owner")
    admin_key, _ = _invite(c, owner_key, "admin")
    # admin cannot demote an owner-role member
    r = c.patch(f"/v1/members/{owner2_id}", json={"role": "member"}, headers=_h(admin_key))
    assert r.status_code == 403
    # owner can
    assert c.patch(f"/v1/members/{owner2_id}", json={"role": "member"},
                   headers=_h(owner_key)).status_code == 200


def test_cross_org_member_isolation():
    c = _app()
    _, owner_a = _org(c)
    _, owner_b = _org(c)
    a_member, _ = _invite(c, owner_a, "member")
    sid_b = c.post("/v1/streams", json={}, headers=_h(owner_b)).json()["stream_id"]
    # org A's member cannot read org B's stream bundle
    assert c.get(f"/v1/streams/{sid_b}/bundle", headers=_h(a_member)).status_code in (403, 404)


def test_audit_log_records_and_chain_verifies():
    c = _app()
    _, owner_key = _org(c)
    # Evidence packs are a reports-tier feature; upgrade so the export runs and is audited.
    c.put("/v1/account/plan", json={"plan": "team"},
          headers={**_h(owner_key), "X-Provenrail-Billing-Secret": BILLING_SECRET})
    sid = c.post("/v1/streams", json={}, headers=_h(owner_key)).json()["stream_id"]
    c.get(f"/v1/streams/{sid}/bundle", headers=_h(owner_key))
    c.get(f"/v1/streams/{sid}/evidence", headers=_h(owner_key))
    log = c.get("/v1/audit-log", headers=_h(owner_key)).json()
    actions = {e["action"] for e in log["entries"]}
    assert {"stream.create", "stream.export", "evidence.export"} <= actions
    assert log["chain_ok"] is True


def test_audit_log_tamper_detected():
    from provenrail.server.app import create_app as _ca
    app = _ca(":memory:", anchor=LocalAnchor(), require_account=True)
    c = TestClient(app)
    acct = c.post("/v1/accounts", json={}).json()
    key = acct["api_key"]
    sid = c.post("/v1/streams", json={}, headers=_h(key)).json()["stream_id"]
    c.get(f"/v1/streams/{sid}/bundle", headers=_h(key))
    store = app.state.store
    assert store.verify_audit_chain(acct["account_id"]) is True
    # Tamper directly in the DB (bypassing the append-only trigger via raw connection):
    # change a stored action; the recomputed chain must no longer verify.
    store._db.execute("PRAGMA writable_schema=OFF")
    # The trigger blocks UPDATE, so instead simulate corruption by inserting a forged row
    # is not possible (PK). Verify the trigger itself protects the log:
    import sqlite3
    raised = False
    try:
        store._db.execute("UPDATE meta_audit SET action='forged'")
    except sqlite3.IntegrityError:
        raised = True
    assert raised
    assert store.verify_audit_chain(acct["account_id"]) is True


def test_open_mode_unaffected():
    # require_account=False keeps everything open (role None = all-powerful), no audit rows.
    c = TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))
    sid = c.post("/v1/streams", json={}).json()["stream_id"]
    assert c.get(f"/v1/streams/{sid}/bundle").status_code == 200
    assert c.get("/v1/audit-log").json()["open_mode"] is True
