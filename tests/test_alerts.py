"""Integrity alerting: signed webhook delivery, transition detection, webhook API."""
import copy
import types

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.chain import _utc_now_iso
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server import notifier
from provenrail.server.alerts import AlertEngine
from provenrail.server.app import create_app
from provenrail.server.storage import Storage

# ---- notifier ----

def test_sign_is_hmac_and_stable():
    a = notifier.sign("s3cr3t", b"hello")
    b = notifier.sign("s3cr3t", b"hello")
    assert a == b and a.startswith("sha256=")
    assert notifier.sign("other", b"hello") != a


def test_deliver_success_and_failure_with_fake_client():
    seen = {}

    class OK:
        def post(self, url, content, headers):
            seen["url"] = url
            seen["sig"] = headers[notifier.SIGNATURE_HEADER]
            seen["body"] = content
            return types.SimpleNamespace(status_code=200)

    assert notifier.deliver("http://x/hook", "sec", {"type": "integrity.tampered"}, http=OK()) is True
    assert seen["url"] == "http://x/hook"
    assert seen["sig"] == notifier.sign("sec", seen["body"])

    class Bad:
        def post(self, url, content, headers):
            return types.SimpleNamespace(status_code=500)

    assert notifier.deliver("http://x", "sec", {"type": "x"}, http=Bad(), max_retries=1) is False


# ---- alert engine transitions ----

def _seed_bundle():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("a")
        fr.record_decision("b")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    return app.state.store, prov["stream_id"], bundle


def test_engine_fires_on_transition_to_tampered_and_recovered():
    store, sid, bundle = _seed_bundle()
    store.create_webhook("wh_1", None, "http://hook", "sec", "*")
    sent = []

    def deliver(url, secret, event):
        sent.append(event)
        return True

    eng = AlertEngine(store, deliver, _utc_now_iso)

    # first observation: amber (local anchor only), no alert event for amber
    r1 = eng.check_stream(sid, bundle, None)
    assert r1["state"] == "amber-proofs" and r1["fired"] == 0

    # tamper the bundle -> transition amber->tampered fires integrity.tampered
    bad = copy.deepcopy(bundle)
    bad["records"][1]["record"]["payload"]["summary"] = "edited"
    r2 = eng.check_stream(sid, bad, None)
    assert r2["state"] == "tampered" and "integrity.tampered" in r2["events"] and r2["fired"] == 1
    assert sent[-1]["type"] == "integrity.tampered"
    assert sent[-1]["stream_id"] == sid

    # back to clean -> recovered
    r3 = eng.check_stream(sid, bundle, None)
    assert r3["state"] == "amber-proofs" and "integrity.recovered" in r3["events"]


def test_engine_respects_event_subscription_filter():
    store, sid, bundle = _seed_bundle()
    store.create_webhook("wh_only_recover", None, "http://hook", "sec", "integrity.recovered")
    fired = []
    eng = AlertEngine(store, lambda u, s, e: fired.append(e) or True, _utc_now_iso)
    eng.check_stream(sid, bundle, None)  # amber, sets state
    bad = copy.deepcopy(bundle)
    bad["records"][1]["record"]["payload"]["summary"] = "x"
    r = eng.check_stream(sid, bad, None)  # tampered, but hook only wants 'recovered'
    assert r["state"] == "tampered" and r["fired"] == 0  # filtered out


def test_engine_no_event_for_empty_bundle():
    store = Storage(":memory:")
    eng = AlertEngine(store, lambda *a: True, _utc_now_iso)
    r = eng.check_stream("s", {"format": "flightrecorder.bundle/1", "records": []}, None)
    assert r["state"] == "empty" and r["fired"] == 0


# ---- webhook API ----

def test_webhook_crud_account_mode():
    app = create_app(":memory:", require_account=True)
    c = TestClient(app)
    acct = c.post("/v1/accounts", json={"label": "a"}).json()
    h = {"Authorization": f"Bearer {acct['api_key']}"}
    r = c.post("/v1/webhooks", json={"url": "https://ops.example/hook",
                                     "events": ["integrity.tampered"]}, headers=h)
    assert r.status_code == 200
    wh = r.json()
    assert wh["secret"].startswith("whsec_") and wh["events"] == "integrity.tampered"
    lst = c.get("/v1/webhooks", headers=h).json()["webhooks"]
    assert len(lst) == 1 and "secret" not in lst[0]  # secret never re-exposed
    assert c.delete(f"/v1/webhooks/{wh['webhook_id']}", headers=h).status_code == 200
    assert len(c.get("/v1/webhooks", headers=h).json()["webhooks"]) == 0


def test_webhook_rejects_bad_url_and_event():
    app = create_app(":memory:", require_account=False)
    c = TestClient(app)
    assert c.post("/v1/webhooks", json={"url": "ftp://x"}).status_code == 422
    assert c.post("/v1/webhooks", json={"url": "https://x", "events": ["nope"]}).status_code == 422


def test_webhooks_are_account_isolated():
    app = create_app(":memory:", require_account=True)
    c = TestClient(app)
    a = c.post("/v1/accounts", json={}).json()
    b = c.post("/v1/accounts", json={}).json()
    ha = {"Authorization": f"Bearer {a['api_key']}"}
    hb = {"Authorization": f"Bearer {b['api_key']}"}
    wh = c.post("/v1/webhooks", json={"url": "https://a/hook"}, headers=ha).json()
    # B cannot see or delete A's webhook
    assert len(c.get("/v1/webhooks", headers=hb).json()["webhooks"]) == 0
    assert c.delete(f"/v1/webhooks/{wh['webhook_id']}", headers=hb).status_code == 404


def test_manual_anchor_runs_alert_hook_and_persists_state(monkeypatch):
    # the wired scheduler path must record integrity state after a manual anchor
    delivered = []
    monkeypatch.setattr(notifier, "deliver", lambda u, s, e: delivered.append(e) or True)
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    c.post("/v1/webhooks", json={"url": "http://hook"})
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    # local anchor only -> amber state recorded, no alert event (amber is not an alert trigger)
    assert app.state.store.get_stream_state(prov["stream_id"]) == "amber-proofs"
    assert delivered == []


def test_the_documented_verification_recipe_is_the_one_the_sink_actually_uses():
    """The docs hand a receiver a snippet and tell them to trust it. If the snippet and the
    signer ever disagree, every honest delivery starts failing verification, and the natural
    fix a user reaches for is to stop checking the signature at all.

    So this pins the three things the snippet depends on: the MAC is over the raw body bytes
    before any parsing, it is prefixed `sha256=`, and the replay material the snippet reads
    (`id` and `at`) is inside the signed body rather than a header, where it cannot be stripped
    in transit.
    """
    import hashlib
    import hmac
    import json
    import re
    from pathlib import Path

    from provenrail.server import notifier

    secret = "whsec_example"
    event = {"id": "abc123", "type": "integrity.tampered", "stream_id": "s1",
             "at": "2026-08-05T12:00:00Z"}
    raw = json.dumps(event).encode("utf-8")
    assert notifier.sign(secret, raw) == \
        "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()

    # Whatever the sink puts on the wire must be exactly what it signed.
    sent = {}
    class _Client:
        def post(self, url, content, headers, **kw):
            sent["body"], sent["sig"] = content, headers["X-Provenrail-Signature"]
            class R:
                status_code = 200
            return R()
        def close(self): pass
    assert notifier.deliver("https://ops.example/hook", secret, event, http=_Client())
    assert sent["sig"] == "sha256=" + hmac.new(
        secret.encode(), sent["body"], hashlib.sha256).hexdigest()
    body = json.loads(sent["body"])
    assert body["id"] and body["at"], "replay material must travel inside the signed body"

    docs = Path(__file__).resolve().parents[1] / "web" / "docs.html"
    text = docs.read_text(encoding="utf-8")
    assert "hmac.compare_digest" in text, "the docs must tell receivers to compare in constant time"
    assert re.search(r'hmac\.new\(secret\.encode\(\),\s*raw_body,\s*hashlib\.sha256\)', text), \
        "the documented MAC must be taken over the raw body"
    assert 'event["id"]' in text and 'event["at"]' in text, \
        "the docs must show the replay check the payload makes possible"
