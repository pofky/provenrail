"""Public hosted verifier endpoint, embeddable badge, and verify page."""
import copy

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.server.badges import render_badge


def _seeded():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_model_call("anthropic", "claude-sonnet-4", {"q": "hi"}, {"a": "yo"},
                             usage={"input": "100", "output": "50"})
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    return c, prov, bundle


# ---- badge SVG ----

def test_render_badge_states():
    for state, needle in [("verified", "integrity verified"), ("amber", "no timestamp"),
                          ("tampered", "tampering detected"), ("empty", "no records"),
                          ("unknown", "unknown")]:
        svg = render_badge(state)
        assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
        assert needle in svg


def test_badge_endpoint_returns_svg():
    c, prov, _ = _seeded()
    r = c.get(f"/badge/{prov['share_token']}.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    # local anchor only, append-only proofs present, unwitnessed -> amber-proofs
    assert "proofs, not witnessed" in r.text


def test_badge_unknown_token_still_returns_svg():
    c, _, _ = _seeded()
    r = c.get("/badge/not-a-real-token.svg")
    assert r.status_code == 200
    assert "<svg" in r.text and "unknown" in r.text


# ---- hosted verify endpoint ----

def test_verify_endpoint_passes_clean_bundle():
    c, _, bundle = _seeded()
    rep = c.post("/v1/verify", json={"bundle": bundle}).json()
    assert rep["ok"] is True
    codes = {f["code"] for f in rep["findings"]}
    assert "local_anchor_only" in codes  # amber, honest


def test_verify_endpoint_detects_tampering():
    c, _, bundle = _seeded()
    bad = copy.deepcopy(bundle)
    bad["records"][1]["record"]["payload"]["model"] = "evil"
    rep = c.post("/v1/verify", json={"bundle": bad}).json()
    assert rep["ok"] is False
    assert rep["fail"] >= 1


def test_verify_endpoint_rejects_oversized_bundle():
    app = create_app(":memory:", require_account=False, max_verify_bytes=500)
    c = TestClient(app)
    big = {"format": "flightrecorder.bundle/1", "records": [{"x": "y" * 2000}]}
    r = c.post("/v1/verify", json={"bundle": big})
    assert r.status_code == 413


def test_verify_endpoint_rate_limited():
    app = create_app(":memory:", require_account=False, verify_per_min=1)
    c = TestClient(app)
    body = {"bundle": {"format": "flightrecorder.bundle/1", "records": []}}
    assert c.post("/v1/verify", json=body).status_code == 200
    assert c.post("/v1/verify", json=body).status_code == 429


# ---- pages ----

def test_verify_page_served():
    c, _, _ = _seeded()
    r = c.get("/verify")
    assert r.status_code == 200 and "Verify a record" in r.text
    assert "/v1/verify" in r.text


def test_verify_js_served():
    c, _, _ = _seeded()
    r = c.get("/verify.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/javascript")
    assert "verifyBundle" in r.text and "Ed25519" in r.text


def test_share_page_includes_embed_badge():
    c, prov, _ = _seeded()
    r = c.get(f"/share/{prov['share_token']}")
    assert r.status_code == 200
    assert f"/badge/{prov['share_token']}.svg" in r.text
    assert "Embed a live badge" in r.text
    assert "/verify" in r.text


# ---- transparency-log badge states ----

def test_render_badge_tlog_states():
    from provenrail.server.badges import render_badge
    for state, needle in [("witnessed", "verified + witnessed"),
                          ("amber-proofs", "proofs, not witnessed")]:
        svg = render_badge(state)
        assert svg.startswith("<svg") and needle in svg


def test_badge_endpoint_witnessed_green():
    from provenrail.server.witness import LocalWitness
    witness = LocalWitness("witness-A")
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     tlog_witnesses=[witness])
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    r = c.get(f"/badge/{prov['share_token']}.svg")
    assert r.status_code == 200
    assert "verified + witnessed" in r.text


def test_share_page_shows_witness_section():
    from provenrail.server.witness import LocalWitness
    witness = LocalWitness("witness-A")
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     tlog_witnesses=[witness])
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    html = c.get(f"/share/{prov['share_token']}").text
    assert "transparency log" in html
    assert "witnessed by 1 independent party" in html
