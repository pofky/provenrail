"""Run Explorer: pricing, analytics rollups, account-scoped API, ownership isolation."""
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.pricing import cost_for, resolve_price
from provenrail.sdk import FlightRecorder
from provenrail.server import analytics
from provenrail.server.app import create_app

# ---- pricing ----

def test_cost_for_known_model():
    c = cost_for("claude-opus-4-8", {"input": "1000000", "output": "1000000"})
    assert c["priced"] is True
    assert c["tokens_in"] == 1_000_000 and c["tokens_out"] == 1_000_000
    assert round(c["cost_usd"], 2) == 90.00  # 15 in + 75 out per 1M


def test_cost_for_unknown_model_is_unpriced():
    c = cost_for("some-local-llama-finetune-xyz", {"input": "10", "output": "5"})
    assert c["priced"] is False
    assert c["cost_usd"] == 0.0
    assert c["tokens_in"] == 10


def test_pricing_longest_match_wins():
    # gpt-4o-mini must resolve to the mini price, not gpt-4o
    assert resolve_price("gpt-4o-mini-2026") == (0.15, 0.60)
    assert resolve_price("gpt-4o-2026") == (2.50, 10.00)


def test_cost_handles_usage_key_variants():
    assert cost_for("gpt-4o", {"prompt_tokens": 100, "completion_tokens": 50})["tokens_in"] == 100
    assert cost_for("gpt-4o", {"in": "7", "out": "3"})["tokens_out"] == 3


# ---- analytics ----

def _run_session(c, prov, content=False):
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)

    @fr.tool("search")
    def search(q):
        return {"hits": 2}

    with fr.session({"agent": "demo", "task": "research"}):
        fr.record_model_call("anthropic", "claude-sonnet-4", {"q": "hi"}, {"a": "yo"},
                             usage={"input": "1000", "output": "500"})
        search("x")
        fr.record_decision("ship it")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})


def test_summarize_rolls_up_tokens_and_cost():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_session(c, prov)
    records = app.state.store.get_records(prov["stream_id"])
    summ = analytics.summarize(records)
    assert summ["totals"]["sessions"] == 1
    assert summ["totals"]["model_calls"] == 1
    assert summ["totals"]["tool_calls"] == 1
    assert summ["totals"]["tokens_in"] == 1000 and summ["totals"]["tokens_out"] == 500
    # claude-sonnet-4: 3 in + 15 out per 1M -> 1000*3/1e6 + 500*15/1e6 = 0.0105
    assert round(summ["totals"]["cost_usd"], 4) == 0.0105
    s = summ["sessions"][0]
    assert s["sealed"] is True and s["outcome"] == "success"
    assert "claude-sonnet-4" in s["models"]


# ---- dashboard API (open mode) ----

def test_overview_and_summary_open_mode():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_session(c, prov)
    ov = c.get("/v1/overview").json()
    assert ov["open_mode"] is True
    assert len(ov["streams"]) == 1
    assert ov["totals"]["model_calls"] == 1
    # local anchor only -> amber verdict
    assert ov["streams"][0]["verdict"]["state"] == "amber-proofs"

    summ = c.get(f"/v1/streams/{prov['stream_id']}/summary").json()
    assert summ["verdict"]["state"] == "amber-proofs"
    assert len(summ["sessions"]) == 1


def test_session_timeline_has_costed_model_call():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_session(c, prov)
    summ = c.get(f"/v1/streams/{prov['stream_id']}/summary").json()
    sid = summ["sessions"][0]["session_id"]
    tl = c.get(f"/v1/streams/{prov['stream_id']}/sessions/{sid}").json()
    mc = next(e for e in tl["events"] if e["action_type"] == "model_call")
    assert mc["cost"]["priced"] is True and mc["cost"]["cost_usd"] > 0
    assert mc["model"] == "claude-sonnet-4"


def test_account_bundle_export():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_session(c, prov)
    b = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    assert b["format"] == "flightrecorder.bundle/1"
    assert len(b["records"]) >= 4


def test_dashboard_page_served():
    app = create_app(":memory:", require_account=False)
    c = TestClient(app)
    r = c.get("/app")
    assert r.status_code == 200
    assert "Run Explorer" in r.text
    assert "text/html" in r.headers["content-type"]


def test_meta_reports_open_mode_and_events():
    open_app = TestClient(create_app(":memory:", require_account=False))
    m = open_app.get("/v1/meta").json()
    assert m["open_mode"] is True
    assert "integrity.tampered" in m["alert_events"]
    keyed = TestClient(create_app(":memory:", require_account=True))
    assert keyed.get("/v1/meta").json()["open_mode"] is False


# ---- ownership isolation (account mode) ----

def test_overview_is_account_scoped_and_blocks_cross_read():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True)
    c = TestClient(app)
    a = c.post("/v1/accounts", json={"label": "A"}).json()
    b = c.post("/v1/accounts", json={"label": "B"}).json()
    ha = {"Authorization": f"Bearer {a['api_key']}"}
    hb = {"Authorization": f"Bearer {b['api_key']}"}
    sa = c.post("/v1/streams", json={"label": "a-stream"}, headers=ha).json()
    c.post("/v1/streams", json={"label": "b-stream"}, headers=hb)

    # B's overview must not see A's stream
    ovb = c.get("/v1/overview", headers=hb).json()
    labels = {s["label"] for s in ovb["streams"]}
    assert "a-stream" not in labels and "b-stream" in labels

    # B cannot read A's stream summary
    r = c.get(f"/v1/streams/{sa['stream_id']}/summary", headers=hb)
    assert r.status_code == 403
    # and A can
    assert c.get(f"/v1/streams/{sa['stream_id']}/summary", headers=ha).status_code == 200


def test_overview_requires_key_in_account_mode():
    app = create_app(":memory:", require_account=True)
    c = TestClient(app)
    assert c.get("/v1/overview").status_code == 401


def _policy_stream():
    """A stream where the agent tried four risky things and the policy blocked them."""
    from provenrail.policy import Policy, PolicyViolation
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    policy = Policy.from_dict({"rules": [
        {"id": "no-delete", "effect": "deny", "event_type": "tool_call", "tool": "delete_*",
         "reason": "destructive tool"},
        {"id": "no-secrets", "effect": "deny", "event_type": "tool_call",
         "arg_contains": r"AKIA[0-9A-Z]{8}", "reason": "looks like an AWS key"},
    ]})
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c, policy=policy)
    with fr.session():
        for tool, args in [("delete_database", {"db": "prod"}),
                           ("post_message", {"text": "AKIA12345678"}),
                           ("send_email", {"to": "ok"})]:
            try:
                fr.record_tool_call(tool, args, "ok")
            except PolicyViolation:
                pass
    return c, prov


def test_policy_denials_are_counted_in_the_rollup():
    """A blocked action must be visible without reading raw records."""
    c, prov = _policy_stream()
    s = c.get(f"/v1/streams/{prov['stream_id']}/summary",
              headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert s["totals"]["policy_denials"] == 2
    assert set(s["sessions"][0]["denied_rules"]) == {"no-delete", "no-secrets"}


def test_policy_denials_have_a_readable_summary_line():
    """These render in the dashboard timeline and the SIEM export; a blank line there
    means a blocked action looks like nothing happened."""
    c, prov = _policy_stream()
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    sid = exp["records"][0]["record"]["session_id"]
    tl = c.get(f"/v1/streams/{prov['stream_id']}/sessions/{sid}",
               headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    denials = [e for e in tl["events"] if e["action_type"] == "policy.decision"]
    assert denials, "policy decisions must appear in the timeline"
    for e in denials:
        assert e["summary"].strip(), "a policy decision must never render as a blank line"
    assert any("DENY" in e["summary"] and "destructive tool" in e["summary"] for e in denials)


def test_policy_denials_carry_a_summary_into_the_siem_export():
    import json as _json
    c, prov = _policy_stream()
    r = c.get(f"/v1/streams/{prov['stream_id']}/export.ndjson",
              headers={"Authorization": f"Bearer {prov['read_token']}"})
    lines = [_json.loads(x) for x in r.text.strip().split("\n")]
    pol = [x for x in lines if x["action"] == "policy.decision"]
    assert pol and all(x["summary"].strip() for x in pol)
