"""The full risky-behaviour workflow, end to end.

Covers the path an operator actually walks: declare guardrails in .provenrail.json, run an
agent that tries something forbidden, get alerted immediately, then review it afterwards
from the dashboard API, the SIEM export, and the offline CLI.
"""
import json

import pytest
from fastapi.testclient import TestClient

from provenrail import easy
from provenrail.anchor import LocalAnchor
from provenrail.easy import PolicyConfigError, load_policy
from provenrail.ingest_client import provision_stream
from provenrail.policy import PolicyViolation
from provenrail.sdk import FlightRecorder
from provenrail.server.alerts import EVENTS, POLICY_DENIED, AlertEngine
from provenrail.server.app import create_app

POLICY_SPEC = {
    "rules": [
        {"id": "no-destructive-tools", "effect": "deny", "event_type": "tool_call",
         "tool": "delete_*", "reason": "destructive tool"},
        {"id": "no-credentials-in-args", "effect": "deny", "event_type": "tool_call",
         "arg_contains": r"AKIA[0-9A-Z]{8}", "reason": "argument looks like an AWS key"},
        {"id": "wire-needs-human", "effect": "require_oversight", "event_type": "tool_call",
         "tool": "wire_transfer", "reason": "a human must approve a wire"},
        {"id": "email-burst", "effect": "limit", "event_type": "tool_call",
         "tool": "send_email", "max_per_session": 2},
    ],
    "session_spend_cap_usd": 5.0,
}


class CapturingDeliver:
    """Stands in for the webhook receiver, recording what it was sent and when."""

    def __init__(self):
        self.events = []

    def __call__(self, url, secret, event, **kw):
        self.events.append((url, event))
        return True


# --------------------------------------------------------------------------------------
# Configuring guardrails without writing Python
# --------------------------------------------------------------------------------------

def test_policy_loads_from_a_config_file_dict():
    policy = load_policy(POLICY_SPEC)
    assert len(policy.rules) == 4
    assert policy.session_spend_cap_usd == 5.0


def test_policy_loads_from_a_json_file_path(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(POLICY_SPEC), encoding="utf-8")
    assert len(load_policy(str(p)).rules) == 4


def test_record_picks_up_a_policy_declared_in_the_config_file(tmp_path, monkeypatch):
    """The deployment owner can add guardrails without touching the agent's code."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    cfg = {"endpoint": "http://t", "write_token": prov["write_token"],
           "stream_id": prov["stream_id"], "policy": POLICY_SPEC}
    (tmp_path / ".provenrail.json").write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    easy._GLOBAL.clear()

    rec = easy.make_recorder("agent-under-config", http=c)
    assert rec.policy is not None, "a policy in .provenrail.json must take effect"
    with rec.session():
        with pytest.raises(PolicyViolation):
            rec.record_tool_call("delete_everything", {"x": 1}, "ok")


@pytest.mark.parametrize(("spec", "fragment"), [
    ({"rules": [{"effect": "deny"}]}, 'needs a string "id"'),
    ({"rules": [{"id": "a", "effect": "destroy"}]}, "expected one of"),
    ({"rules": [{"id": "a", "effect": "limit"}]}, "max_per_session"),
    ({"rules": [{"id": "a", "effect": "deny", "arg_contains": "([bad"}]}, "invalid arg_contains"),
    ({"rules": [{"id": "a", "effect": "deny", "toool": "x"}]}, "unknown field"),
    ({"rules": [{"id": "a", "effect": "deny"}, {"id": "a", "effect": "deny"}]}, "duplicate"),
    ({"rules": "not-a-list"}, "must be a list"),
    ({"rules": [{"id": "a", "effect": "deny"}], "session_spend_cap_usd": "lots"}, "must be a number"),
])
def test_malformed_policies_are_rejected_loudly(spec, fragment):
    """A typo that silently disables a guardrail is the worst outcome for this feature:
    the operator believes they are protected and is not."""
    with pytest.raises(PolicyConfigError, match=fragment):
        load_policy(spec)


def test_a_misspelled_tool_field_cannot_silently_widen_a_rule():
    # "tol" instead of "tool" would leave tool="*", blocking every tool call rather than
    # the intended delete_*. Rejected rather than applied.
    with pytest.raises(PolicyConfigError):
        load_policy({"rules": [{"id": "oops", "effect": "deny", "tol": "delete_*"}]})


# --------------------------------------------------------------------------------------
# Detecting the denial
# --------------------------------------------------------------------------------------

def test_policy_denied_is_a_registered_alert_event():
    assert POLICY_DENIED in EVENTS


def test_denials_in_extracts_only_blocked_actions():
    records = [
        {"record": {"action_type": "policy.decision", "session_id": "s", "seq": 1,
                    "payload": {"effect": "deny", "rule": "r1", "reason": "why",
                                "event_type": "tool_call", "target": "delete_db"}}},
        {"record": {"action_type": "policy.decision", "session_id": "s", "seq": 2,
                    "payload": {"effect": "allow", "rule": "r2"}}},
        {"record": {"action_type": "tool_call", "session_id": "s", "seq": 3, "payload": {}}},
    ]
    denials = AlertEngine.denials_in(records)
    assert len(denials) == 1
    assert denials[0]["rule"] == "r1"
    assert denials[0]["target"] == "delete_db"
    assert denials[0]["reason"] == "why"


def test_denials_in_tolerates_junk_records():
    assert AlertEngine.denials_in([]) == []
    assert AlertEngine.denials_in([{}, {"record": {}}, {"record": {"payload": None}}]) == []


# --------------------------------------------------------------------------------------
# Alerting instantly, at ingest, not at the next anchor
# --------------------------------------------------------------------------------------

def _run_agent_against(c, prov, policy_spec=POLICY_SPEC):
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=load_policy(policy_spec))
    blocked = []
    with fr.session():
        for tool, args in [("delete_database", {"db": "prod"}),
                           ("post_message", {"text": "creds AKIA12345678 here"}),
                           ("send_email", {"to": "a"})]:
            try:
                fr.record_tool_call(tool, args, "ok")
            except PolicyViolation as e:
                blocked.append(e.rule_id)
    return fr, blocked


def test_check_records_emits_one_event_per_denial_with_full_context():
    class Store:
        def webhooks_for_delivery(self, account_id):
            return [{"url": "https://ops.example/hook", "secret": "s", "events": "*"}]

    sink = CapturingDeliver()
    engine = AlertEngine(Store(), sink, lambda: "2026-07-30T00:00:00.000000Z")
    records = [
        {"record": {"action_type": "policy.decision", "session_id": "sess-1", "seq": 4,
                    "record_hash": "abc", "ts_utc": "2026-07-30T00:00:00.000000Z",
                    "payload": {"effect": "deny", "rule": "wire-needs-human",
                                "reason": "a human must approve a wire",
                                "event_type": "tool_call", "target": "wire_transfer"}}},
        {"record": {"action_type": "policy.decision", "session_id": "sess-1", "seq": 5,
                    "payload": {"effect": "deny", "rule": "no-destructive-tools",
                                "reason": "destructive tool", "event_type": "tool_call",
                                "target": "delete_database"}}},
    ]
    out = engine.check_records("stream-1", records, None)
    assert out == {"denials": 2, "budget_events": 0, "fired": 2}
    # One event per denial: collapsing them would lose the rule/target detail that makes
    # the alert actionable.
    assert len(sink.events) == 2
    first = sink.events[0][1]
    assert first["type"] == POLICY_DENIED
    assert first["stream_id"] == "stream-1"
    assert first["denial"]["rule"] == "wire-needs-human"
    assert first["denial"]["target"] == "wire_transfer"
    assert first["denial"]["session_id"] == "sess-1"
    assert first["denial"]["reason"] == "a human must approve a wire"
    assert first["id"] and first["at"]


def test_only_subscribers_to_this_event_are_notified():
    class Store:
        def webhooks_for_delivery(self, account_id):
            return [{"url": "https://a", "secret": "s", "events": "integrity.tampered"},
                    {"url": "https://b", "secret": "s", "events": POLICY_DENIED},
                    {"url": "https://c", "secret": "s", "events": "*"}]

    sink = CapturingDeliver()
    engine = AlertEngine(Store(), sink, lambda: "t")
    engine.check_records("s1", [{"record": {"action_type": "policy.decision", "seq": 1,
                                            "payload": {"effect": "deny", "rule": "r"}}}], None)
    urls = sorted(u for u, _ in sink.events)
    assert urls == ["https://b", "https://c"]


def test_a_failing_webhook_never_breaks_the_alert_loop():
    class Store:
        def webhooks_for_delivery(self, account_id):
            return [{"url": "https://dead", "secret": "s", "events": "*"},
                    {"url": "https://alive", "secret": "s", "events": "*"}]

    calls = []

    def flaky(url, secret, event, **kw):
        calls.append(url)
        if url == "https://dead":
            raise RuntimeError("connection refused")
        return True

    engine = AlertEngine(Store(), flaky, lambda: "t")
    out = engine.check_records("s1", [{"record": {"action_type": "policy.decision", "seq": 1,
                                                  "payload": {"effect": "deny", "rule": "r"}}}],
                               None)
    assert out["fired"] == 1          # the healthy endpoint still got it
    assert "https://alive" in calls   # a dead endpoint does not stop the next one


def test_ingesting_a_denial_does_not_slow_or_break_the_agent():
    """Alert delivery runs off the request path, so a hung webhook cannot stall ingest."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr, blocked = _run_agent_against(c, prov)
    assert blocked == ["no-destructive-tools", "no-credentials-in-args"]
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert exp["records"], "records still land normally while alerting happens"


# --------------------------------------------------------------------------------------
# Reviewing it afterwards
# --------------------------------------------------------------------------------------

def test_the_full_operator_workflow_end_to_end(tmp_path):
    """Config file -> agent blocked -> counted -> readable -> exportable -> verifiable."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr, blocked = _run_agent_against(c, prov)
    hdr = {"Authorization": f"Bearer {prov['read_token']}"}

    # 1. Counted in the rollup, so a denial is visible without reading raw records.
    summary = c.get(f"/v1/streams/{prov['stream_id']}/summary", headers=hdr).json()
    assert summary["totals"]["policy_denials"] == 2
    assert set(summary["sessions"][0]["denied_rules"]) == {"no-destructive-tools",
                                                           "no-credentials-in-args"}

    # 2. Readable in the timeline (this rendered as a blank line before).
    sid = summary["sessions"][0]["session_id"]
    tl = c.get(f"/v1/streams/{prov['stream_id']}/sessions/{sid}", headers=hdr).json()
    denial_lines = [e["summary"] for e in tl["events"]
                    if e["action_type"] == "policy.decision" and "DENY" in e["summary"]]
    assert len(denial_lines) == 2
    assert all(line.strip() for line in denial_lines)
    assert any("destructive tool" in line for line in denial_lines)

    # 3. Exportable to a SIEM with a populated summary field.
    nd = c.get(f"/v1/streams/{prov['stream_id']}/export.ndjson", headers=hdr)
    lines = [json.loads(x) for x in nd.text.strip().split("\n")]
    pol = [x for x in lines if x["action"] == "policy.decision"]
    assert pol and all(x["summary"].strip() for x in pol)

    # 4. Still verifiable: the denials are inside the signed chain, not beside it.
    from provenrail.verifier.verify import verify_bundle
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle", headers=hdr).json()
    assert verify_bundle(bundle).ok

    # 5. Reviewable offline with the CLI, which exits non-zero so CI can gate on it.
    from provenrail.cli import main
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main(["risk", str(path)]) == 1
    assert main(["risk", str(path), "--json"]) == 1


def test_risk_command_is_explicit_when_no_policy_was_in_force(tmp_path, capsys):
    """Silence must not read as safety: no denials because no policy is not the same as
    no denials because nothing bad happened."""
    from provenrail.cli import main
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_tool_call("delete_database", {"db": "prod"}, "ok")  # nothing blocks it
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")

    assert main(["risk", str(path)]) == 0
    out = capsys.readouterr().out
    assert "no policy was in force" in out
    assert "NOT the same as" in out


def test_risk_command_json_output_is_machine_readable(tmp_path, capsys):
    from provenrail.cli import main
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_agent_against(c, prov)
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")

    main(["risk", str(path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["policy_enforced"] is True
    assert len(data["denials"]) == 2
    assert {d["rule"] for d in data["denials"]} == {"no-destructive-tools",
                                                   "no-credentials-in-args"}


# --------------------------------------------------------------------------------------
# The real ingest path, not a hand-driven engine
# --------------------------------------------------------------------------------------

def test_real_ingest_of_a_denial_delivers_a_signed_webhook(monkeypatch):
    """End to end through the actual HTTP route: an agent's blocked action must produce a
    delivered, HMAC-signed alert without any anchor having run."""
    import threading as _threading

    from provenrail.server import notifier

    delivered = []
    done = _threading.Event()

    def fake_deliver(url, secret, event, **kw):
        body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        delivered.append({"url": url, "event": event,
                          "signature": notifier.sign(secret, body)})
        done.set()
        return True

    monkeypatch.setattr(notifier, "deliver", fake_deliver)

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    app.state.store.create_webhook("wh_test", None, "https://ops.example/hook",
                                   "whsec_testsecret", "*")

    fr, blocked = _run_agent_against(c, prov)
    assert blocked, "the policy must have blocked something for this test to mean anything"

    assert done.wait(timeout=10), "no alert was delivered within 10s of ingest"
    # The alert thread may still be finishing the second denial.
    for _ in range(100):
        if len(delivered) >= 2:
            break
        _threading.Event().wait(0.05)

    assert len(delivered) >= 1
    types = {d["event"]["type"] for d in delivered}
    assert types == {POLICY_DENIED}
    rules = {d["event"]["denial"]["rule"] for d in delivered}
    assert "no-destructive-tools" in rules
    for d in delivered:
        assert d["signature"].startswith("sha256=")  # every delivery is signed
        assert d["event"]["denial"]["target"]
        assert d["event"]["denial"]["session_id"]

    # No anchor ran: this fired purely on ingest.
    assert app.state.store.get_stream_state(prov["stream_id"]) is None


def test_clean_ingest_starts_no_alert_thread(monkeypatch):
    """A stream with no denials must not pay any alerting cost at all."""
    from provenrail.server import notifier

    calls = []
    monkeypatch.setattr(notifier, "deliver",
                        lambda *a, **k: calls.append(a) or True)

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    app.state.store.create_webhook("wh_test", None, "https://ops.example/hook", "s", "*")

    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_tool_call("send_email", {"to": "a"}, "ok")
    assert calls == []


def test_webhook_registration_accepts_the_new_event_name():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    r = c.post("/v1/webhooks", json={"url": "https://ops.example/hook",
                                     "events": [POLICY_DENIED]})
    assert r.status_code == 200, r.text
    assert r.json()["events"] == POLICY_DENIED


def test_meta_endpoint_advertises_the_new_event():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    meta = c.get("/v1/meta").json()
    assert POLICY_DENIED in meta["alert_events"]


# --------------------------------------------------------------------------------------
# The SSRF guard, which is the first thing a user hits when testing locally
# --------------------------------------------------------------------------------------

def test_a_loopback_webhook_url_is_refused_by_design():
    """Alerts cannot be pointed at localhost or a private address. This is deliberate
    (SSRF and DNS-rebinding defence), but it is also the first thing every user hits when
    they try to test alerting on their laptop, so it must fail with a clear message."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    for url in ["http://127.0.0.1:9000/hook", "http://localhost:9000/hook",
                "http://192.168.1.10/hook", "http://169.254.169.254/latest/meta-data"]:
        r = c.post("/v1/webhooks", json={"url": url, "events": [POLICY_DENIED]})
        assert r.status_code == 422, f"{url} should be refused, got {r.status_code}"
        assert "public" in r.json()["detail"].lower()


def test_delivery_revalidates_the_url_at_send_time():
    """A hostname that was public at registration can later resolve to an internal address.
    The check runs again at delivery, not only at registration."""
    from provenrail.server import notifier
    assert notifier.deliver("http://127.0.0.1:9000/hook", "secret", {"type": POLICY_DENIED}) is False


def test_a_real_signed_delivery_carries_a_verifiable_hmac():
    """Prove the full delivery contract: exact body, signature header, event header."""
    import hashlib
    import hmac as _hmac

    from provenrail.server import notifier

    captured = {}

    class FakeClient:
        def post(self, url, content=None, headers=None):
            captured["url"] = url
            captured["body"] = content
            captured["headers"] = headers

            class R:
                status_code = 200
            return R()

    event = {"id": "e1", "type": POLICY_DENIED, "stream_id": "s1",
             "denial": {"rule": "no-destructive-tools", "target": "delete_database"}}
    # http= is injected, which is also the only way to bypass the SSRF guard, so this
    # exercises the real signing path without needing a public endpoint.
    assert notifier.deliver("https://ops.example/hook", "whsec_abc", event, http=FakeClient())

    expected = "sha256=" + _hmac.new(b"whsec_abc", captured["body"], hashlib.sha256).hexdigest()
    assert captured["headers"][notifier.SIGNATURE_HEADER] == expected
    assert captured["headers"][notifier.EVENT_HEADER] == POLICY_DENIED
    assert json.loads(captured["body"])["denial"]["rule"] == "no-destructive-tools"


# --------------------------------------------------------------------------------------
# The public proof page
# --------------------------------------------------------------------------------------

def test_share_page_renders_a_denial_as_a_blocked_action_not_a_raw_type():
    """The proof page is what gets handed to a third party. A live guardrail block is the
    strongest content it can show, and must never appear as an opaque 'policy.decision'."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    _run_agent_against(c, prov)

    page = c.get(f"/share/{prov['share_token']}")
    assert page.status_code == 200
    body = page.text
    assert "Policy blocked: delete_database" in body
    assert "ev-deny" in body                      # denials carry the red styling class
    assert "policy.decision</span>" not in body   # never the raw action_type as a label
    # The event-type chips use the friendly label too.
    assert "Policy decision:" in body


def test_share_page_labels_allows_differently_from_denials():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=load_policy({"rules": [
                            {"id": "email-cap", "effect": "limit", "event_type": "tool_call",
                             "tool": "send_email", "max_per_session": 5}]}))
    with fr.session():
        fr.record_tool_call("send_email", {"to": "a"}, "ok")
    body = c.get(f"/share/{prov['share_token']}").text
    assert "Policy allowed: send_email" in body
    assert "Policy blocked" not in body
