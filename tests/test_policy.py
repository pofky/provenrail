"""Active policy / guardrail layer: enforcement at the dispatch boundary, recorded as evidence."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.policy import Policy, PolicyViolation, Rule, SessionState
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _fr(policy, enforce=True):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=policy, enforce=enforce)
    return app, c, prov, fr


# ---- pure policy evaluation ----

def test_deny_rule_blocks_tool():
    p = Policy(rules=[Rule(id="no-shell", effect="deny", event_type="tool_call", tool="shell*")])
    d = p.decide("tool_call", {"tool": "shell_exec"}, SessionState())
    assert d.effect == "deny" and d.rule_id == "no-shell"
    # a non-matching tool is allowed
    assert p.decide("tool_call", {"tool": "search"}, SessionState()).effect == "allow"


def test_require_oversight_gate():
    p = Policy(rules=[Rule(id="phi", effect="require_oversight", event_type="data_access",
                           resource="patient/*")])
    s = SessionState()
    assert p.decide("data_access", {"resource": "patient/123"}, s).effect == "deny"
    s.had_oversight = True
    assert p.decide("data_access", {"resource": "patient/123"}, s).effect == "allow"


def test_spend_cap():
    p = Policy(session_spend_cap_usd=0.01)
    s = SessionState(spend_usd=0.009)
    ctx = {"model": "claude-opus-4-8", "usage": {"input": "100000", "output": "100000"}}
    assert p.decide("model_call", ctx, s).effect == "deny"


# ---- SDK enforcement ----

def test_sdk_denies_and_records_decision():
    policy = Policy(rules=[Rule(id="no-delete", effect="deny", event_type="tool_call",
                                tool="delete_*")])
    app, c, prov, fr = _fr(policy)

    @fr.tool("delete_db")
    def delete_db():
        return {"dropped": True}

    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "demo"}):
            delete_db()
    # the deny decision was recorded into the chain before the tool ran
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    actions = [r["record"]["action_type"] for r in bundle["records"]]
    assert "policy.decision" in actions
    # the tool_call itself was never recorded (the action was blocked)
    assert "tool_call" not in actions


def test_sdk_allows_when_oversight_present():
    policy = Policy(rules=[Rule(id="phi", effect="require_oversight", event_type="data_access",
                                resource="patient/*")])
    app, c, prov, fr = _fr(policy)
    with fr.session({"agent": "demo"}):
        fr.record_human_oversight("clinician approved access")
        fr.record_data_access("patient/42", "read")  # allowed now
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    actions = [r["record"]["action_type"] for r in bundle["records"]]
    assert "data_access" in actions
    decisions = [r["record"]["payload"] for r in bundle["records"]
                 if r["record"]["action_type"] == "policy.decision"]
    assert any(d["effect"] == "allow" and d["rule"] == "phi" for d in decisions)


def test_sdk_denies_data_access_without_oversight():
    policy = Policy(rules=[Rule(id="phi", effect="require_oversight", event_type="data_access",
                                resource="patient/*")])
    app, c, prov, fr = _fr(policy)
    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "demo"}):
            fr.record_data_access("patient/42", "read")


def test_report_only_mode_records_but_does_not_block():
    policy = Policy(rules=[Rule(id="warn-shell", effect="deny", event_type="tool_call",
                                tool="shell*")])
    app, c, prov, fr = _fr(policy, enforce=False)

    @fr.tool("shell_run")
    def shell_run():
        return {"ran": True}

    with fr.session({"agent": "demo"}):
        out = shell_run()  # not blocked in report-only mode
    assert out == {"ran": True}
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    actions = [r["record"]["action_type"] for r in bundle["records"]]
    assert "policy.decision" in actions  # decision still recorded as evidence
    assert "tool_call" in actions        # and the tool did run


def test_spend_cap_blocks_second_call():
    policy = Policy(session_spend_cap_usd=0.05)
    app, c, prov, fr = _fr(policy)
    big = {"input": "1000000", "output": "1000000"}  # well over the cap for a priced model
    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "demo"}):
            fr.record_model_call("anthropic", "claude-opus-4-8", {"q": "x"}, {"a": "y"}, usage=big)


def test_enforced_bundle_still_verifies():
    # A bundle that contains policy decisions must still verify cleanly (decisions are normal
    # signed records in the chain).
    policy = Policy(rules=[Rule(id="no-x", effect="deny", tool="x")])
    app, c, prov, fr = _fr(policy)
    with fr.session({"agent": "demo"}):
        fr.record_decision("benign")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor")
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    rep = verify_bundle(bundle)
    assert rep.ok


def test_no_policy_is_noop():
    app, c, prov, fr = _fr(None)
    with fr.session({"agent": "demo"}):
        fr.record_tool_call("anything", {"a": 1}, {"ok": True})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    actions = [r["record"]["action_type"] for r in bundle["records"]]
    assert "policy.decision" not in actions


def test_policy_from_dict():
    p = Policy.from_dict({
        "session_spend_cap_usd": 1.5,
        "rules": [{"id": "r1", "effect": "deny", "event_type": "tool_call", "tool": "rm*"}],
    })
    assert p.session_spend_cap_usd == 1.5
    assert p.decide("tool_call", {"tool": "rm_rf"}, SessionState()).effect == "deny"
