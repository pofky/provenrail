"""Signed policy commitment + richer rule types, and the verifier's policy-consistency check.

The novel property: the active policy is committed into the signed session-start record, so a
standalone verifier can prove which guardrails were in force and that no executed action violates
a re-verifiable deny/limit/spend rule. Content gates (arg_contains) are enforced live but reported
as not-offline-reverifiable, never silently trusted.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.chain import GENESIS, TOOL_CALL
from provenrail.ingest_client import provision_stream
from provenrail.policy import Policy, PolicyViolation, Rule, SessionState
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import Report, _verify_policy, verify_bundle

# ---- unit: policy serialization + new rules ----

def test_policy_id_stable_and_sensitive():
    p1 = Policy(rules=[Rule(id="a", effect="deny", tool="danger")], session_spend_cap_usd=5.0)
    p2 = Policy.from_dict(p1.to_dict())
    assert p1.policy_id() == p2.policy_id()  # roundtrip stable
    p3 = Policy(rules=[Rule(id="a", effect="deny", tool="other")], session_spend_cap_usd=5.0)
    assert p3.policy_id() != p1.policy_id()  # any change moves the hash
    assert p2.session_spend_cap_usd == 5.0   # cap survived the string roundtrip


def test_arg_contains_gate_denies_matching_content():
    pol = Policy(rules=[Rule(id="no-secret", effect="deny", event_type="tool_call",
                             arg_contains=r"password|api[_-]?key")])
    st = SessionState()
    assert pol.decide("tool_call", {"tool": "send", "match_text": "my password is x"}, st).effect == "deny"
    assert pol.decide("tool_call", {"tool": "send", "match_text": "hello world"}, st).effect == "allow"


def test_limit_rule_denies_after_cap():
    pol = Policy(rules=[Rule(id="cap", effect="limit", tool="search", max_per_session=2)])
    st = SessionState()
    assert pol.decide("tool_call", {"tool": "search"}, st).effect == "allow"
    assert pol.decide("tool_call", {"tool": "search"}, st).effect == "allow"
    assert pol.decide("tool_call", {"tool": "search"}, st).effect == "deny"  # 3rd over the cap


# ---- integration: enforcement through the SDK ----

def _session(policy, enforce=True, actions=None):
    sink = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(sink)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=policy, enforce=enforce)
    with fr.session({"agent": "pol"}):
        if actions:
            actions(fr)
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


def test_policy_committed_into_signed_genesis():
    pol = Policy(rules=[Rule(id="no-danger", effect="deny", tool="danger")],
                 session_spend_cap_usd=10.0)
    bundle = _session(pol, actions=lambda fr: fr.record_decision("fine"))
    genesis = bundle["records"][0]["record"]
    assert genesis["action_type"] == GENESIS
    meta = genesis["payload"]["meta"]
    assert meta["policy_sha256"] == pol.policy_id()
    # and the bundle verifies, reporting the policy as checked
    rep = verify_bundle(bundle)
    assert rep.ok, rep.to_dict()
    assert any(f.code == "policy_verified" for f in rep.findings)


def test_content_gate_blocks_through_sdk():
    pol = Policy(rules=[Rule(id="no-secret", effect="deny", event_type="tool_call",
                             arg_contains="password")])
    with pytest.raises(PolicyViolation):
        _session(pol, actions=lambda fr: fr.record_tool_call("send", {"body": "the password=hunter2"}, {}))


def test_limit_blocks_third_call_through_sdk():
    pol = Policy(rules=[Rule(id="cap-search", effect="limit", tool="search", max_per_session=2)])

    def acts(fr):
        fr.record_tool_call("search", {"q": 1}, {})
        fr.record_tool_call("search", {"q": 2}, {})
        fr.record_tool_call("search", {"q": 3}, {})  # over the cap

    with pytest.raises(PolicyViolation):
        _session(pol, actions=acts)


# ---- verifier: adversarial cases on the committed policy ----

def _genesis(pol, committed):
    return {"seq": 0, "action_type": GENESIS,
            "payload": {"meta": {"policy": pol.to_dict(), "policy_sha256": committed}}}


def test_verifier_flags_policy_commit_tampering():
    pol = Policy(rules=[Rule(id="d", effect="deny", tool="x")])
    rep = Report()
    _verify_policy([_genesis(pol, "deadbeefdeadbeef")], rep)  # hash disagrees with embedded policy
    assert any(f.code == "policy_commit_mismatch" and f.severity == "fail" for f in rep.findings)


def test_verifier_flags_unenforced_deny():
    pol = Policy(rules=[Rule(id="block-danger", effect="deny", tool="danger")])
    ordered = [
        _genesis(pol, pol.policy_id()),
        {"seq": 1, "action_type": TOOL_CALL, "payload": {"tool": "danger"}, "record_id": "r1"},
    ]
    rep = Report()
    _verify_policy(ordered, rep)
    assert any(f.code == "policy_not_enforced" for f in rep.findings)


def test_verifier_clean_when_no_policy_committed():
    ordered = [{"seq": 0, "action_type": GENESIS, "payload": {"meta": {}}}]
    rep = Report()
    _verify_policy(ordered, rep)
    assert rep.findings == []  # no policy committed: nothing to say


def test_dashboard_verdict_surfaces_policy_and_signals():
    from provenrail.server.analytics import verdict

    pol = Policy(rules=[Rule(id="cap", effect="limit", tool="x", max_per_session=9)])

    def acts(fr):
        # a model call with no usage triggers the usage_missing coherence signal
        fr.record_model_call("openai", "gpt-4o", request="hi", response="yo")

    bundle = _session(pol, actions=acts)
    v = verdict(bundle)
    assert v["policy"]["committed"] and v["policy"]["verified"]
    assert any(s["code"] == "usage_missing" for s in v["signals"])
    assert all(s["severity"] != "fail" for s in v["signals"])
