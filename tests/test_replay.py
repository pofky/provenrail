"""Replay and diff: aligning two verified runs and surfacing real behavioral changes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.replay import diff_runs, extract_steps
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _run(c, steps):
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        for s in steps:
            s(fr)
    c.post(f"/v1/streams/{prov['stream_id']}/anchor")
    return prov["stream_id"], c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


def _client():
    return TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))


def test_identical_runs_diff_clean():
    c = _client()
    steps = [lambda fr: fr.record_tool_call("search", {"q": "x"}, {"hits": 1}),
             lambda fr: fr.record_decision("ship")]
    _, a = _run(c, steps)
    _, b = _run(c, steps)
    d = diff_runs(a, b)
    assert d["verified_a"] and d["verified_b"]
    assert d["summary"]["identical"] is True
    assert d["summary"]["equal"] == 2


def test_changed_step_detected():
    c = _client()
    _, a = _run(c, [lambda fr: fr.record_tool_call("search", {"q": "cats"}, {"hits": 1})])
    _, b = _run(c, [lambda fr: fr.record_tool_call("search", {"q": "dogs"}, {"hits": 9})])
    d = diff_runs(a, b)
    assert d["summary"]["changed"] == 1
    assert d["summary"]["identical"] is False
    step = [s for s in d["steps"] if s["action_type"] == "tool_call"][0]
    assert step["tag"] == "changed"


def test_added_and_removed_steps():
    c = _client()
    _, a = _run(c, [lambda fr: fr.record_decision("only-a")])
    _, b = _run(c, [lambda fr: fr.record_decision("only-a"),
                    lambda fr: fr.record_tool_call("extra", {}, {})])
    d = diff_runs(a, b)
    assert d["summary"]["added"] == 1
    tags = {s["tag"] for s in d["steps"]}
    assert "added" in tags


def test_extract_steps_ignores_lifecycle():
    c = _client()
    _, a = _run(c, [lambda fr: fr.record_decision("d")])
    steps = extract_steps(a)
    # genesis/seal/heartbeat are excluded; only the decision is a meaningful step
    assert all(s["action_type"] == "decision" for s in steps)
    assert len(steps) == 1


def test_diff_endpoint():
    c = _client()
    # same tool name (same signature), different args -> a "changed" step
    sa, _ = _run(c, [lambda fr: fr.record_tool_call("query", {"sql": "select 1"}, {"rows": 1})])
    sb, _ = _run(c, [lambda fr: fr.record_tool_call("query", {"sql": "drop table"}, {"rows": 0})])
    r = c.get(f"/v1/streams/{sa}/diff/{sb}")
    assert r.status_code == 200
    out = r.json()
    assert out["summary"]["changed"] == 1


def test_diff_over_tampered_bundle_flags_unverified():
    c = _client()
    _, a = _run(c, [lambda fr: fr.record_decision("d")])
    _, b = _run(c, [lambda fr: fr.record_decision("d")])
    b["records"][1]["record"]["payload"]["summary"] = "tampered"
    d = diff_runs(a, b)
    assert d["verified_b"] is False  # the diff still runs but flags the tampering
