"""Out-of-band human approval for headless agents.

`require_oversight` is the most useful rule in the catalogue and, without this, the least
usable one outside Claude Code: with no human at the keyboard it can only deny. These tests
pin the safety properties, all of which are ways an approval flow could hand out an allow it
should not have.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.policy import Policy, PolicyViolation, Rule
from provenrail.sdk import FlightRecorder
from provenrail.server import approvals as approvals_mod
from provenrail.server.app import create_app


def _store():
    import sqlite3
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    return approvals_mod.ApprovalStore(db)


# ---------------------------------------------------------------- store semantics


def test_approve_link_decides_once_and_a_replay_changes_nothing():
    store = _store()
    req = store.create("stream-1", rule="money.wire-transfer", target="wire_transfer")
    first = store.decide_by_token(req["approve_token"], approvals_mod.APPROVED, "ops@x.com")
    assert first["ok"] is True
    assert first["request"]["status"] == "approved"
    replay = store.decide_by_token(req["approve_token"], approvals_mod.APPROVED, "someone@else")
    assert replay["ok"] is False
    assert "already approved" in replay["reason"]
    assert store.get(req["request_id"])["decided_by"] == "ops@x.com"


def test_the_deny_token_can_never_approve():
    """One token plus an action parameter is one prefetcher away from an accidental allow."""
    store = _store()
    req = store.create("stream-1")
    assert store.decide_by_token(req["deny_token"], approvals_mod.APPROVED)["ok"] is False
    assert store.get(req["request_id"])["status"] == "pending"
    assert store.decide_by_token(req["deny_token"], approvals_mod.DENIED)["ok"] is True


def test_an_unanswered_request_expires_rather_than_lingering():
    store = _store()
    req = store.create("stream-1", ttl_seconds=1)
    later = datetime.now(UTC) + timedelta(seconds=5)
    assert store.get(req["request_id"], now=later)["status"] == "expired"
    # and can no longer be approved
    assert store.decide_by_token(req["approve_token"], approvals_mod.APPROVED,
                                 now=later)["ok"] is False


def test_token_hashes_are_never_exposed():
    store = _store()
    req = store.create("stream-1")
    public = store.get(req["request_id"])
    assert "approve_hash" not in public and "deny_hash" not in public


def test_unknown_token_decides_nothing():
    assert _store().decide_by_token("not-a-real-token", approvals_mod.APPROVED)["ok"] is False


def test_expired_requests_drop_out_of_the_pending_list():
    store = _store()
    store.create("stream-1", ttl_seconds=1)
    store.create("stream-1", ttl_seconds=9999)
    later = datetime.now(UTC) + timedelta(seconds=5)
    assert len(store.list_pending(None, now=later)) == 1


# ---------------------------------------------------------------- through the API


def _wired():
    client = TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))
    prov = provision_stream("http://t", http=client)
    return client, prov


def test_endpoint_returns_two_distinct_links_and_hides_the_tokens_afterwards():
    client, prov = _wired()
    resp = client.post("/v1/approvals",
                       json={"stream_id": prov["stream_id"], "rule": "money.wire-transfer",
                             "target": "wire_transfer", "reason": "needs a human"},
                       headers={"Authorization": f"Bearer {prov['write_token']}"})
    body = resp.json()
    assert body["approve_url"] != body["deny_url"]
    assert "approve_token" not in body and "deny_token" not in body
    polled = client.get(f"/v1/approvals/{body['request_id']}",
                        headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    assert polled["status"] == "pending"


def test_opening_the_approve_link_does_not_approve(tmp_path):
    """THE regression test for a live vulnerability.

    Mail gateways, Slack's unfurler and antivirus scanners GET every URL in a notification
    before a human sees it, so a GET that approved was answered by a robot. A human tapping
    the link to read what was being asked had also already granted it. GET must only read.
    """
    client, prov = _wired()
    body = client.post("/v1/approvals",
                       json={"stream_id": prov["stream_id"], "rule": "money.wire",
                             "target": "wire_transfer", "reason": "Send $9,000 to ACME"},
                       headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    path = body["approve_url"].replace("http://testserver", "")

    # simulate the unfurler / scanner: several plain GETs
    for _ in range(3):
        page = client.get(path)
        assert page.status_code == 200
    still = client.get(f"/v1/approvals/{body['request_id']}",
                       headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    assert still["status"] == "pending", "a GET decided the request; a robot can approve"

    # and the human's actual submit does decide it
    posted = client.post(path)
    assert posted.status_code == 200
    assert "Approved" in posted.text
    after = client.get(f"/v1/approvals/{body['request_id']}",
                       headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    assert after["status"] == "approved"


def test_the_review_page_leads_with_the_action_not_the_product(tmp_path):
    """What is being asked must be readable before deciding, and the page must say plainly
    that nothing has happened yet."""
    client, prov = _wired()
    body = client.post("/v1/approvals",
                       json={"stream_id": prov["stream_id"], "rule": "money.wire",
                             "target": "wire_transfer(amount=9000)",
                             "reason": "Send $9,000 to ACME Corp"},
                       headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    page = client.get(body["approve_url"].replace("http://testserver", "")).text
    assert "Send $9,000 to ACME Corp" in page
    assert "wire_transfer(amount=9000)" in page
    assert "Nothing has been decided yet" in page
    assert "<form method=\"post\"" in page
    # the deny link renders its own review page, and also decides nothing on GET
    deny = client.get(body["deny_url"].replace("http://testserver", "")).text
    assert "Block this action?" in deny


def test_the_decision_page_renders_the_outcome():
    client, prov = _wired()
    body = client.post("/v1/approvals",
                       json={"stream_id": prov["stream_id"], "rule": "money.wire-transfer",
                             "target": "wire_transfer"},
                       headers={"Authorization": f"Bearer {prov['write_token']}"}).json()
    path = body["approve_url"].replace("http://testserver", "")
    page = client.post(path)
    assert page.status_code == 200
    assert "Approved" in page.text
    assert "wire_transfer" in page.text
    # resubmitting the same link states plainly that nothing changed
    again = client.post(path)
    assert "No change" in again.text
    # and revisiting it with a GET reports the settled state without altering it
    revisit = client.get(path)
    assert "Already approved" in revisit.text


def test_an_unknown_link_is_a_404_that_changes_nothing():
    client, _ = _wired()
    assert client.get("/approve/not-a-real-token").status_code == 404
    assert client.post("/deny/not-a-real-token").status_code == 200  # renders "No change"


def test_creating_a_request_needs_the_streams_own_write_token():
    client, prov = _wired()
    other = provision_stream("http://t", http=client)
    resp = client.post("/v1/approvals", json={"stream_id": prov["stream_id"]},
                       headers={"Authorization": f"Bearer {other['write_token']}"})
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------- through the SDK


def _recorder(client, prov, policy, timeout=0.0):
    return FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=client,
                          policy=policy, enforce=True, approval_timeout=timeout,
                          approval_poll=0.02)


OVERSIGHT = Policy(rules=[Rule(id="money.wire", effect="require_oversight", tool="wire_*")])


def test_without_an_approval_timeout_behaviour_is_unchanged():
    """Opt-in matters: pausing an agent on a human is the operator's decision to make."""
    client, prov = _wired()
    fr = _recorder(client, prov, OVERSIGHT)
    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "a"}):
            fr.record_tool_call("wire_transfer", {"amount": 100}, {})


def test_an_approved_request_releases_the_agent_and_is_recorded_as_oversight():
    """The human clicks the emailed link while the agent is blocked mid-call."""
    client, prov = _wired()
    fr = _recorder(client, prov, OVERSIGHT, timeout=5)

    # The raw tokens exist only in the response the agent received, by design, so the test
    # takes them from there: exactly what the notifier delivers to whoever is on call.
    created: dict = {}
    original = fr.client.request_approval

    def capture(body):
        result = original(body)
        created.update(result)
        return result

    fr.client.request_approval = capture

    def approver():
        for _ in range(500):
            if created.get("approve_url"):
                link = created["approve_url"].replace("http://testserver", "")
                client.get(link)     # the human opens and reads it
                client.post(link)    # then presses the button
                return
            threading.Event().wait(0.01)

    t = threading.Thread(target=approver, daemon=True)
    t.start()
    with fr.session({"agent": "a"}):
        fr.record_tool_call("wire_transfer", {"amount": 100}, {})
    t.join(timeout=5)

    bundle = client.get(f"/v1/streams/{prov['stream_id']}/export",
                        headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    kinds = [r["record"]["action_type"] for r in bundle["records"]]
    assert "human_oversight" in kinds
    assert "tool_call" in kinds
    oversight = next(r["record"]["payload"] for r in bundle["records"]
                     if r["record"]["action_type"] == "human_oversight")
    assert oversight["channel"] == "out_of_band"
    # the pause itself is evidence, recorded before any answer arrived
    awaits = [r["record"]["payload"] for r in bundle["records"]
              if r["record"]["action_type"] == "policy.decision"
              and r["record"]["payload"].get("effect") == "await_oversight"]
    assert awaits and awaits[0]["approval_request_id"]


def test_an_unanswered_request_fails_closed():
    client, prov = _wired()
    fr = _recorder(client, prov, OVERSIGHT, timeout=1)
    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "a"}):
            fr.record_tool_call("wire_transfer", {"amount": 100}, {})


def test_a_hard_deny_is_never_offered_to_a_human():
    """Only require_oversight is answerable. Offering to click past a deny rule or a blown
    budget would turn every guardrail into a prompt."""
    client, prov = _wired()
    policy = Policy(rules=[Rule(id="no-wire", effect="deny", tool="wire_*")])
    fr = _recorder(client, prov, policy, timeout=30)
    with pytest.raises(PolicyViolation):
        with fr.session({"agent": "a"}):
            fr.record_tool_call("wire_transfer", {"amount": 100}, {})
    # nothing was ever asked of a human
    assert client.get("/v1/approvals").json()["pending"] == []


def test_approving_one_rule_does_not_unlock_every_other_oversight_rule():
    """A single session-wide "someone approved something" flag meant approving a harmless
    read also released a delete. Oversight is per rule."""
    from provenrail.policy import SessionState

    policy = Policy(rules=[Rule(id="oversee.query", effect="require_oversight", tool="db_query"),
                           Rule(id="oversee.delete", effect="require_oversight", tool="db_delete")])
    state = SessionState()
    assert policy.decide("tool_call", {"tool": "db_query"}, state).effect == "deny"

    state.oversight_rules.add("oversee.query")            # a human approves the query only
    assert policy.decide("tool_call", {"tool": "db_query"}, state).effect == "allow"
    assert policy.decide("tool_call", {"tool": "db_delete"}, state).effect == "deny", \
        "approving a read unlocked a delete"

    state.oversight_rules.add("oversee.delete")
    assert policy.decide("tool_call", {"tool": "db_delete"}, state).effect == "allow"


def test_an_unnamed_oversight_still_acts_as_a_blanket_approval():
    """A host that cannot name the rule it answered (the Claude Code permission prompt, a
    manual call) keeps the older behaviour, because silently tightening it would start denying
    work people genuinely approved."""
    from provenrail.policy import SessionState

    policy = Policy(rules=[Rule(id="oversee.delete", effect="require_oversight", tool="db_*")])
    state = SessionState(had_oversight=True)
    assert policy.decide("tool_call", {"tool": "db_delete"}, state).effect == "allow"


def test_the_out_of_band_approval_names_its_rule():
    """The approval flow always sends the rule, so it gets the narrow scope by default."""
    client, prov = _wired()
    fr = _recorder(client, prov, OVERSIGHT, timeout=5)
    created: dict = {}
    original = fr.client.request_approval

    def capture(body):
        result = original(body)
        created.update(result)
        return result

    fr.client.request_approval = capture

    def approver():
        for _ in range(500):
            if created.get("approve_url"):
                link = created["approve_url"].replace("http://testserver", "")
                client.get(link)
                client.post(link)
                return
            threading.Event().wait(0.01)

    t = threading.Thread(target=approver, daemon=True)
    t.start()
    with fr.session({"agent": "a"}):
        fr.record_tool_call("wire_transfer", {"amount": 1}, {})
    t.join(timeout=5)
    assert fr._session_state.oversight_rules == {"money.wire"}
    assert fr._session_state.had_oversight is False
