"""Spend budgets: scopes that outlive a session, warnings before the cap, honest verification.

The scenario every one of these defends against is the same: an agent runs overnight across
hundreds of short sessions and the team finds out when the invoice arrives. A cap that only
sees one session cannot stop that, and a cap that silently resets every process is worse than
no cap because it reports as armed.
"""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime, timedelta

import pytest

from provenrail import spend
from provenrail.easy import PolicyConfigError, load_policy
from provenrail.policy import Budget, Policy, SessionState, budget_status

MODEL = "claude-sonnet-4-5"


def usage(input_tokens: int, output_tokens: int = 0) -> dict:
    return {"input_tokens": input_tokens, "output_tokens": output_tokens}


def call(policy: Policy, state: SessionState, input_tokens: int):
    ctx = {"model": MODEL, "usage": usage(input_tokens)}
    decision = policy.decide("model_call", ctx, state)
    return decision


# ---------------------------------------------------------------- scopes


def test_session_budget_denies_the_call_that_would_cross_it():
    p = Policy(budgets=[Budget(scope="session", limit_usd=1.0, warn_at=0)])
    s = SessionState()
    assert call(p, s, 100_000).effect == "allow"      # $0.30
    s.spend_usd = 0.9
    d = call(p, s, 100_000)                            # 0.9 + 0.30 > 1.0
    assert d.effect == "deny"
    assert d.rule_id == "budget.session"


def test_day_budget_binds_across_sessions_where_a_session_budget_cannot():
    """The overnight-run case: this session has spent nothing, the day has spent plenty."""
    p = Policy(budgets=[Budget(scope="day", limit_usd=10.0, warn_at=0)])
    s = SessionState(prior_day_usd=9.95, prior_known=True)
    assert s.spend_usd == 0.0
    d = call(p, s, 100_000)
    assert d.effect == "deny"
    assert d.rule_id == "budget.day"
    # a session-scoped cap of the same size would have allowed it
    session_only = Policy(budgets=[Budget(scope="session", limit_usd=10.0, warn_at=0)])
    assert call(session_only, SessionState(), 100_000).effect == "allow"


def test_total_budget_uses_lifetime_prior():
    p = Policy(budgets=[Budget(scope="total", limit_usd=100.0, warn_at=0)])
    assert call(p, SessionState(prior_total_usd=99.99, prior_known=True), 100_000).effect == "deny"
    assert call(p, SessionState(prior_total_usd=1.0, prior_known=True), 100_000).effect == "allow"


def test_legacy_session_spend_cap_still_works_and_is_reported_as_a_budget():
    p = Policy(session_spend_cap_usd=0.01)
    s = SessionState(spend_usd=0.009)
    assert call(p, s, 100_000).effect == "deny"
    assert [b.scope for b in p.effective_budgets()] == ["session"]
    assert p.effective_budgets()[0].id == "session_spend_cap"


def test_explicit_session_budget_supersedes_the_legacy_shorthand():
    p = Policy(session_spend_cap_usd=1.0,
               budgets=[Budget(scope="session", limit_usd=5.0, id="b1")])
    assert [b.id for b in p.effective_budgets()] == ["b1"]


# ---------------------------------------------------------------- warnings


def test_warning_fires_before_the_cap_bites_and_does_not_block():
    p = Policy(budgets=[Budget(scope="session", limit_usd=1.0, warn_at=0.8)])
    s = SessionState(spend_usd=0.6)
    d = call(p, s, 100_000)   # 0.6 + 0.30 = 0.90, 90% of the cap
    assert d.effect == "allow"
    assert d.warning is not None
    assert "90%" in d.warning


def test_no_warning_below_the_threshold():
    p = Policy(budgets=[Budget(scope="session", limit_usd=1.0, warn_at=0.8)])
    assert call(p, SessionState(), 100_000).warning is None


def test_warn_at_zero_disables_warnings():
    p = Policy(budgets=[Budget(scope="session", limit_usd=1.0, warn_at=0)])
    assert call(p, SessionState(spend_usd=0.99), 1000).warning is None


# ---------------------------------------------------------------- committed policy


def test_budgets_are_committed_into_the_policy_hash():
    a = Policy(budgets=[Budget(scope="day", limit_usd=10.0)])
    b = Policy(budgets=[Budget(scope="day", limit_usd=1000.0)])
    assert a.policy_id() != b.policy_id()
    assert Policy.from_dict(a.to_dict()).effective_budgets()[0].limit_usd == 10.0


def test_adding_budgets_does_not_change_the_hash_of_a_policy_without_them():
    """Frozen conformance vectors carry policy hashes; an empty budgets list must not appear
    in the canonical form or every previously recorded policy commit would break."""
    p = Policy(session_spend_cap_usd=5.0)
    assert "budgets" not in p.to_dict()
    assert p.policy_id() == Policy.from_dict(
        {"rules": [], "session_spend_cap_usd": 5.0}).policy_id()


def test_policy_dict_is_canonicalizable_no_floats():
    d = Policy(budgets=[Budget(scope="day", limit_usd=12.5, warn_at=0.75)]).to_dict()
    assert d["budgets"][0]["limit_usd"] == "12.500000"
    assert d["budgets"][0]["warn_at"] == "0.7500"


# ---------------------------------------------------------------- config validation


def test_config_rejects_a_budget_that_would_cap_nothing():
    with pytest.raises(PolicyConfigError, match="limit_usd"):
        load_policy({"budgets": [{"scope": "day"}]})
    with pytest.raises(PolicyConfigError, match="greater than zero"):
        load_policy({"budgets": [{"scope": "day", "limit_usd": 0}]})


def test_config_rejects_an_unknown_scope_or_field():
    with pytest.raises(PolicyConfigError, match="scope"):
        load_policy({"budgets": [{"scope": "weekly", "limit_usd": 5}]})
    with pytest.raises(PolicyConfigError, match="unknown field"):
        load_policy({"budgets": [{"scope": "day", "limit_usd": 5, "limt_usd": 1}]})


def test_config_rejects_a_budget_id_colliding_with_a_rule_id():
    with pytest.raises(PolicyConfigError, match="duplicate policy id"):
        load_policy({
            "rules": [{"id": "cap", "effect": "deny", "tool": "x"}],
            "budgets": [{"id": "cap", "scope": "day", "limit_usd": 5}],
        })


def test_config_accepts_a_well_formed_budget():
    p = load_policy({"budgets": [{"scope": "day", "limit_usd": 25, "warn_at": 0.5}]})
    assert p.effective_budgets()[0].scope == "day"
    assert p.effective_budgets()[0].warn_at == 0.5


# ---------------------------------------------------------------- status


def test_budget_status_reports_headroom_and_flags_unknown_history():
    p = Policy(budgets=[Budget(scope="session", limit_usd=10.0),
                        Budget(scope="day", limit_usd=100.0)])
    rows = budget_status(p, SessionState(spend_usd=9.0))
    by_scope = {r["scope"]: r for r in rows}
    assert by_scope["session"]["remaining_usd"] == 1.0
    assert by_scope["session"]["pct"] == 90.0
    assert by_scope["session"]["warning"] is True
    assert by_scope["session"]["prior_known"] is True
    # the day budget's history was never supplied, and must not be presented as authoritative
    assert by_scope["day"]["prior_known"] is False


# ---------------------------------------------------------------- ledger


def test_ledger_round_trips_day_and_total(tmp_path):
    f = tmp_path / "spend.json"
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    assert spend.prior_spend("a", path=f, now=now) == (0.0, 0.0, False)
    spend.add_spend(1.5, "a", path=f, now=now)
    spend.add_spend(0.5, "a", path=f, now=now)
    assert spend.prior_spend("a", path=f, now=now) == (2.0, 2.0, True)


def test_ledger_day_bucket_rolls_over_but_total_does_not(tmp_path):
    f = tmp_path / "spend.json"
    day1 = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
    day2 = day1 + timedelta(days=1)
    spend.add_spend(4.0, "a", path=f, now=day1)
    spend.add_spend(1.0, "a", path=f, now=day2)
    today, total, known = spend.prior_spend("a", path=f, now=day2)
    assert (today, total, known) == (1.0, 5.0, True)


def test_ledger_separates_agents(tmp_path):
    f = tmp_path / "spend.json"
    now = datetime(2026, 8, 4, tzinfo=UTC)
    spend.add_spend(3.0, "billing-agent", path=f, now=now)
    spend.add_spend(7.0, "support-agent", path=f, now=now)
    assert spend.prior_spend("billing-agent", path=f, now=now)[1] == 3.0
    rows = {r["agent_id"]: r for r in spend.report(path=f, now=now)["agents"]}
    assert rows["support-agent"]["today_usd"] == 7.0
    assert spend.report(path=f, now=now)["total_usd"] == 10.0


def test_ledger_prunes_old_days_but_keeps_lifetime_total(tmp_path):
    f = tmp_path / "spend.json"
    old = datetime(2026, 1, 1, tzinfo=UTC)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    spend.add_spend(9.0, "a", path=f, now=old)
    spend.add_spend(1.0, "a", path=f, now=now)
    entry = json.loads(f.read_text())["agents"]["a"]
    assert "2026-01-01" not in entry["days"]
    assert entry["total_usd"] == 10.0


def test_corrupt_ledger_reads_as_unknown_not_as_zero(tmp_path):
    """A truncated file after a disk-full event still holds real spend that is now unreadable.

    Reporting that as "$0.00, authoritative" lifts a day cap at exactly the moment the machine
    is in trouble. This test previously asserted `known=True`, i.e. it certified the bug while
    its own name claimed the opposite.
    """
    f = tmp_path / "spend.json"
    spend.add_spend(9.90, "a", path=f)                 # real history exists
    f.write_text("{ truncated mid-write")              # then the disk fills
    day, total, known = spend.prior_spend("a", path=f)
    assert known is False, "corrupt history was reported as authoritative zero"
    assert (day, total) == (0.0, 0.0)
    # and a cross-session budget must therefore not present itself as authoritative
    p = Policy(budgets=[Budget(scope="day", limit_usd=10.0)])
    state = SessionState(prior_day_usd=day, prior_total_usd=total, prior_known=known)
    assert budget_status(p, state)[0]["prior_known"] is False
    # recording still works: a broken ledger must never break the recorder
    spend.add_spend(1.0, "a", path=f)
    assert spend.prior_spend("a", path=f)[1] == 1.0


def test_concurrent_writers_do_not_lose_spend(tmp_path):
    """Atomic replacement prevents a torn file but not a lost update: two callers read the
    same state, each add their own cost, and the second write discards the first. Measured at
    50 percent of increments lost before the lock was added."""
    import threading

    f = tmp_path / "spend.json"

    def worker():
        for _ in range(100):
            spend.add_spend(0.01, "a", path=f)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert spend.prior_spend("a", path=f)[1] == pytest.approx(2.00)


def test_concurrent_writers_do_not_erase_another_agent(tmp_path):
    """The worse variant of the same bug: agent B's entire history vanished."""
    import threading

    f = tmp_path / "spend.json"

    def worker(name):
        for _ in range(100):
            spend.add_spend(0.01, name, path=f)

    threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert spend.prior_spend("a", path=f)[1] == pytest.approx(1.00)
    assert spend.prior_spend("b", path=f)[1] == pytest.approx(1.00)


def test_separate_processes_do_not_lose_spend(tmp_path):
    """The lock must hold across processes, not just threads: an agent fleet on one host is
    separate processes, which is exactly the overnight-run shape budgets exist for."""
    import subprocess
    import sys

    f = tmp_path / "spend.json"
    root = str(pathlib.Path(spend.__file__).parents[2])
    script = (
        f"import sys; sys.path.insert(0, {root!r})\n"
        "from provenrail import spend\n"
        "from pathlib import Path\n"
        f"for _ in range(60): spend.add_spend(0.01, 'a', path=Path({str(f)!r}))\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", script]) for _ in range(3)]
    for pr in procs:
        assert pr.wait(timeout=60) == 0
    assert spend.prior_spend("a", path=f)[1] == pytest.approx(1.80)


# ---------------------------------------------------------------- through the SDK


def _live_recorder(tmp_path, monkeypatch, policy, enforce=True):
    """A recorder wired to an in-process sink, with the spend ledger pointed at tmp_path."""
    from fastapi.testclient import TestClient

    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    from provenrail.server.app import create_app

    monkeypatch.setenv("PROVENRAIL_SPEND_LEDGER", str(tmp_path / "spend.json"))
    client = TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))
    prov = provision_stream("http://t", http=client)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=client,
                        policy=policy, enforce=enforce)
    return client, prov, fr


def test_sdk_records_a_budget_warning_into_the_signed_chain(tmp_path, monkeypatch):
    from provenrail.verifier.verify import verify_bundle

    pol = Policy(budgets=[Budget(scope="session", limit_usd=0.35, warn_at=0.8)])
    client, prov, fr = _live_recorder(tmp_path, monkeypatch, pol)
    with fr.session({"agent": "budget"}):
        fr.record_model_call("anthropic", MODEL, "hi", "yo", usage=usage(100_000))  # $0.30, 86%
    bundle = client.get(f"/v1/streams/{prov['stream_id']}/export",
                        headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    warnings = [r["record"]["payload"] for r in bundle["records"]
                if r["record"]["action_type"] == "policy.decision"
                and r["record"]["payload"].get("warning")]
    assert len(warnings) == 1
    assert "86%" in warnings[0]["warning"]
    assert verify_bundle(bundle).ok


def test_sdk_day_budget_survives_process_restart(tmp_path, monkeypatch):
    """Two separate recorder lifetimes on one stream, as an overnight run produces. The second
    must see the first one's spend, which is the whole reason the ledger exists."""
    pol = Policy(budgets=[Budget(scope="day", limit_usd=0.5, warn_at=0)])
    client, prov, fr1 = _live_recorder(tmp_path, monkeypatch, pol)
    with fr1.session({"agent": "a"}):
        fr1.record_model_call("anthropic", MODEL, "hi", "yo", usage=usage(100_000))  # $0.30

    # a fresh recorder, as a new process would build: same stream, zero in-memory spend
    from provenrail.policy import PolicyViolation
    from provenrail.sdk import FlightRecorder
    fr2 = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=client,
                         policy=pol, enforce=True)
    assert fr2._session_state is None
    with pytest.raises(PolicyViolation, match="day"):
        with fr2.session({"agent": "a"}):
            fr2.record_model_call("anthropic", MODEL, "hi", "yo", usage=usage(100_000))


def test_session_only_budget_never_touches_the_ledger(tmp_path, monkeypatch):
    """A session-scoped policy must not pay for ledger I/O on every model call."""
    pol = Policy(budgets=[Budget(scope="session", limit_usd=100.0)])
    _, _, fr = _live_recorder(tmp_path, monkeypatch, pol)
    with fr.session({"agent": "a"}):
        fr.record_model_call("anthropic", MODEL, "hi", "yo", usage=usage(1000))
    assert not (tmp_path / "spend.json").exists()


def test_sink_fires_budget_alerts_for_warnings_and_denials():
    from provenrail.server.alerts import AlertEngine

    records = [
        {"record": {"action_type": "policy.decision", "session_id": "s", "seq": 3,
                    "payload": {"effect": "allow", "rule": "budget.day",
                                "warning": "budget.day: 90% of the $10 cap"}}},
        {"record": {"action_type": "policy.decision", "session_id": "s", "seq": 4,
                    "payload": {"effect": "deny", "rule": "budget.day",
                                "reason": "over the cap"}}},
    ]
    events = AlertEngine.budget_events_in(records)
    assert [e["type"] for e in events] == ["budget.warning", "budget.exceeded"]
    assert all(e["estimated"] for e in events)


def test_verifier_does_not_invent_violations_from_missing_cross_session_history(tmp_path,
                                                                                monkeypatch):
    """A day budget was evaluated against spend in other sessions. Replaying it against this
    bundle alone would fail every call; the verifier must report it as not-re-checkable."""
    from provenrail.verifier.verify import verify_bundle

    pol = Policy(budgets=[Budget(scope="day", limit_usd=1000.0, warn_at=0)])
    client, prov, fr = _live_recorder(tmp_path, monkeypatch, pol)
    with fr.session({"agent": "a"}):
        fr.record_model_call("anthropic", MODEL, "hi", "yo", usage=usage(100_000))
    bundle = client.get(f"/v1/streams/{prov['stream_id']}/export",
                        headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    rep = verify_bundle(bundle)
    assert rep.ok, rep.to_dict()
    verified = [f for f in rep.findings if f.code == "policy_verified"]
    assert verified and "cross-session budget" in verified[0].detail
