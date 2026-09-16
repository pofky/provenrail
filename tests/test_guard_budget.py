"""A spend cap that binds at the tool boundary, which is where the product recommends installing.

Until this existed, `policy.budgets` only ever saw a `model_call` raised by the SDK. The hook
install, the one the README and the plugin both tell people to use, raised none: the cap was
written into `.provenrail.json`, printed by `pr guard status` as armed, and capped nothing. The
tests here are about that gap and about the two ways of closing it badly, which are a cap that
reads an unreadable transcript as $0.00 spent, and a cap that says nothing when it cannot bind.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from provenrail import guard, spend
from provenrail import transcript as transcript_mod
from provenrail.easy import load_policy

FIXTURE = Path(__file__).parent / "fixtures" / "transcripts" / "claude-code-spend.jsonl"
FIXTURE_LINES = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]
#: The fixture marks the point its own labels total $0.90, which is under a $1.00 cap and over
#: the 80% warning line. `test_transcript.py` holds that invariant; here it is just a cut point.
SPLIT_AT = next(i for i, line in enumerate(FIXTURE_LINES) if json.loads(line).get("_split"))

DAY_CAP = {"policy": {"use": ["destructive"],
                      "budgets": [{"scope": "day", "limit_usd": 1.0, "warn_at": 0.8}]}}


@pytest.fixture()
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))
    monkeypatch.setenv("PROVENRAIL_SPEND_LEDGER", str(tmp_path / "ledger.json"))
    for var in ("PROVENRAIL_URL", "FLIGHTRECORDER_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def write_config(workdir: Path, config: dict) -> None:
    (workdir / ".provenrail.json").write_text(json.dumps(config), encoding="utf-8")


def write_transcript(workdir: Path, upto: int | None = None) -> Path:
    path = workdir / "transcript.jsonl"
    path.write_text("\n".join(FIXTURE_LINES[:upto]) + "\n", encoding="utf-8")
    return path


def hook_payload(transcript_path, command="ls -la", session="s1"):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "session_id": session, "tool_input": {"command": command},
                       "cwd": str(Path(transcript_path).parent) if transcript_path else "",
                       "transcript_path": str(transcript_path) if transcript_path else ""})


def verdict_of(stdout: str) -> str:
    return (json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]
            if stdout.strip() else "allow")


# ---------------------------------------------------------------- the cap binds


def test_the_payload_field_that_carries_the_spend_is_read_at_all():
    parsed = guard.parse_hook_input({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                     "transcript_path": "/tmp/t.jsonl"})
    assert parsed["transcript_path"] == "/tmp/t.jsonl"


def test_a_growing_transcript_warns_first_and_then_denies_the_next_tool_call(workdir):
    """The whole feature in one test: an ordinary `ls` is allowed while the day cap has room,
    warned about as it is approached, and refused once the transcript says the money is gone."""
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)

    code, out, err = guard.run_hook(hook_payload(transcript))
    assert code == 0
    assert verdict_of(out) == "allow"
    warned = [e for e in guard.read_journal() if e.get("warning")]
    assert len(warned) == 1
    assert "90% of the $1.0000 cap" in warned[0]["warning"]
    assert "estimated at API list price" in warned[0]["warning"]

    write_transcript(workdir)
    code, out, err = guard.run_hook(hook_payload(transcript))
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    assert "budget.day" in payload["permissionDecisionReason"]
    # The agent is the reader. It has to be told to stop rather than to route around it, and
    # where a human can lift the cap, or it simply tries the next tool.
    assert "Stop here and tell the person" in payload["permissionDecisionReason"]
    assert ".provenrail.json" in payload["permissionDecisionReason"]
    assert "estimated at API list price" in payload["permissionDecisionReason"]


def test_the_ledger_carries_the_spend_across_hook_processes(workdir):
    """Every hook call is its own process. A figure held in memory would restart at zero on each
    one, which is exactly how the budget used to report itself armed while binding nothing."""
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)
    guard.run_hook(hook_payload(transcript))
    today, total, known = spend.prior_spend(guard.spend_agent_id())
    assert known is True
    assert today == pytest.approx(0.90)
    assert total == pytest.approx(0.90)


def test_the_same_transcript_read_twice_is_not_charged_twice(workdir):
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)
    for _ in range(4):
        assert verdict_of(guard.run_hook(hook_payload(transcript))[1]) == "allow"
    today, _, _ = spend.prior_spend(guard.spend_agent_id())
    assert today == pytest.approx(0.90)


def test_a_cap_already_over_from_an_earlier_session_denies_the_first_call_of_the_next(workdir):
    """The overnight-run case. Session two has spent nothing of its own and must still stop."""
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir)
    guard.run_hook(hook_payload(transcript, session="s1"))
    empty = workdir / "second.jsonl"
    empty.write_text("", encoding="utf-8")
    out = guard.run_hook(hook_payload(empty, session="s2"))[1]
    assert verdict_of(out) == "deny"


def test_a_rule_deny_still_wins_over_an_allowed_budget(workdir):
    """Adding a budget path before the rule loop must not shadow the rules that were there."""
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)
    out = guard.run_hook(hook_payload(transcript, command="rm -rf /var/data"))[1]
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    assert "destructive.recursive-force-remove" in payload["permissionDecisionReason"]


# ---------------------------------------------------------------- it never fails silently


def test_an_unreadable_transcript_allows_and_says_the_cap_cannot_bind(workdir):
    """Unknown, not zero. And said out loud: a cap that has stopped counting looks exactly like
    a cap with nothing to count, and the difference is the user's invoice."""
    write_config(workdir, DAY_CAP)
    code, out, err = guard.run_hook(hook_payload(workdir / "no-such-transcript.jsonl"))
    assert (code, verdict_of(out)) == (0, "allow")
    assert "spend cap cannot bind: transcript unreadable" in err


def test_the_cannot_bind_warning_is_said_once_a_day_and_not_once_a_tool_call(workdir):
    """A line on every tool call is noise, and noise is why people uninstall guardrails."""
    write_config(workdir, DAY_CAP)
    missing = workdir / "no-such-transcript.jsonl"
    first = guard.run_hook(hook_payload(missing))[2]
    second = guard.run_hook(hook_payload(missing))[2]
    assert "cannot bind" in first
    assert second == ""


def test_a_host_that_sends_no_transcript_path_is_reported_rather_than_assumed_free(workdir):
    write_config(workdir, DAY_CAP)
    err = guard.run_hook(hook_payload(None))[2]
    assert "spend cap cannot bind" in err
    assert "no transcript_path" in err


def test_a_payload_with_no_session_id_refuses_to_count_and_says_why(workdir):
    """Without a session key the read offset cannot be persisted, so the next call would price
    the whole transcript again and deny a correct cap within minutes."""
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir)
    payload = json.loads(hook_payload(transcript))
    payload["session_id"] = ""
    code, out, err = guard.run_hook(json.dumps(payload))
    assert verdict_of(out) == "allow"
    assert "no session_id" in err


def test_a_policy_that_is_only_a_budget_is_an_armed_policy(workdir):
    """It used to fall into the "nothing is armed, nothing is being blocked" branch, because
    that branch counted rules and a spend cap is not a rule. A config written by someone whose
    only interest is cost was therefore never evaluated at all."""
    write_config(workdir, {"policy": {"budgets": [{"scope": "day", "limit_usd": 1.0}]}})
    transcript = write_transcript(workdir)
    code, out, err = guard.run_hook(hook_payload(transcript))
    assert "NO guardrails are armed" not in err
    assert verdict_of(out) == "deny"


def test_a_model_with_no_price_follows_on_unpriced(workdir):
    """`warn` allows and says the total is a floor; `deny` refuses to run what it cannot count."""
    unpriced = workdir / "unpriced.jsonl"
    unpriced.write_text(json.dumps({
        "type": "assistant", "uuid": "u1",
        "message": {"id": "m1", "role": "assistant", "model": "grok-4-fast",
                    "usage": {"input_tokens": 500_000, "output_tokens": 100_000}}}) + "\n",
        encoding="utf-8")

    write_config(workdir, {"policy": {"budgets": [{"scope": "day", "limit_usd": 1.0}]}})
    assert verdict_of(guard.run_hook(hook_payload(unpriced))[1]) == "allow"

    write_config(workdir, {"policy": {"on_unpriced": "deny",
                                      "budgets": [{"scope": "day", "limit_usd": 1.0}]}})
    out = guard.run_hook(hook_payload(unpriced, session="s2"))[1]
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    assert "budget.unpriced" in payload["permissionDecisionReason"]


# ---------------------------------------------------------------- it costs nothing when unused


def test_a_policy_with_no_budgets_never_opens_the_transcript(workdir, monkeypatch):
    """Pricing a multi-megabyte transcript on every tool call would be a tax paid by every
    project that has never set a cap, which is almost all of them."""
    write_config(workdir, {"policy": {"use": ["destructive"]}})
    transcript = write_transcript(workdir)
    opened: list[str] = []
    real_open = builtins.open

    def spy(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy)
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: spy(self, *a, **k))
    guard.run_hook(hook_payload(transcript))
    assert not any(str(transcript) in name for name in opened)


def test_the_budget_path_leaves_the_policy_hash_alone():
    """`Policy.to_dict` is the basis of the policy id committed into every signed session and of
    the frozen conformance vectors. A budget evaluated at the tool boundary must not change it."""
    plain = load_policy({"use": ["destructive"]})
    before = plain.policy_id()
    plain.spent_verdict(__import__("provenrail.policy", fromlist=["x"]).SessionState())
    assert plain.policy_id() == before


# ---------------------------------------------------------------- what the user is shown


def test_guard_status_prints_todays_figure_from_the_ledger(workdir, capsys):
    from provenrail import cli

    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)
    guard.run_hook(hook_payload(transcript))
    cli.main(["guard", "status"])
    out = capsys.readouterr().out
    assert "budget.day" in out
    assert "$0.9000 of $1.00" in out
    # The claim `cli.py` used to print here was that tool hooks carry no model spend. It is now
    # false, and a stale sentence about money is the kind of drift this repo pins in a test.
    assert "tool hooks carry no model spend" not in out.lower()
    assert "estimated at API list price" in out


def test_the_counters_and_the_spend_cursor_share_a_file_without_erasing_each_other(workdir):
    """Both live in `.provenrail-guard-counts.json`. Writing one used to replace the whole entry,
    and losing the spend cursor means the next tool call re-prices the entire transcript."""
    write_config(workdir, {"policy": {
        "budgets": [{"scope": "day", "limit_usd": 100.0}],
        "rules": [{"id": "cap.bash", "effect": "limit", "event_type": "tool_call",
                   "arg_contains": "echo", "max_per_session": 5,
                   "reason": "at most five echoes"}]}})
    transcript = write_transcript(workdir, SPLIT_AT)
    guard.run_hook(hook_payload(transcript, command="echo hi"))
    guard.run_hook(hook_payload(transcript, command="echo hi"))
    data = json.loads((workdir / guard.COUNTS_FILENAME).read_text())
    entry = data["s1"]
    assert entry["counts"]["cap.bash"] == 2
    # The session keeps what a `session` cap counts; the read cursor lives under the transcript
    # it describes, which is why the key is looked up rather than assumed to be the session.
    assert entry["spend"]["session_usd"] == pytest.approx(0.90)
    cursor = data[transcript_mod.state_key(transcript)]
    assert cursor["spend"]["offset"] > 0


def test_two_sessions_reading_one_transcript_charge_the_day_ledger_once(workdir):
    """The read cursor belongs to the transcript, not to the session id reading it.

    Keyed on the session, a forked or re-identified session pointed at its parent's transcript
    found no cursor, started at offset zero, and charged the whole history to the shared day
    ledger a second time. The cap then refused work the user had already paid for, which is the
    direction a spend cap must never fail in.
    """
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)

    first = guard.run_hook(hook_payload(transcript, session="parent"))
    second = guard.run_hook(hook_payload(transcript, session="fork"))
    assert verdict_of(first[1]) == "allow"
    assert verdict_of(second[1]) == "allow", "the fork was charged its parent's spend again"
    today, _total, _known = spend.prior_spend(guard.spend_agent_id())
    assert today == pytest.approx(0.90)


def test_a_cursor_written_under_the_old_session_key_is_adopted_rather_than_recharged(workdir):
    """Upgrading mid-session must not recharge what the session already paid for.

    Before the cursor moved to the transcript it lived under the session id. Reading only the
    new key would have made the first tool call after the upgrade re-price the whole transcript.
    """
    write_config(workdir, DAY_CAP)
    transcript = write_transcript(workdir, SPLIT_AT)
    guard.run_hook(hook_payload(transcript))
    data = json.loads((workdir / guard.COUNTS_FILENAME).read_text())
    cursor = data.pop(transcript_mod.state_key(transcript))
    data["s1"]["spend"].update(cursor["spend"])
    (workdir / guard.COUNTS_FILENAME).write_text(json.dumps(data), encoding="utf-8")

    guard.run_hook(hook_payload(transcript))
    today, _total, _known = spend.prior_spend(guard.spend_agent_id())
    assert today == pytest.approx(0.90)
