"""The zero-install guard must reach the same verdict as the installed one.

`plugins/provenrail-guard/scripts/guard_standalone.py` exists so that installing the plugin
protects the next tool call with nothing else on the machine. That makes it a second
implementation of the enforcement path, and this project has already paid once for two
implementations that quietly disagreed (three anchor-verify holes, all from reimplementing
what the verifier already did). The answer there was a lockstep test, and it is the answer
here: every case below is driven through BOTH engines and the verdicts must match.

It also checks the thing a lockstep test cannot: that the vendored rule data is a faithful
copy of the catalogue, since a stale copy would put the two engines on different rules while
agreeing perfectly about each of them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from provenrail import guard
from provenrail.easy import PolicyConfigError, load_policy

ROOT = Path(__file__).resolve().parent.parent
STANDALONE = ROOT / "plugins" / "provenrail-guard" / "scripts" / "guard_standalone.py"
VENDOR = ROOT / "tools" / "vendor_guard_rules.py"

# (tool, tool_input) pairs covering every effect the catalogue can produce, plus the payload
# shapes that have previously disarmed the guard.
CASES = [
    ("Bash", {"command": "ls -la"}),
    ("Bash", {"command": "rm -rf /"}),
    ("Bash", {"command": "rm -rf ~/"}),
    ("Bash", {"command": "sudo rm -rf --no-preserve-root /"}),
    ("Bash", {"command": "dd if=/dev/zero of=/dev/disk2 bs=1m"}),
    ("Bash", {"command": "kubectl delete namespace production"}),
    ("Bash", {"command": "kubectl delete ns staging"}),
    ("Bash", {"command": "git push --force origin main"}),
    ("Bash", {"command": "git push origin main"}),
    ("Bash", {"command": "terraform destroy -auto-approve"}),
    ("Bash", {"command": "psql -c 'DROP TABLE users'"}),
    ("Bash", {"command": "psql -c 'DELETE FROM users'"}),
    ("Bash", {"command": "chmod 777 /etc/passwd"}),
    ("Bash", {"command": "cat .env"}),
    ("Bash", {"command": "npx wrangler pages deploy web"}),
    ("Bash", {"command": "supabase db push"}),
    ("Bash", {"command": "echo AKIAIOSFODNN7EXAMPLE >> config.txt"}),
    ("Write", {"file_path": "k.pem", "content": "-----BEGIN RSA PRIVATE KEY-----\nabc"}),
    ("Edit", {"file_path": "a.py", "old_string": "x", "new_string": "y"}),
    # Payload shapes that are not a dict. Each one has been a real disarming bug: a string
    # command, an argv array, and a shape nobody anticipated.
    ("Bash", "rm -rf /var/data"),
    ("Bash", ["rm", "-rf", "/var/data"]),
    ("Bash", None),
    ("Bash", 42),
    ("Bash", {"command": "rm\t-rf /var/data"}),
    ("", {"command": "rm -rf /"}),
]


def _installed_verdict(packs, tool, tool_input):
    policy = load_policy({"use": list(packs)})
    return guard.decide(policy, tool, guard._coerce_tool_input(tool_input))["verdict"]


def _standalone_verdict(tmp_path, packs, tool, tool_input, write_config=True):
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
               "session_id": "s1", "cwd": str(tmp_path)}
    if write_config:
        (tmp_path / ".provenrail.json").write_text(
            json.dumps({"policy": {"use": list(packs)}}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--event", "pre"],
        input=json.dumps(payload), capture_output=True, text=True, cwd=str(tmp_path),
        # A HOME with no .provenrail.json, so the upward search cannot reach the operator's own.
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    assert proc.returncode == 0, proc.stderr
    if not proc.stdout.strip():
        return "allow"
    out = json.loads(proc.stdout)
    return out["hookSpecificOutput"]["permissionDecision"]


@pytest.mark.parametrize("tool,tool_input", CASES,
                         ids=[f"{i}-{t or 'notool'}" for i, (t, _) in enumerate(CASES)])
def test_both_engines_agree_on_every_case(tmp_path, tool, tool_input):
    packs = guard.DEFAULT_PACKS
    assert _standalone_verdict(tmp_path, packs, tool, tool_input) == \
        _installed_verdict(packs, tool, tool_input)


@pytest.mark.parametrize("pack", ["destructive", "secrets", "production", "access",
                                  "money", "exfiltration"])
def test_both_engines_agree_pack_by_pack(tmp_path, pack):
    """Not just the default set: a user who arms one pack must get the same answer too."""
    for tool, tool_input in CASES:
        assert _standalone_verdict(tmp_path, [pack], tool, tool_input) == \
            _installed_verdict([pack], tool, tool_input), (pack, tool, tool_input)


def test_the_vendored_rules_are_not_stale():
    """A stale copy is the failure this whole file cannot otherwise see: both engines would
    still agree with themselves while enforcing different rules."""
    proc = subprocess.run([sys.executable, str(VENDOR), "--check"],
                          capture_output=True, text=True, cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr + "\n" + proc.stdout


def test_the_default_packs_are_armed_with_no_config_at_all(tmp_path):
    """The entire point of the zero-install path: no `.provenrail.json`, still blocked."""
    assert _standalone_verdict(tmp_path, [], "Bash", {"command": "rm -rf /"},
                               write_config=False) == "deny"
    assert _standalone_verdict(tmp_path, [], "Bash", {"command": "ls"},
                               write_config=False) == "allow"


def test_an_explicit_empty_policy_disarms_and_says_so(tmp_path):
    """Whoever writes a config outranks our defaults, including a config that arms nothing."""
    (tmp_path / ".provenrail.json").write_text('{"policy": {"use": []}}', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--event", "pre"],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf /"}, "session_id": "s"}),
        capture_output=True, text=True, cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.stdout.strip() == ""
    assert "NO guardrails are armed" in proc.stderr


def test_a_config_that_only_sets_a_stream_still_gets_the_defaults(tmp_path):
    """A `.provenrail.json` written by `pr quickstart` says nothing about guardrails. Reading
    that as "run unguarded" would silently disarm every existing user on upgrade."""
    (tmp_path / ".provenrail.json").write_text('{"stream_id": "abc"}', encoding="utf-8")
    assert _standalone_verdict(tmp_path, [], "Bash", {"command": "rm -rf /"},
                               write_config=False) == "deny"


def test_a_broken_policy_is_loud_and_not_silently_permissive(tmp_path):
    (tmp_path / ".provenrail.json").write_text('{"policy": {"use": ["destuctive"]}}',
                                               encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--event", "pre"],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf /"}, "session_id": "s"}),
        capture_output=True, text=True, cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.returncode == 0
    assert "NOT enforcing" in proc.stderr
    assert "destuctive" in proc.stderr


def test_garbage_on_stdin_never_breaks_the_session(tmp_path):
    for raw in ("", "not json", "[]", "null"):
        proc = subprocess.run(
            [sys.executable, str(STANDALONE), "--event", "pre"],
            input=raw, capture_output=True, text=True, cwd=str(tmp_path),
            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""


def test_a_block_is_journalled_where_the_installed_cli_will_find_it(tmp_path):
    """The upgrade path is only real if `pr guard status` reads the history this wrote."""
    (tmp_path / ".provenrail.json").write_text('{"policy": {"use": ["destructive"]}}',
                                               encoding="utf-8")
    _standalone_verdict(tmp_path, ["destructive"], "Bash", {"command": "rm -rf /"})
    lines = (tmp_path / guard.JOURNAL_FILENAME).read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    assert entry["verdict"] == "deny"
    assert entry["rule"] == "destructive.recursive-force-remove"
    assert entry["by"] == "standalone"


def test_a_limit_rule_actually_caps_across_processes(tmp_path):
    """Every hook call is its own process. A count held in memory would cap nothing while
    `pr guard status` reported the rule as armed."""
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"rules": [
            {"id": "cap.bash", "effect": "limit", "event_type": "tool_call",
             "arg_contains": "echo", "max_per_session": 2,
             "reason": "at most two echoes per session"}]}}), encoding="utf-8")
    verdicts = [_standalone_verdict(tmp_path, [], "Bash", {"command": "echo hi"},
                                    write_config=False) for _ in range(4)]
    assert verdicts == ["allow", "allow", "deny", "deny"]


# ---------------------------------------------------------------- adversarial review, 0.3.1
#
# The bypasses found against the installed engine exist in this one too, and a fix that lands
# in only one of them is the divergence this whole file exists to prevent.

ADVERSARIAL_CASES = [
    ("Bash", {"command": "#" * 20_001 + "\nrm -rf /var/data"}),
    ("Bash", {"command": "#" * 50_000 + "\ngit push --force origin main"}),
    ("Bash", {"command": "x" * 30_000 + "; terraform destroy -auto-approve"}),
]


@pytest.mark.parametrize("tool,tool_input", ADVERSARIAL_CASES,
                         ids=["pad-rm", "pad-force-push", "pad-terraform"])
def test_padding_hides_nothing_from_either_engine(tmp_path, tool, tool_input):
    packs = guard.DEFAULT_PACKS
    standalone = _standalone_verdict(tmp_path, packs, tool, tool_input)
    assert standalone == _installed_verdict(packs, tool, tool_input)
    assert standalone == "deny"


def test_both_engines_ask_rather_than_pass_an_unscreenable_argument(tmp_path):
    from provenrail.policy import MAX_MATCH_TEXT

    payload = {"command": "#" * (MAX_MATCH_TEXT + 5) + "\nrm -rf /"}
    assert _standalone_verdict(tmp_path, guard.DEFAULT_PACKS, "Bash", payload) == "ask"
    assert _installed_verdict(guard.DEFAULT_PACKS, "Bash", payload) == "ask"


def test_both_engines_keep_the_deny_rules_behind_a_blast_radius_cap(tmp_path):
    """A `limit` rule matching tool "*" used to short-circuit the whole ruleset in the installed
    engine while the standalone kept scanning, so the two disagreed AND the signed one was the
    permissive half: installing Provenrail made a blocked call succeed."""
    packs = ["blast-radius", "destructive"]
    payload = {"command": "rm -rf /"}
    assert _standalone_verdict(tmp_path, packs, "Bash", payload) == "deny"
    assert _installed_verdict(packs, "Bash", payload) == "deny"


# ---------------------------------------------------------------- the spend cap, 0.5.0
#
# The cap is the one control in this space with proven payment behaviour, and it now answers in
# both engines. A dollar figure that differs between them is worse than a rule verdict that
# does: the user reads one number in `/guard-status` and is stopped at a different one.

TRANSCRIPT = ROOT / "tests" / "fixtures" / "transcripts" / "claude-code-spend.jsonl"
TRANSCRIPT_LINES = [ln for ln in TRANSCRIPT.read_text(encoding="utf-8").splitlines() if ln.strip()]
#: The fixture marks where its own labelled costs total $0.90, under a $1.00 cap and over its
#: 80% warning line. `tests/test_transcript.py` is what holds that invariant.
SPLIT_AT = next(i for i, ln in enumerate(TRANSCRIPT_LINES) if json.loads(ln).get("_split"))

DAY_CAP = {"policy": {"use": ["destructive"],
                      "budgets": [{"scope": "day", "limit_usd": 1.0, "warn_at": 0.8}]}}


def _spend_payload(workdir, command="ls -la"):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
            "tool_input": {"command": command}, "cwd": str(workdir),
            "transcript_path": str(workdir / "transcript.jsonl")}


def _lay_out(workdir, upto=None):
    (workdir / ".provenrail.json").write_text(json.dumps(DAY_CAP), encoding="utf-8")
    (workdir / "transcript.jsonl").write_text("\n".join(TRANSCRIPT_LINES[:upto]) + "\n",
                                              encoding="utf-8")


def _figure(text):
    """The dollar amounts a reason quotes, which is what the user is actually told."""
    import re
    return re.findall(r"\$[\d,]+\.\d{4}", text or "")


def _answer(stdout):
    """(verdict, rule id, dollar figures) from a hook's stdout, in whichever engine wrote it."""
    if not stdout.strip():
        return "allow", None, []
    payload = json.loads(stdout)["hookSpecificOutput"]
    reason = payload["permissionDecisionReason"]
    rule = reason.split("Provenrail guardrail ", 1)[-1].split(":", 1)[0]
    return payload["permissionDecision"], rule, _figure(reason)


def _standalone_run(workdir, payload):
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--event", "pre"],
        input=json.dumps(payload), capture_output=True, text=True, cwd=str(workdir),
        env={"PATH": "/usr/bin:/bin", "HOME": str(workdir)})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout, proc.stderr


def _installed_run(workdir, payload, monkeypatch):
    monkeypatch.chdir(workdir)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: workdir))
    for var in ("PROVENRAIL_URL", "FLIGHTRECORDER_URL", "PROVENRAIL_GUARD_JOURNAL",
                "PROVENRAIL_SPEND_LEDGER"):
        monkeypatch.delenv(var, raising=False)
    _, out, err = guard.run_hook(json.dumps(payload))
    return out, err


def test_both_engines_deny_the_same_tool_call_at_the_same_dollar(tmp_path, monkeypatch):
    """Same transcript, same cap, same verdict, same rule id, same number on screen."""
    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        _lay_out(workdir)
    standalone = _answer(_standalone_run(one, _spend_payload(one))[0])
    installed = _answer(_installed_run(two, _spend_payload(two), monkeypatch)[0])
    assert standalone == installed
    assert standalone[0] == "deny"
    assert standalone[1] == "budget.day"
    assert standalone[2] == ["$1.5000", "$1.0000"]


def test_both_engines_allow_and_warn_at_the_same_point(tmp_path, monkeypatch):
    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        _lay_out(workdir, SPLIT_AT)
    assert _answer(_standalone_run(one, _spend_payload(one))[0])[0] == "allow"
    assert _answer(_installed_run(two, _spend_payload(two), monkeypatch)[0])[0] == "allow"
    warnings = []
    for workdir in (one, two):
        entries = [json.loads(line) for line in
                   (workdir / guard.JOURNAL_FILENAME).read_text(encoding="utf-8").splitlines()]
        warned = [e for e in entries if e.get("warning")]
        assert len(warned) == 1
        warnings.append(warned[0]["warning"])
    assert warnings[0] == warnings[1]
    assert "90% of the $1.0000 cap" in warnings[0]


def test_both_engines_write_the_same_ledger_figure(tmp_path, monkeypatch):
    """They share one ledger file on a real machine: installing the CLI over a working plugin
    must continue the day's spend, not start a second, invisible count under another key."""
    from provenrail import spend

    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        _lay_out(workdir, SPLIT_AT)
    _standalone_run(one, _spend_payload(one))
    _installed_run(two, _spend_payload(two), monkeypatch)
    ledgers = [json.loads((w / spend.LEDGER_FILENAME).read_text(encoding="utf-8"))
               for w in (one, two)]
    assert ledgers[0]["agents"]["default"]["total_usd"] == \
        ledgers[1]["agents"]["default"]["total_usd"]
    assert ledgers[0]["agents"]["default"]["total_usd"] == pytest.approx(0.90)


def test_both_engines_refuse_a_budget_that_could_never_bind(tmp_path, monkeypatch):
    """A misspelled scope or a missing limit reads like a spend control and enforces nothing,
    so both engines refuse to load it rather than arming a policy that lies."""
    for broken in ({"scope": "daily", "limit_usd": 5},
                   {"scope": "day"},
                   {"scope": "day", "limit_usd": 0},
                   {"scope": "day", "limit_usd": 5, "warn": 0.9}):
        one = tmp_path / ("s" + str(abs(hash(str(broken)))))
        one.mkdir()
        (one / ".provenrail.json").write_text(
            json.dumps({"policy": {"use": ["destructive"], "budgets": [broken]}}),
            encoding="utf-8")
        stdout, stderr = _standalone_run(one, _spend_payload(one))
        assert stdout.strip() == ""
        assert "NOT enforcing" in stderr, broken
        with pytest.raises(PolicyConfigError):
            load_policy({"use": ["destructive"], "budgets": [broken]})


def test_a_policy_with_no_budget_makes_neither_engine_read_a_transcript(tmp_path):
    """There is no default cap, so this is the path almost every install takes."""
    workdir = tmp_path / "plain"
    workdir.mkdir()
    (workdir / ".provenrail.json").write_text(json.dumps({"policy": {"use": ["destructive"]}}),
                                              encoding="utf-8")
    (workdir / "transcript.jsonl").write_text("\n".join(TRANSCRIPT_LINES) + "\n",
                                              encoding="utf-8")
    _standalone_run(workdir, _spend_payload(workdir))
    from provenrail import spend
    assert not (workdir / spend.LEDGER_FILENAME).exists()
    assert not (workdir / guard.COUNTS_FILENAME).exists()


#: The interpreters the vendored engine has to survive. The plugin's shim runs `python3` off the
#: user's PATH, which on macOS is still the 3.9 that ships with the developer tools, so the suite
#: is not allowed to test only the interpreter the maintainer happens to be using. Vendoring
#: `spend.py` broke exactly here: `from datetime import UTC` is 3.11 and up, and the import error
#: took the whole guard down to "allowing" on every tool call.
INTERPRETERS = [sys.executable] + [p for p in ("/usr/bin/python3",) if Path(p).exists()]


@pytest.mark.parametrize("module", ["pricing", "spend", "transcript", "shell", "predicates",
                                    "welcome"])
@pytest.mark.parametrize("interpreter", INTERPRETERS)
def test_every_vendored_module_imports_with_no_provenrail_on_the_path(module, interpreter):
    """They are vendored precisely so they run where the package does not exist. A dependency
    that only resolves because the repo happens to be importable would work in this suite and
    fail on every real install."""
    scripts = STANDALONE.parent
    proc = subprocess.run(
        [interpreter, "-c",
         f"import sys; sys.path[:] = [p for p in sys.path if 'flightrecorder' not in p]; "
         f"sys.path.insert(0, {str(scripts)!r}); import {module} as m; print(m.__file__)"],
        capture_output=True, text=True, cwd=str(scripts))
    assert proc.returncode == 0, proc.stderr
    assert str(scripts) in proc.stdout


def test_a_config_that_only_sets_a_spend_cap_does_not_disarm_the_rules(tmp_path, monkeypatch):
    """`/guard-budget 25` and `pr guard budget 25` both write a policy block with no `use` key.
    Reading that as "the user chose no rules" meant that arming a spend cap switched off every
    destructive rule in both engines at once, while each of them reported a cap as armed."""
    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        (workdir / ".provenrail.json").write_text(
            json.dumps({"policy": {"budgets": [{"scope": "day", "limit_usd": 100.0}]}}),
            encoding="utf-8")
        (workdir / "transcript.jsonl").write_text("", encoding="utf-8")
    payload = dict(_spend_payload(one), tool_input={"command": "rm -rf /var/data"})
    standalone = _answer(_standalone_run(one, payload)[0])
    installed = _answer(_installed_run(two, dict(payload, cwd=str(two),
                                                 transcript_path=str(two / "transcript.jsonl")),
                                       monkeypatch)[0])
    assert standalone == installed
    assert standalone[0] == "deny"
    assert standalone[1] == "destructive.recursive-force-remove"


def test_neither_engine_tells_a_project_with_a_config_file_that_it_has_none(tmp_path,
                                                                            monkeypatch):
    """`pr guard budget 1` writes a .provenrail.json holding a cap and no rules. The defaults arm
    because it named no rules, and the first line both engines printed was "because this project
    has no .provenrail.json", at a user whose file the same command had just written. The clause
    is derived from the situation now, so both engines say the same true thing."""
    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        (workdir / ".provenrail.json").write_text(
            json.dumps({"policy": {"budgets": [{"scope": "day", "limit_usd": 100.0}]}}),
            encoding="utf-8")
        (workdir / "transcript.jsonl").write_text("", encoding="utf-8")
    payload = dict(_spend_payload(one), tool_input={"command": "echo hi"})
    standalone = _standalone_run(one, payload)[1]
    installed = _installed_run(two, dict(payload, cwd=str(two),
                                         transcript_path=str(two / "transcript.jsonl")),
                               monkeypatch)[1]
    armed = [text.splitlines()[0] for text in (standalone, installed)]
    assert armed[0] == armed[1]
    assert "armed with" in armed[0]
    assert "has no .provenrail.json" not in armed[0]
    assert "sets no rules" in armed[0]


def test_neither_engine_charges_one_transcript_twice_for_two_session_ids(tmp_path, monkeypatch):
    """A forked or re-identified session reads the same transcript under a new session id. Keyed
    on the session, the read cursor started at zero for the second one and charged the parent's
    entire history to the shared day ledger a second time: $0.90 became $1.80, over a $1.00 cap,
    and the agent was refused work that had already been paid for. Failing in the direction that
    stops work is the worse direction, so both engines key the cursor on the transcript."""
    from provenrail import spend

    one, two = tmp_path / "standalone", tmp_path / "installed"
    for workdir in (one, two):
        workdir.mkdir()
        _lay_out(workdir, SPLIT_AT)

    def payload_for(workdir, session):
        return dict(_spend_payload(workdir), session_id=session, cwd=str(workdir),
                    transcript_path=str(workdir / "transcript.jsonl"))

    answers = []
    for session in ("parent", "fork"):
        answers.append(_answer(_standalone_run(one, payload_for(one, session))[0]))
        answers.append(_answer(_installed_run(two, payload_for(two, session), monkeypatch)[0]))
    assert [a[0] for a in answers] == ["allow"] * 4
    ledgers = [json.loads((w / spend.LEDGER_FILENAME).read_text(encoding="utf-8"))
               for w in (one, two)]
    assert ledgers[0]["agents"]["default"]["total_usd"] == pytest.approx(0.90)
    assert ledgers[1]["agents"]["default"]["total_usd"] == pytest.approx(0.90)


# ---------------------------------------------------------------- one policy, five hosts

#: Where each host's own envelope carries the verdict, read from the vendor pages rather than
#: from `hosts.py`, so this stays a second reading of the contract instead of an echo of ours.
#: https://code.claude.com/docs/en/hooks, https://learn.chatgpt.com/docs/hooks,
#: https://geminicli.com/docs/hooks/reference/,
#: https://docs.github.com/en/copilot/reference/hooks-reference,
#: https://cursor.com/docs/agent/hooks (all read 2026-09-16).
HOST_VERDICT_KEY = {
    "claude-code": lambda out: out["hookSpecificOutput"]["permissionDecision"],
    "codex": lambda out: out["hookSpecificOutput"]["permissionDecision"],
    "gemini": lambda out: out["decision"],
    "copilot": lambda out: out["permissionDecision"],
    "cursor": lambda out: out["permission"],
}

HOST_FIXTURES = ROOT / "tests" / "fixtures" / "hosts"


def _host_payload(host, command, cwd):
    """That host's documented field names, from its synthetic fixture, with one command in it."""
    data = json.loads(
        (HOST_FIXTURES / f"{host}-pretooluse.json").read_text(encoding="utf-8"))["payload"]
    if host == "cursor":
        data["command"] = command
    elif host == "copilot":
        data["toolArgs"] = {"command": command}
    else:
        data["tool_input"] = {"command": command}
    data["cwd"] = cwd
    return data


def _standalone_host_verdict(tmp_path, host, command):
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--host", host],
        input=json.dumps(_host_payload(host, command, str(tmp_path))),
        capture_output=True, text=True, cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.returncode == 0, proc.stderr
    if not proc.stdout.strip():
        return "allow"
    return HOST_VERDICT_KEY[host](json.loads(proc.stdout))


@pytest.mark.parametrize("host", ["claude-code", "codex", "gemini", "copilot", "cursor"])
@pytest.mark.parametrize("command", ["rm -rf /", "rm -rf ~/", "chmod 777 /etc/passwd", "ls -la"])
def test_both_engines_reach_the_same_verdict_on_every_host(tmp_path, host, command):
    """The lockstep that already covers the rules now covers the adapters. Two engines that
    agree about Claude Code and disagree about Cursor would ship a guard whose behaviour
    depends on which of the two happened to answer, which is the failure this file exists for."""
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": list(guard.DEFAULT_PACKS)}}), encoding="utf-8")
    from provenrail import hosts

    hook = hosts.parse(host, _host_payload(host, command, str(tmp_path)))
    policy = load_policy({"use": list(guard.DEFAULT_PACKS)})
    installed = guard.decide(policy, hook["tool"], hook["input"], None, hook["cwd"])["verdict"]
    expected = hosts.host_verdict(host, installed)
    assert _standalone_host_verdict(tmp_path, host, command) == expected


def test_the_zero_install_engine_answers_an_unknown_host_with_a_block_not_with_silence(tmp_path):
    """Exit 2 is the one blocking signal every supported host documents. Silence is "allow" on
    four of the five, and a guard that quietly stops guarding is the failure this product has
    already shipped twice."""
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--host", "borg"],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}),
        capture_output=True, text=True, cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "unknown host" in proc.stderr and "NOT enforcing" in proc.stderr


def test_an_unarmed_project_still_tells_cursor_to_carry_on(tmp_path):
    """Cursor documents that invalid JSON or a schema mismatch BLOCKS the action, so the paths
    that mean "nothing is armed" and "the policy would not load" must still print an allow
    there. A guard that bricks every command in a project it was never configured for is worse
    than one that was never installed."""
    (tmp_path / ".provenrail.json").write_text('{"policy": {"use": []}}', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(STANDALONE), "--host", "cursor"],
        input=json.dumps(_host_payload("cursor", "rm -rf /", str(tmp_path))),
        capture_output=True, text=True, cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"permission": "allow"}
    assert "NO guardrails are armed" in proc.stderr
