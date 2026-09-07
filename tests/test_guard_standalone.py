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
from provenrail.easy import load_policy

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
