"""`pr guard`: the coding-agent guardrail hook.

The contract under test is the one a user's data depends on:
  1. the verdict is computed offline, so an unreachable sink can never turn deny into allow;
  2. deny/oversight/limit map onto Claude Code's deny/ask, not all onto "block";
  3. installing hooks never clobbers hooks the user already had;
  4. a decision that could not be recorded is journalled and reported as unsigned, not lost.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from provenrail import guard
from provenrail.easy import load_policy


def _policy(*packs: str):
    return load_policy({"use": list(packs)})


def _hook(tool="Bash", command="ls", event="PreToolUse", session="s1"):
    return {"hook_event_name": event, "tool_name": tool, "session_id": session,
            "tool_input": {"command": command}}


# ---------------------------------------------------------------- parsing


def test_parse_hook_input_reads_claude_code_shape():
    got = guard.parse_hook_input(_hook(command="rm -rf /tmp/x"))
    assert got["event"] == "pre"
    assert got["tool"] == "Bash"
    assert got["input"] == {"command": "rm -rf /tmp/x"}
    assert got["session_id"] == "s1"


def test_parse_hook_input_post_event():
    data = _hook(event="PostToolUse")
    data["tool_response"] = {"stdout": "ok"}
    got = guard.parse_hook_input(data)
    assert got["event"] == "post"
    assert got["response"] == {"stdout": "ok"}


def test_parse_hook_input_unknown_event_falls_back_to_declared_phase():
    # If Anthropic renames the event, we must not treat a completed call as a pre-gate.
    got = guard.parse_hook_input({"hook_event_name": "SomethingNew"}, default_event="post")
    assert got["event"] == "post"


def test_parse_hook_input_tolerates_missing_fields():
    got = guard.parse_hook_input({})
    assert got["tool"] == "" and got["input"] == {}


# ---------------------------------------------------------------- decisions


def test_recursive_rm_is_denied():
    d = guard.decide(_policy("destructive"), "Bash", {"command": "rm -rf ./build"})
    assert d["verdict"] == "deny"
    assert d["rule"] == "destructive.recursive-force-remove"


def test_terraform_destroy_and_force_push_are_denied():
    p = _policy("production")
    assert guard.decide(p, "Bash", {"command": "terraform destroy -auto-approve"})["verdict"] == "deny"
    assert guard.decide(p, "Bash", {"command": "git push --force origin main"})["verdict"] == "deny"


def test_leaked_key_in_a_write_is_denied():
    d = guard.decide(_policy("secrets"), "Write",
                     {"file_path": "a.py", "content": "KEY = 'sk-abcdefghijklmnopqrst'"})
    assert d["verdict"] == "deny"
    assert d["rule"] == "secrets.bearer-token"


def test_require_oversight_becomes_ask_not_deny():
    # The human answering the Claude Code prompt IS the oversight the rule wanted. Flattening
    # this into a hard deny is what makes people uninstall guardrails on day one.
    d = guard.decide(_policy("secrets"), "Read", {"file_path": ".env"})
    assert d["verdict"] == "ask"
    assert d["rule"] == "secrets.env-file-read"


def test_ordinary_command_is_allowed_silently():
    d = guard.decide(_policy("destructive", "secrets", "production"), "Bash",
                     {"command": "pytest -q"})
    assert d["verdict"] == "allow" and d["rule"] is None


def test_no_policy_allows_everything():
    assert guard.decide(None, "Bash", {"command": "rm -rf /"})["verdict"] == "allow"


# ---------------------------------------------------------------- the hook end to end


@pytest.fixture()
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))
    # No endpoint anywhere: recording must fail, enforcement must not.
    for var in ("PROVENRAIL_URL", "FLIGHTRECORDER_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["destructive", "secrets"]}}), encoding="utf-8")
    return tmp_path


def test_hook_blocks_even_when_the_sink_is_unreachable(workdir):
    code, out, err = guard.run_hook(json.dumps(_hook(command="rm -rf /var/data")))
    assert code == 0
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    assert "destructive.recursive-force-remove" in payload["permissionDecisionReason"]
    # And it says so rather than implying the block was recorded as evidence.
    assert "journalled" in payload["permissionDecisionReason"]


def test_unrecordable_decision_is_journalled(workdir):
    guard.run_hook(json.dumps(_hook(command="rm -rf /var/data")))
    entries = guard.read_journal()
    assert len(entries) == 1
    assert entries[0]["verdict"] == "deny"
    assert entries[0]["tool"] == "Bash"


def test_hook_allows_ordinary_commands_with_no_output(workdir):
    code, out, err = guard.run_hook(json.dumps(_hook(command="ls -la")))
    assert (code, out) == (0, "")


def test_hook_survives_garbage_input(workdir):
    code, out, err = guard.run_hook("not json at all")
    assert code == 0 and out == "" and "not JSON" in err


def test_hook_never_gates_a_post_event(workdir):
    data = _hook(command="rm -rf /var/data", event="PostToolUse")
    code, out, _ = guard.run_hook(json.dumps(data))
    assert (code, out) == (0, "")  # the call already ran; blocking it now would be theatre


def test_broken_policy_config_is_loud_and_not_silently_permissive(workdir):
    (workdir / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["no-such-pack"]}}), encoding="utf-8")
    code, out, err = guard.run_hook(json.dumps(_hook(command="rm -rf /")))
    assert code == 0 and out == ""
    assert "NOT enforcing" in err  # the user is told the guardrail is off, not left believing


# ---------------------------------------------------------------- install


def test_install_creates_hooks(tmp_path):
    path = guard.install_claude_hooks(root=tmp_path)
    settings = json.loads(path.read_text())
    pre = settings["hooks"]["PreToolUse"]
    assert len(pre) == 1
    assert pre[0]["hooks"][0]["command"] == "pr guard hook --event pre"
    assert "Bash" in pre[0]["matcher"]
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "pr guard hook --event post"


def test_install_is_idempotent(tmp_path):
    guard.install_claude_hooks(root=tmp_path)
    path = guard.install_claude_hooks(root=tmp_path)
    settings = json.loads(path.read_text())
    assert len(settings["hooks"]["PreToolUse"]) == 1


def test_install_preserves_existing_user_hooks(tmp_path):
    (tmp_path / ".claude").mkdir()
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "./my-own-hook.sh"}]}
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"model": "opus", "hooks": {"PreToolUse": [mine]}}), encoding="utf-8")
    path = guard.install_claude_hooks(root=tmp_path)
    settings = json.loads(path.read_text())
    assert settings["model"] == "opus"          # unrelated settings survive
    assert mine in settings["hooks"]["PreToolUse"]  # the user's own hook survives
    assert len(settings["hooks"]["PreToolUse"]) == 2


def test_uninstall_removes_only_ours(tmp_path):
    (tmp_path / ".claude").mkdir()
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "./my-own-hook.sh"}]}
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [mine]}}), encoding="utf-8")
    guard.install_claude_hooks(root=tmp_path)
    path, removed = guard.uninstall_claude_hooks(root=tmp_path)
    settings = json.loads(path.read_text())
    assert removed == 2
    assert settings["hooks"]["PreToolUse"] == [mine]


def test_hooks_installed_reports_state(tmp_path):
    assert guard.hooks_installed(root=tmp_path) is False
    guard.install_claude_hooks(root=tmp_path)
    assert guard.hooks_installed(root=tmp_path) is True


def test_invalid_settings_json_is_an_error_not_an_overwrite(tmp_path):
    (tmp_path / ".claude").mkdir()
    settings = tmp_path / ".claude" / "settings.json"
    settings.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(guard.GuardError):
        guard.install_claude_hooks(root=tmp_path)
    assert settings.read_text() == "{ this is not json"  # untouched


# ---------------------------------------------------------------- policy arming


def test_arm_default_policy_writes_packs(workdir):
    (workdir / ".provenrail.json").write_text(json.dumps({"endpoint": "http://x"}),
                                              encoding="utf-8")
    packs = guard.arm_default_policy()
    assert packs == guard.DEFAULT_PACKS
    cfg = json.loads((workdir / ".provenrail.json").read_text())
    assert cfg["policy"]["use"] == guard.DEFAULT_PACKS
    assert cfg["endpoint"] == "http://x"  # existing config preserved


def test_arm_default_policy_never_overwrites_a_configured_policy(workdir):
    (workdir / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["money"]}}), encoding="utf-8")
    assert guard.arm_default_policy() == ["money"]
    cfg = json.loads((workdir / ".provenrail.json").read_text())
    assert cfg["policy"]["use"] == ["money"]


def test_ask_is_remembered_so_the_approval_can_be_recorded(workdir):
    guard.run_hook(json.dumps(_hook(tool="Read", command=None, session="cc-9")
                              | {"tool_input": {"file_path": ".env"}}))
    assert guard.take_ask("cc-9", "Read") == "secrets.env-file-read"
    assert guard.take_ask("cc-9", "Read") is None  # popped, not re-usable


def test_a_denied_call_is_not_remembered_as_an_approval(workdir):
    guard.run_hook(json.dumps(_hook(command="rm -rf /x", session="cc-9")))
    assert guard.take_ask("cc-9", "Bash") is None


def test_take_ask_survives_a_corrupt_pending_file(workdir, monkeypatch):
    guard._pending_path().write_text("{ broken", encoding="utf-8")
    assert guard.take_ask("cc-9", "Read") is None


def test_journal_never_raises_on_an_unwritable_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "nope" / "j.jsonl"))
    guard.journal({"a": 1})  # must not raise: a log line is never worth breaking the agent
    assert guard.read_journal() == []


def test_journal_path_is_env_overridable(tmp_path, monkeypatch):
    target = tmp_path / "j.jsonl"
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(target))
    guard.journal({"tool": "Bash"})
    assert target.is_file()
    assert guard.read_journal()[0]["tool"] == "Bash"


def test_default_journal_name_when_env_unset(monkeypatch):
    monkeypatch.delenv("PROVENRAIL_GUARD_JOURNAL", raising=False)
    assert os.path.basename(str(guard._journal_path())) == guard.JOURNAL_FILENAME
