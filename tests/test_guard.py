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

#: A directory that is a git repository, so the delete predicates have a workspace to measure
#: against rather than whatever directory pytest happened to start in.
REPO = Path(__file__).resolve().parent.parent


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


def test_a_recursive_rm_is_denied_by_its_target_not_by_its_flags():
    """`rm -rf ./build` used to be denied and is now allowed, deliberately. Over 36,929 real
    agent commands the two rm rules produced 646 of 824 interruptions and almost none were
    dangerous; a guard that stops a build directory clean-up is uninstalled the same day. The
    target is what makes a delete unrecoverable, so the target is what is screened."""
    policy = _policy("destructive")
    inside = guard.decide(policy, "Bash", {"command": "rm -rf ./build"}, None, str(REPO))
    assert inside["verdict"] == "allow"
    d = guard.decide(policy, "Bash", {"command": "rm -rf ~/"}, None, str(REPO))
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
    # Every tool, not a named list. A named list covered the built-in tools and nothing else,
    # so an MCP server's deleteVolume and a Read of ~/.ssh/id_ed25519 reached no rule at all
    # while the catalogue advertised rules for both. Scope lives in the rules now.
    assert pre[0]["matcher"] == "*"
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


# ------------------------------------------------- blast-radius caps across hook processes


def _capped(cap: int):
    """A one-rule policy whose `limit` effect is the thing under test."""
    return load_policy({"rules": [
        {"id": "cap.tool-calls", "effect": "limit", "event_type": "tool_call",
         "tool": "Bash", "max_per_session": cap, "reason": "session tool-call cap reached"},
    ]})


def test_limit_rules_accumulate_across_separate_hook_processes(workdir):
    """The bug this closes: each hook invocation is a new process, so a per-session cap that
    lived only in memory reset on every call and capped nothing. A cap that never caps is
    worse than no cap, because `pr guard status` reports it as armed."""
    policy = _capped(2)
    verdicts = [guard.decide(policy, "Bash", {"command": f"echo {i}"}, session_id="s-cap")
                for i in range(4)]
    assert [v["verdict"] for v in verdicts] == ["allow", "allow", "deny", "deny"]
    assert "cap" in (verdicts[2]["reason"] or "").lower()


def test_counters_are_scoped_per_session(workdir):
    policy = _capped(1)
    assert guard.decide(policy, "Bash", {"command": "a"}, session_id="s-A")["verdict"] == "allow"
    assert guard.decide(policy, "Bash", {"command": "b"}, session_id="s-A")["verdict"] == "deny"
    # A different Claude Code session must start from zero, not inherit the neighbour's count.
    assert guard.decide(policy, "Bash", {"command": "c"}, session_id="s-B")["verdict"] == "allow"


def test_no_session_id_falls_back_to_in_process_counting(workdir):
    """Callers that have no session id (a bare SDK call) must still work, just without
    cross-process accumulation, rather than raising or writing a junk state key."""
    policy = _capped(1)
    assert guard.decide(policy, "Bash", {"command": "a"})["verdict"] == "allow"
    assert guard.decide(policy, "Bash", {"command": "b"})["verdict"] == "allow"
    assert not guard._counts_path().exists()


def test_reset_clears_the_counters(workdir):
    policy = _capped(1)
    guard.decide(policy, "Bash", {"command": "a"}, session_id="s-r")
    assert guard.decide(policy, "Bash", {"command": "b"}, session_id="s-r")["verdict"] == "deny"
    guard.reset_counts()
    assert guard.decide(policy, "Bash", {"command": "c"}, session_id="s-r")["verdict"] == "allow"


def test_stale_sessions_are_pruned(workdir):
    """Counters must not be immortal: a cap set weeks ago must not deny the first matching
    call of a session that happens to reuse the id."""
    import time
    guard.save_counts("old", {"cap.tool-calls": 99})
    data = guard._read_counts_file()
    data["old"]["updated"] = int(time.time()) - guard.COUNTS_TTL_S - 1
    guard._write_json_atomic(guard._counts_path(), data)
    guard.save_counts("new", {"cap.tool-calls": 1})
    assert "old" not in guard._read_counts_file()
    assert guard.load_counts("old") == {}


def test_a_corrupt_counter_file_never_breaks_the_verdict(workdir):
    """The counters file is local and editable. Corrupting it must degrade to "count from
    zero", never to an exception that takes down the user's tool call."""
    guard._counts_path().write_text("{not json", encoding="utf-8")
    assert guard.load_counts("s1") == {}
    out = guard.decide(_policy("destructive"), "Bash", {"command": "rm -rf /x"},
                       session_id="s1")
    assert out["verdict"] == "deny"


def test_deny_rules_never_consult_the_counter_file(workdir):
    """Deny and oversight are the rules that actually protect. They must not become
    bypassable by deleting or editing a local JSON file."""
    guard._counts_path().write_text(json.dumps({"s1": {"counts": {}, "updated": 0}}),
                                    encoding="utf-8")
    for _ in range(3):
        out = guard.decide(_policy("destructive"), "Bash", {"command": "rm -rf /x"},
                           session_id="s1")
        assert out["verdict"] == "deny"


def test_hook_end_to_end_enforces_the_cap_across_invocations(workdir):
    (workdir / ".provenrail.json").write_text(json.dumps({"policy": {
        "rules": [{"id": "cap.tool-calls", "effect": "limit", "event_type": "tool_call",
                   "tool": "Bash", "max_per_session": 1, "reason": "cap reached"}]}}),
        encoding="utf-8")
    first = guard.run_hook(json.dumps(_hook(command="echo one", session="live")))
    assert first[1] == ""  # allowed, nothing added to the agent's path
    second = guard.run_hook(json.dumps(_hook(command="echo two", session="live")))
    assert json.loads(second[1])["hookSpecificOutput"]["permissionDecision"] == "deny"


# ------------------------------------------------- finding the policy from a subdirectory


def test_policy_is_found_from_a_subdirectory(tmp_path, monkeypatch):
    """`pr guard install` writes the policy at the repo root, but agents are routinely launched
    from a subdirectory (a package in a monorepo, apps/web, a nested worktree). Searching only
    the current directory meant the hook found no policy and allowed everything, silently. That
    is the worst failure mode available: the user installed it, so they believe they are covered.
    """
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["destructive"]}}), encoding="utf-8")
    nested = tmp_path / "apps" / "web" / "src"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nowhere"))
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))

    payload = json.loads(guard.run_hook(json.dumps(_hook(command="rm -rf /var/data")))[1])
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_journal_stays_with_the_policy_not_the_cwd(tmp_path, monkeypatch):
    """Otherwise a session started in a subdirectory opens a second, invisible journal and its
    blast-radius counters restart from zero."""
    from provenrail.easy import find_config_file

    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["destructive"]}}), encoding="utf-8")
    nested = tmp_path / "packages" / "api"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.delenv("PROVENRAIL_GUARD_JOURNAL", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nowhere"))

    assert find_config_file() == tmp_path / ".provenrail.json"
    assert guard._journal_path().parent == tmp_path
    assert guard._counts_path().parent == tmp_path


def test_an_explicit_journal_override_still_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "custom.jsonl"))
    assert guard._journal_path() == tmp_path / "custom.jsonl"


# ------------------------------------------------- hooks installed but nothing armed


def test_hooks_without_a_policy_say_so_instead_of_going_quiet(tmp_path, monkeypatch):
    """A silent allow is indistinguishable from a working guardrail. If the hooks are wired but
    no rules are armed, the user has to be told, or they run unguarded believing otherwise."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nowhere"))
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))

    code, out, err = guard.run_hook(json.dumps(_hook(command="rm -rf /")))
    assert code == 0 and out == ""          # never block on a configuration problem
    assert "NO guardrails are armed" in err


def test_the_no_policy_warning_is_at_most_daily(tmp_path, monkeypatch):
    """Warning on every tool call is noise, and noise gets the plugin uninstalled."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nowhere"))
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))

    first = guard.run_hook(json.dumps(_hook(command="ls")))[2]
    second = guard.run_hook(json.dumps(_hook(command="ls")))[2]
    assert first and second == ""


# ------------------------------------------------- the copy has to match the code


# Every capability the site, the README, the plugin README and the PyPI summary promise, as
# (command, expected verdict). If a claim is added to the copy it is added here; if it cannot
# pass, the claim is wrong and it comes out of the copy. This table caught four false claims:
# `chmod 777` lived in a pack the default install did not arm, `TRUNCATE orders` needed the
# optional `TABLE` keyword, `dd of=/dev/` and `kubectl delete namespace` had no rule at all,
# and the token pattern matched only the retired `sk-` key format.
ADVERTISED = [
    # git-worktree. The incident class the plugin exists for, and the one the default install
    # allowed until the pack was written. Verified against a repository holding uncommitted
    # work, because that is when these commands cost something.
    ("git reset --hard origin/main", "ask"),
    ("git checkout -- .", "ask"),
    ("git restore .", "ask"),
    ("git clean -fd", "ask"),
    ("git stash drop", "ask"),
    ("git branch -D feature/wip", "ask"),
    ("git worktree remove --force ../wt", "ask"),
    ("git push origin --delete main", "ask"),
    ("git push origin :main", "ask"),
    ("rsync -a --delete build/ /srv/www/", "ask"),
    ("Remove-Item -Recurse -Force *", "ask"),
    ("git reflog expire --expire=now --all", "deny"),
    ("git filter-repo --path secret --invert-paths", "deny"),
    # destructive
    ("rm -rf ~/", "deny"),
    ("rm -fr /var/data", "deny"),
    ("rm -rf $UNSET_ANYWHERE/", "deny"),
    ("rm -rf --no-preserve-root /", "deny"),
    ("terraform destroy", "deny"),
    ("dd if=/dev/zero of=/dev/sda", "deny"),
    ("kubectl delete namespace prod", "deny"),
    ("psql -c 'DROP TABLE users'", "deny"),
    ("psql -c 'DROP DATABASE prod'", "deny"),
    ("psql -c 'TRUNCATE orders'", "deny"),
    ("psql -c 'TRUNCATE TABLE orders'", "deny"),
    ("psql -c 'DELETE FROM orders'", "deny"),
    ("git push --force origin main", "deny"),
    # database
    ("npx prisma migrate reset --force", "ask"),
    ("supabase db reset", "ask"),
    ("rails db:drop", "ask"),
    ("php artisan migrate:fresh", "ask"),
    ("python manage.py flush", "ask"),
    ("alembic downgrade base", "ask"),
    ("dropdb myapp_production", "ask"),
    ("redis-cli FLUSHALL", "ask"),
    # cloud
    ("aws rds delete-db-instance --db-instance-identifier prod", "ask"),
    ("aws s3 rb s3://my-bucket --force", "ask"),
    ("gcloud sql instances delete prod-db", "ask"),
    ("az group delete --name prod-rg", "ask"),
    ("fly volumes destroy vol_123", "ask"),
    ("npx wrangler d1 delete provenrail-prod", "ask"),
    ("heroku pg:reset DATABASE_URL", "ask"),
    ("pulumi destroy --yes", "ask"),
    ("cdk destroy --force", "ask"),
    ("terraform state rm module.db", "ask"),
    ("helm uninstall api -n prod", "ask"),
    ("kubectl delete pvc data-postgres-0", "ask"),
    ("docker compose down -v", "ask"),
    # secrets. Fake keys, shaped like the real ones.
    ("export OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "deny"),
    ("export ANTHROPIC_API_KEY=sk-ant-api03-bbbbbbbbbbbbbbbbbbbbbbbb", "deny"),
    ("curl -H 'Authorization: token ghp_cccccccccccccccccccccccccc'", "deny"),
    ("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE", "deny"),
    ("cat .env", "ask"),
    ("cat .env.example", "allow"),
    # access
    ("chmod 777 /etc/passwd", "deny"),
    ("chmod a+rwx /etc/passwd", "deny"),
    ("aws iam update-account-password-policy --disable-mfa", "deny"),
    # oversight, not denial: these need a human, they are not forbidden
    ("psql postgres://u:p@db.prod.example.com/app -c 'select 1'", "ask"),
    ("npx wrangler pages deploy web", "ask"),
    ("kubectl apply -f deploy.yaml --context production", "ask"),
]


@pytest.fixture(scope="module")
def repo_with_unpushed_work(tmp_path_factory):
    """The git rules ask only when there is work that exists nowhere else, so the page's claims
    have to be checked in a repository that has some."""
    import subprocess

    path = tmp_path_factory.mktemp("advertised")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=path, check=True)
    (path / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("command,expected", ADVERTISED)
def test_the_default_install_does_what_the_copy_says(command, expected,
                                                     repo_with_unpushed_work):
    """A guardrail advertised as blocking something it does not block is worse than one that
    never claimed it: the user reads the list, believes it, and stops checking."""
    policy = load_policy({"use": guard.DEFAULT_PACKS})
    got = guard.decide(policy, "Bash", {"command": command}, None, repo_with_unpushed_work)
    assert got["verdict"] == expected, (
        f"copy says {expected} but got {got['verdict']} ({got['rule']}): {command}")


def test_ordinary_commands_are_not_touched():
    """The other half of the contract. A guard that blocks normal work gets uninstalled, and
    then it protects nothing at all."""
    policy = load_policy({"use": guard.DEFAULT_PACKS})
    for command in ["ls -la", "git status", "npm test", "pytest -q", "git commit -m 'fix'",
                    "rm ./tmp.txt", "chmod 644 file.py", "docker ps", "git push origin main",
                    "kubectl get pods", "terraform plan", "npm run build",
                    "psql postgres://localhost/app_dev -c 'select 1'",
                    "psql -c 'SELECT count(*) FROM orders'",
                    "psql -c 'DELETE FROM orders WHERE id = 3'",
                    "grep -rn TRUNCATE ./docs", "dd if=disk.img of=./copy.img"]:
        got = guard.decide(policy, "Bash", {"command": command})
        assert got["verdict"] == "allow", (
            f"false positive on ordinary work ({got['rule']}): {command}")


# ---------------------------------------------------------------- adversarial review, 0.3.1
#
# Three findings from an adversarial pass over the shipped guard. Each was reproduced against
# the real engine before it was fixed, and each is a total bypass of the product's headline
# claim rather than an edge case, so each gets a test that fails if the fix is ever undone.


def _default_policy():
    from provenrail.easy import load_policy
    return load_policy({"use": guard.DEFAULT_PACKS})


def test_padding_cannot_hide_a_destructive_command_from_a_content_rule():
    """The argument text was silently truncated at 20,000 characters before any content rule
    ran, so twenty thousand characters of comment in front of `rm -rf /` matched nothing and
    the call was allowed. A valid bash script, and a complete defeat of every advertised rule.
    """
    policy = _default_policy()
    for pad in (20_001, 50_000, 500_000):
        command = "#" * pad + "\nrm -rf /var/data"
        verdict = guard.decide(policy, "Bash", guard._coerce_tool_input({"command": command}))
        assert verdict["verdict"] == "deny", f"{pad} characters of padding hid the command"
        assert verdict["rule"] == "destructive.recursive-force-remove"


def test_an_argument_too_large_to_screen_asks_rather_than_passing():
    """Past the cap the engine cannot answer, and an argument it could not read is not an
    argument known to be safe. It must not deny either: a legitimate multi-megabyte file write
    would then be blocked outright."""
    from provenrail.policy import MAX_MATCH_TEXT, UNSCREENABLE

    policy = _default_policy()
    command = "#" * (MAX_MATCH_TEXT + 5) + "\nrm -rf /"
    verdict = guard.decide(policy, "Bash", guard._coerce_tool_input({"command": command}))
    assert verdict["verdict"] == "ask"
    assert verdict["rule"] == UNSCREENABLE
    assert "cannot be screened" in verdict["reason"]


def test_a_blast_radius_cap_does_not_disarm_the_deny_rules_after_it():
    """`blast-radius.tool-call-cap` matches tool "*", and a `limit` rule under its cap used to
    return ALLOW immediately. So `use: ["blast-radius", "destructive"]`, which is the obvious
    thing to write when you want both, let `rm -rf /` through for the first 500 calls of every
    session while reporting itself armed."""
    from provenrail.easy import load_policy

    policy = load_policy({"use": ["blast-radius", "destructive"]})
    verdict = guard.decide(policy, "Bash", guard._coerce_tool_input({"command": "rm -rf /"}))
    assert verdict["verdict"] == "deny"
    assert verdict["rule"] == "destructive.recursive-force-remove"
    # And the cap still caps when nothing denies.
    allowed = guard.decide(policy, "Bash", guard._coerce_tool_input({"command": "ls -la"}))
    assert allowed["verdict"] == "allow"


def test_a_satisfied_oversight_rule_does_not_disarm_a_later_deny():
    """Same class as the cap: an allow found in the loop is provisional until nothing later
    denies. Ordering a permissive rule before a strict one must not silence the strict one."""
    from provenrail.easy import load_policy
    from provenrail.policy import SessionState

    policy = load_policy({"rules": [
        {"id": "soft.env", "effect": "require_oversight", "event_type": "tool_call",
         "arg_contains": r"\.env", "reason": "touches .env"},
        {"id": "hard.rm", "effect": "deny", "event_type": "tool_call",
         "arg_contains": r"rm\s+-rf", "reason": "recursive delete"},
    ]})
    state = SessionState()
    state.had_oversight = True
    decision = policy.decide("tool_call", {"tool": "Bash", "match_text": "rm -rf .env"}, state)
    assert decision.effect == "deny"
    assert decision.rule_id == "hard.rm"


def test_the_hook_command_is_quoted_so_an_install_path_with_a_space_still_works():
    """Unquoted, `${CLAUDE_PLUGIN_ROOT}/scripts/pr-guard-hook.sh` word-splits: the shell reports
    "no such file", exits 127 with no stdout, and Claude Code reads no stdout as "no opinion".
    Every tool call then proceeds unguarded, with nothing said to the user. Plugin paths with
    spaces are ordinary on macOS and Windows."""
    import json as _json
    import pathlib

    hooks = _json.loads((pathlib.Path(__file__).resolve().parent.parent / "plugins" /
                         "provenrail-guard" / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    commands = [h["command"] for event in hooks.values() for entry in event
                for h in entry["hooks"]]
    assert commands
    for command in commands:
        assert '"${CLAUDE_PLUGIN_ROOT}' in command, f"unquoted plugin root in {command!r}"
        assert command.count('"') >= 2
