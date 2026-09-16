"""One policy, five coding agents, and no claim that we have driven any of them.

`guard.decide` was always host-agnostic. What was not agnostic was the payload it was handed
and the envelope it printed, and those are `hosts.py`. The tests here hold three properties
that a cross-host guard lives or dies by:

1. each host's deny envelope is EXACTLY what its own documentation says, because an envelope
   the host cannot parse is a guard that fails open on that host while looking installed;
2. every documented data-loss command is non-allow through every adapter, so the wedge
   ("one policy, whichever agent is running it") is a measurement rather than a slogan;
3. nothing here, and nothing in `src/`, calls a host verified when no payload from it has ever
   been captured. Every fixture in `tests/fixtures/hosts/` is hand-written from a vendor page
   and says so in the file.

The vendor pages, all read 2026-09-16, are in `hosts.HOSTS[...]["doc"]` next to the contract
each one describes, so the next person re-checks them instead of trusting this docstring.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_predicates import DATA_INCIDENTS, GIT_INCIDENTS

from provenrail import guard, hosts
from provenrail.easy import load_policy

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "hosts"
STANDALONE = ROOT / "plugins" / "provenrail-guard" / "scripts" / "guard_standalone.py"

#: Where each host puts the shell command inside its own payload. One place, because the same
#: table is what `hosts.py` parses and a second copy would let the two drift into agreement
#: with each other and disagreement with the vendor.
_COMMAND_FIELD = {
    "claude-code": ("tool_input", "command"),
    "codex": ("tool_input", "command"),
    "gemini": ("tool_input", "command"),
    "copilot": ("toolArgs", "command"),
    "cursor": ("command",),
}

ALL_HOSTS = list(hosts.HOST_NAMES)


def _fixture(host: str) -> dict:
    return json.loads((FIXTURES / f"{host}-pretooluse.json").read_text(encoding="utf-8"))


def _payload(host: str, command: str, cwd: str | None = None) -> dict:
    data = json.loads(json.dumps(_fixture(host)["payload"]))
    path = _COMMAND_FIELD[host]
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = command
    if cwd is not None:
        data["cwd"] = cwd
    return data


@pytest.fixture(scope="module")
def policy():
    return load_policy({"use": guard.DEFAULT_PACKS})


@pytest.fixture(scope="module")
def dirty_repo(tmp_path_factory):
    """A repository holding work that exists nowhere else, which is when the git rules bite."""
    path = tmp_path_factory.mktemp("dirty-hosts")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=path, check=True)
    (path / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------- envelopes


#: The deny envelope each vendor documents, to the byte, with the page it came from. Written
#: out as literal JSON rather than built from `hosts.py`, because a test that constructs the
#: expected value the same way the code does proves only that the code is self-consistent.
DOCUMENTED_DENY = {
    # https://code.claude.com/docs/en/hooks
    "claude-code": '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
                   '"permissionDecision": "deny", "permissionDecisionReason": "REASON"}}',
    # https://learn.chatgpt.com/docs/hooks: the same three keys under hookSpecificOutput.
    "codex": '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
             '"permissionDecision": "deny", "permissionDecisionReason": "REASON"}}',
    # https://geminicli.com/docs/hooks/reference/
    "gemini": '{"decision": "deny", "reason": "REASON"}',
    # https://docs.github.com/en/copilot/reference/hooks-reference
    "copilot": '{"permissionDecision": "deny", "permissionDecisionReason": "REASON"}',
    # https://cursor.com/docs/agent/hooks
    "cursor": '{"permission": "deny", "user_message": "REASON", "agent_message": "REASON"}',
}


@pytest.mark.parametrize("host", ALL_HOSTS)
def test_the_deny_envelope_is_byte_identical_to_the_one_the_vendor_documents(host):
    assert hosts.render(host, "deny", "REASON") == DOCUMENTED_DENY[host]


@pytest.mark.parametrize("host", ALL_HOSTS)
def test_an_allowed_command_adds_nothing_to_the_agents_path_on_every_host_that_reads_silence(
        host):
    """Four hosts read an empty stdout as "this hook has no opinion". Cursor documents that
    invalid JSON or a schema mismatch BLOCKS the action, so it is the one host that must be
    told "allow" out loud, or the guard would block every ordinary command in the session."""
    out = hosts.render(host, "allow", "")
    if host == "cursor":
        assert json.loads(out) == {"permission": "allow"}
    else:
        assert out == ""


@pytest.mark.parametrize("host", ALL_HOSTS)
def test_a_host_that_cannot_ask_a_human_is_told_deny_and_told_why(host):
    out = hosts.render(host, "ask", "REASON")
    if hosts.supports_ask(host):
        assert json.loads(out.replace("REASON", "R"))  # parses
        assert hosts.ASK_NOTE in out
        assert '"deny"' not in out
    else:
        assert hosts.NO_ASK_NOTE.strip() in out
        assert "deny" in out


def test_the_hosts_with_no_ask_verdict_are_exactly_gemini_and_codex():
    """Pinned rather than derived. Codex documents `permissionDecision` on PreToolUse, and its
    `PermissionRequest` event has not been driven here, so oversight is enforced as a block
    until it has been. Moving a host into the ask column is a decision someone must make on
    purpose, with evidence, not a default that drifts."""
    assert [h for h in ALL_HOSTS if not hosts.supports_ask(h)] == ["codex", "gemini"]


# ---------------------------------------------------------------- the policy travels


@pytest.mark.parametrize("command", GIT_INCIDENTS + DATA_INCIDENTS)
@pytest.mark.parametrize("host", ALL_HOSTS)
def test_a_documented_data_loss_command_is_not_allowed_silently_on_any_host(
        policy, dirty_repo, host, command):
    """The wedge, measured: the same catalogue that stops these on Claude Code stops them on
    every host, because the only thing that differs is the envelope."""
    hook = hosts.parse(host, _payload(host, command, cwd=dirty_repo))
    decision = guard.decide(policy, hook["tool"], hook["input"], None, hook["cwd"])
    assert decision["verdict"] != "allow", (host, command)
    assert hosts.render(host, decision["verdict"], "R") != "", (host, command)


@pytest.mark.parametrize("host", ALL_HOSTS)
def test_ordinary_work_is_not_interrupted_on_any_host(policy, dirty_repo, host):
    for command in ("git status", "git commit -m wip", "npx prisma migrate dev", "ls -la"):
        hook = hosts.parse(host, _payload(host, command, cwd=dirty_repo))
        decision = guard.decide(policy, hook["tool"], hook["input"], None, hook["cwd"])
        assert decision["verdict"] == "allow", (host, command)


# ---------------------------------------------------------------- tool names


def test_each_hosts_documented_tool_names_map_onto_the_names_the_rules_are_written_in():
    """`not_tool` lists say `Read|Glob|Grep`, so a host calling its reader `view` or
    `read_file` would have every grep for the text "rm -rf" screened as if it were a delete."""
    assert hosts.canonical_tool("gemini", "run_shell_command") == "Bash"
    assert hosts.canonical_tool("gemini", "read_file") == "Read"
    assert hosts.canonical_tool("gemini", "replace") == "Edit"
    assert hosts.canonical_tool("copilot", "bash") == "Bash"
    assert hosts.canonical_tool("copilot", "powershell") == "Bash"
    assert hosts.canonical_tool("copilot", "view") == "Read"
    assert hosts.canonical_tool("copilot", "grep") == "Grep"
    assert hosts.canonical_tool("codex", "apply_patch") == "Edit"
    assert hosts.canonical_tool("codex", "Bash") == "Bash"


def test_an_undocumented_tool_name_is_screened_rather_than_skipped():
    """An unknown name matches no `not_tool` exclusion, so the call is screened as if it were a
    command. That is the safe direction: the cost is a false positive, and the cost of guessing
    the other way is a missed delete."""
    assert hosts.canonical_tool("gemini", "some_new_tool") == "some_new_tool"


def test_a_cursor_mcp_call_is_named_the_way_the_mcp_rules_are_written():
    """The catalogue's only MCP protection is `mcp__*__[dD]elete*`. Cursor sends the server
    name and the tool name separately, so unless they are composed those rules match nothing
    and an MCP `deleteVolume` goes through unscreened, which is the PocketOS incident."""
    hook = hosts.parse("cursor", {"hook_event_name": "beforeMCPExecution",
                                  "tool_name": "deleteVolume", "mcp_server_name": "fly",
                                  "tool_input": '{"id": "vol_1"}', "conversation_id": "c"})
    assert hook["tool"] == "mcp__fly__deleteVolume"
    assert hook["input"] == {"id": "vol_1"}


def test_a_cursor_shell_call_is_named_bash_because_the_event_is_the_tool():
    hook = hosts.parse("cursor", _payload("cursor", "rm -rf ~/"))
    assert hook["tool"] == "Bash"
    assert hook["input"] == {"command": "rm -rf ~/"}


# ---------------------------------------------------------------- failing closed


def test_an_unknown_host_refuses_to_pretend_it_guarded_anything():
    """Twice now this product has shipped a guard that reported itself armed and screened
    nothing. A host we have no contract for exits 2, which every supported host documents as a
    block, and says on stderr that nothing screened the call."""
    code, out, err = guard.run_hook(
        json.dumps(_payload("claude-code", "rm -rf ~/")), host="not-a-real-agent")
    assert code == guard.UNKNOWN_HOST_EXIT
    assert out == ""
    assert "unknown host" in err and "NOT enforcing" in err
    assert "claude-code" in err  # it says what it does know


def test_an_unknown_host_is_refused_by_the_zero_install_engine_too():
    proc = subprocess.run([sys.executable, str(STANDALONE), "--host", "not-a-real-agent"],
                          input="{}", capture_output=True, text=True)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "unknown host" in proc.stderr


@pytest.mark.parametrize("host,payload", [
    ("codex", {"hook_event_name": "PreToolUse", "cwd": "/tmp"}),
    ("gemini", {"hook_event_name": "BeforeTool", "cwd": "/tmp"}),
    ("copilot", {"tool_name": "bash", "cwd": "/tmp"}),      # Claude's spelling, not Copilot's
    ("cursor", {"conversation_id": "c", "cwd": "/tmp"}),
])
def test_a_payload_that_is_not_the_shape_we_documented_blocks_instead_of_passing_through(
        host, payload):
    """On a host nobody has driven, a shape we do not recognise means this adapter is wrong,
    not that the call is safe. Passing it through would be a guard reporting itself armed while
    reading an empty object, which is this project's worst failure mode."""
    with pytest.raises(hosts.PayloadShapeError):
        hosts.parse(host, payload)
    code, out, err = guard.run_hook(json.dumps(payload), host=host)
    assert code == 0                       # never break the session with an exit code
    assert "deny" in out                   # but never wave it through either
    assert "could not read" in err


def test_the_claude_code_payload_stays_tolerant_because_it_is_the_one_that_has_been_driven():
    """Asymmetry on purpose. An unfamiliar Claude Code payload is most likely a vendor rename
    of a contract this code has answered thousands of times; an unfamiliar payload on a host
    nobody has run is most likely us. Tolerance where there is evidence, refusal where there
    is none."""
    got = guard.parse_hook_input({})
    assert got["tool"] == "" and got["input"] == {}


# ---------------------------------------------------------------- the record is not flattened


def test_require_oversight_stays_require_oversight_even_where_the_host_can_only_deny(
        tmp_path, monkeypatch):
    """The standing rule: never flatten what the policy decided into what the host could
    express. Gemini has no ask, so the agent is told deny, and the journal still carries the
    policy's own verdict with the host's beside it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["git-worktree"]}}), encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=tmp_path, check=True)
    (tmp_path / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / ".provenrail-guard.jsonl"))

    payload = _payload("gemini", "git reset --hard HEAD~1", cwd=str(tmp_path))
    code, out, _ = guard.run_hook(json.dumps(payload), host="gemini")
    assert code == 0
    assert json.loads(out)["decision"] == "deny"

    entries = [json.loads(line) for line in
               (tmp_path / ".provenrail-guard.jsonl").read_text(encoding="utf-8").splitlines()]
    blocked = [e for e in entries if e.get("rule")]
    assert blocked, entries
    assert blocked[-1]["verdict"] == "ask", "the policy asked for a human; the record must say so"
    assert blocked[-1]["host_verdict"] == "deny"
    assert blocked[-1]["host"] == "gemini"


def test_the_agent_is_told_why_it_was_blocked_rather_than_just_that_it_was():
    """An agent told only "blocked" retries a different spelling. It is told that a human would
    have been asked and cannot be, which is a different instruction."""
    out = hosts.render("gemini", "ask", "Provenrail guardrail x: y")
    assert "cannot put a decision to a human" in json.loads(out)["reason"]
    assert "require_oversight" in json.loads(out)["reason"]


# ---------------------------------------------------------------- install


@pytest.mark.parametrize("host", [h for h in ALL_HOSTS if h != hosts.DEFAULT_HOST])
def test_installing_a_host_hook_writes_its_own_config_and_a_second_run_changes_nothing(
        tmp_path, host):
    """An installer that does not recognise its own entry appends a duplicate on every run,
    and the guard ends up running five times per tool call and being blamed for the latency."""
    path = guard.install_hooks(host, tmp_path)
    assert path.is_file()
    first = path.read_text(encoding="utf-8")
    assert f"--host {host}" in first
    again = guard.install_hooks(host, tmp_path)
    assert again == path
    assert path.read_text(encoding="utf-8") == first


@pytest.mark.parametrize("host", [h for h in ALL_HOSTS if h != hosts.DEFAULT_HOST])
def test_installing_a_host_hook_leaves_the_users_own_hooks_alone(tmp_path, host):
    plan = hosts.install_plan(host, "x", 1)
    path = tmp_path.joinpath(*plan["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    event = next(iter(plan["entries"]))
    theirs = {"theirs": True, "command": "./scripts/mine.sh"}
    path.write_text(json.dumps({"hooks": {event: [theirs]}, "theirSetting": 7}),
                    encoding="utf-8")
    guard.install_hooks(host, tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["theirSetting"] == 7
    assert theirs in data["hooks"][event]
    assert len(data["hooks"][event]) == len(plan["entries"][event]) + 1


@pytest.mark.parametrize("host", [h for h in ALL_HOSTS if h != hosts.DEFAULT_HOST])
def test_the_installed_config_is_the_path_the_vendor_documents(tmp_path, host):
    documented = {
        # https://learn.chatgpt.com/docs/hooks
        "codex": ".codex/hooks.json",
        # https://geminicli.com/docs/hooks/reference/
        "gemini": ".gemini/settings.json",
        # https://docs.github.com/en/copilot/reference/hooks-reference (a directory of *.json)
        "copilot": ".github/hooks/provenrail.json",
        # https://cursor.com/docs/agent/hooks
        "cursor": ".cursor/hooks.json",
    }
    path = guard.install_hooks(host, tmp_path)
    assert path.relative_to(tmp_path).as_posix() == documented[host]
    assert hosts.HOSTS[host]["config"] == documented[host]


def test_installing_claude_code_still_goes_through_the_installer_that_has_users(tmp_path):
    path = guard.install_hooks("claude-code", tmp_path)
    assert path == tmp_path / guard.CLAUDE_SETTINGS
    settings = json.loads(path.read_text(encoding="utf-8"))
    assert "PreToolUse" in settings["hooks"] and "PostToolUse" in settings["hooks"]


def test_installing_an_unknown_host_refuses_rather_than_writing_a_file_nothing_reads(tmp_path):
    with pytest.raises(hosts.UnknownHost):
        guard.install_hooks("not-a-real-agent", tmp_path)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------- no invented evidence


def test_every_host_fixture_says_in_the_file_whether_it_was_captured_or_written():
    """No invented fixtures. A file hand-written from a vendor page and a payload captured from
    a running CLI are different kinds of evidence, and the difference has to survive being read
    by someone who was not here."""
    for host in ALL_HOSTS:
        data = _fixture(host)
        assert isinstance(data.get("_synthetic"), bool), host
        assert data["_source"].startswith("https://"), host
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["_checked"]), host
        if data["_synthetic"]:
            assert "SYNTHETIC" in data["_why"], host


def test_a_host_is_in_the_captured_list_exactly_when_a_captured_fixture_exists():
    captured = {h for h in ALL_HOSTS if not _fixture(h)["_synthetic"]}
    assert set(hosts.CAPTURED_PAYLOAD) == captured


#: Words that turn "we read the docs" into "we ran it". Any of them on a line that also names
#: an uncaptured host is the claim this test exists to stop, wherever in `src/` it appears.
_CLAIM_WORDS = ("verified", "captured", "driven", "proven", "tested against")

#: How a host might be named in prose or in a string the user sees.
_HOST_MENTIONS = {
    "claude-code": ("Claude Code",),
    "codex": ("Codex",),
    "gemini": ("Gemini",),
    "copilot": ("Copilot",),
    "cursor": ("Cursor",),
}


def test_a_host_with_no_captured_payload_is_never_called_verified_anywhere_in_src():
    """The mirror of `test_claims_hygiene.py`'s detector-list test, for hosts. The memo that
    commissioned this module tripped over exactly this claim on the way to writing it: it said
    five hosts were already half-supported because a regex somewhere matched their names.

    Scoped to `src/`, which is what ships and what the site quotes. Test files are allowed to
    say "not captured" in as many words as they like."""
    offences = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            if not any(word in lowered for word in _CLAIM_WORDS):
                continue
            if "not " in lowered or "never" in lowered or "no payload" in lowered:
                continue  # a denial of the claim is the opposite of the claim
            for host, names in _HOST_MENTIONS.items():
                if host in hosts.CAPTURED_PAYLOAD:
                    continue
                if any(name in line for name in names):
                    offences.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert not offences, (
        "a host with no captured payload is described as verified:\n  "
        + "\n  ".join(offences))


def test_the_contract_for_every_host_carries_the_url_and_the_date_it_was_read():
    """A contract without a source is a contract nobody can re-check, which means the next
    person either trusts it or re-derives it, and both of those are how it rots."""
    for host in ALL_HOSTS:
        entry = hosts.HOSTS[host]
        assert entry["doc"].startswith("https://"), host
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["checked"]), host
        assert entry["label"] and entry["events"], host


def test_no_em_dash_or_en_dash_reaches_a_user_facing_host_string():
    text = (ROOT / "src" / "provenrail" / "hosts.py").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text


# ---------------------------------------------------------------- the command line


@pytest.mark.parametrize("host", ALL_HOSTS)
def test_pr_guard_install_host_writes_the_config_and_a_second_run_changes_nothing(
        tmp_path, monkeypatch, host, capsys):
    """The install the docs will tell people to run, end to end, in a directory that starts
    empty. Run twice, because the second run is where an installer that cannot recognise its
    own entry quietly doubles the guard."""
    from provenrail import cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"endpoint": "http://127.0.0.1:8787"}), encoding="utf-8")

    assert cli.main(["guard", "install", "--host", host]) == 0
    written = {p: p.read_text(encoding="utf-8") for p in sorted(tmp_path.rglob("*.json"))}
    assert any(f"--host {host}" in text or host == hosts.DEFAULT_HOST
               for text in written.values())
    capsys.readouterr()
    assert cli.main(["guard", "install", "--host", host]) == 0
    assert {p: p.read_text(encoding="utf-8") for p in sorted(tmp_path.rglob("*.json"))} == written


def test_pr_guard_install_says_the_contract_was_read_and_not_driven(tmp_path, monkeypatch,
                                                                    capsys):
    """The person installing an adapter nobody has run against the real CLI is the first who
    can find out it is wrong. They are told that at the moment they install it, not in a doc
    they will not open."""
    from provenrail import cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"endpoint": "http://127.0.0.1:8787"}), encoding="utf-8")
    cli.main(["guard", "install", "--host", "gemini"])
    out = capsys.readouterr().out
    assert hosts.HOSTS["gemini"]["doc"] in out
    assert "No payload from" in out
    assert "has no way to ask a human" in out


def test_pr_guard_hook_refuses_a_host_the_code_has_no_contract_for(capsys):
    """argparse catches the typo before a hook ever runs, which is the cheapest place to catch
    it, and the exit code is non-zero so an install script cannot ignore it."""
    from provenrail import cli

    with pytest.raises(SystemExit) as raised:
        cli.main(["guard", "hook", "--host", "not-a-real-agent"])
    assert raised.value.code != 0
