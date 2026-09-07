"""Which engine answers the hook, and what happens when neither can.

The shim in front of both engines is three dozen lines of shell that nobody reads and that
every single tool call goes through. Two of its failures are silent by construction: it exits 0
with no output when anything goes wrong, and Claude Code reads no output as "no opinion". So
the shim's own behaviour has to be driven, not reasoned about.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parent.parent / "plugins" / "provenrail-guard"
HOOK = PLUGIN / "scripts" / "pr-guard-hook.sh"


def _fake_pr(directory: Path, version: str) -> Path:
    """A stand-in CLI that identifies itself as ours and answers every call with a marker."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "pr"
    path.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  --help) echo "provenrail: guardrails for coding agents"; exit 0;;\n'
        f'  --version) echo "provenrail {version}"; exit 0;;\n'
        "esac\n"
        "cat >/dev/null\n"
        'printf \'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"deny","permissionDecisionReason":"ANSWERED-BY-FAKE-CLI"}}\'\n',
        encoding="utf-8")
    path.chmod(0o755)
    return path


def _run(work: Path, path_entries: list[str], command: str = "rm -rf /") -> str:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}, "session_id": "shim", "cwd": str(work)}
    env = {"PATH": ":".join([*path_entries, "/usr/bin", "/bin"]),
           "HOME": str(work),
           "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
           "TMPDIR": str(work / "tmp")}
    (work / "tmp").mkdir(exist_ok=True)
    proc = subprocess.run(["bash", str(HOOK), "pre"], input=json.dumps(payload),
                          capture_output=True, text=True, cwd=str(work), env=env)
    assert proc.returncode == 0, f"the shim must never fail the session: {proc.stderr}"
    return proc.stdout


@pytest.fixture()
def work(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=tmp_path, check=True)
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": ["destructive"]}}), encoding="utf-8")
    return tmp_path


def _plugin_version() -> str:
    return json.loads((PLUGIN / ".claude-plugin" / "plugin.json")
                      .read_text(encoding="utf-8"))["version"]


def test_a_cli_at_least_as_new_as_the_plugin_answers(work, tmp_path):
    """The installed CLI is preferred when it is current, because it signs what it decides."""
    bin_dir = tmp_path / "newbin"
    _fake_pr(bin_dir, "99.0.0")
    assert "ANSWERED-BY-FAKE-CLI" in _run(work, [str(bin_dir)])


def test_a_cli_older_than_the_plugin_is_skipped_for_the_bundled_engine(work, tmp_path):
    """Updating the plugin ships new rules. An older `pr` left on the machine from months ago
    would answer with its own older ruleset, the user would see none of what the update added,
    and nothing anywhere would say why. This was real: a 0.2.30 CLI on the developer's own
    machine silently shadowed every rule added in 0.4."""
    bin_dir = tmp_path / "oldbin"
    _fake_pr(bin_dir, "0.2.30")
    out = _run(work, [str(bin_dir)])
    assert "ANSWERED-BY-FAKE-CLI" not in out
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_the_exact_plugin_version_counts_as_new_enough(work, tmp_path):
    bin_dir = tmp_path / "samebin"
    _fake_pr(bin_dir, _plugin_version())
    assert "ANSWERED-BY-FAKE-CLI" in _run(work, [str(bin_dir)])


def test_a_pr_that_is_not_ours_is_ignored(work, tmp_path):
    """`pr` is also a POSIX text-formatting utility, and paginating the hook payload into
    stdout would be read by Claude Code as a decision."""
    bin_dir = tmp_path / "notours"
    bin_dir.mkdir()
    other = bin_dir / "pr"
    other.write_text("#!/bin/sh\necho 'pr - print files'\ncat\n", encoding="utf-8")
    other.chmod(0o755)
    out = _run(work, [str(bin_dir)])
    assert "print files" not in out
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_crashing_cli_never_breaks_the_session(work, tmp_path):
    """Exit 0, no output. Claude Code reads that as no opinion and the call proceeds, which is
    the right failure: a guardrail that bricks the agent is uninstalled, and then it guards
    nothing at all."""
    bin_dir = tmp_path / "brokenbin"
    bin_dir.mkdir()
    broken = bin_dir / "pr"
    broken.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  --help) echo provenrail; exit 0;;\n'
        '  --version) echo "provenrail 99.0.0"; exit 0;;\n'
        "esac\n"
        "echo 'boom' >&2\nexit 3\n", encoding="utf-8")
    broken.chmod(0o755)
    assert _run(work, [str(bin_dir)]) == ""


def test_the_bundled_engine_answers_with_no_cli_at_all(work):
    out = _run(work, [])
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_an_ordinary_command_produces_no_output_from_either_engine(work):
    assert _run(work, [], command="ls -la") == ""


@pytest.mark.skipif(os.name == "nt", reason="the shim is a POSIX shell script")
def test_the_shim_is_valid_shell():
    assert subprocess.run(["bash", "-n", str(HOOK)], capture_output=True).returncode == 0


def test_the_engine_choice_is_remembered_so_it_is_not_probed_every_call(work, tmp_path):
    """The probe spawns a Python CLI, which is around 50 ms, and this shim now runs in front of
    EVERY tool call rather than seven named ones. Paid a few hundred times an hour that is the
    difference between a plugin people keep and one they blame for the session feeling slow.
    Measured before the cache: 215 ms per call, of which 112 ms was `pr --help` plus
    `pr --version` on a CLI that was then rejected for being too old."""
    bin_dir = tmp_path / "counted"
    bin_dir.mkdir()
    counter = tmp_path / "probes"
    fake = bin_dir / "pr"
    fake.write_text(
        "#!/bin/sh\n"
        f'echo x >> "{counter}"\n'
        'case "$1" in\n'
        '  --version) echo "provenrail 99.0.0"; exit 0;;\n'
        "esac\n"
        "cat >/dev/null\n"
        'printf \'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"deny","permissionDecisionReason":"ANSWERED-BY-FAKE-CLI"}}\'\n',
        encoding="utf-8")
    fake.chmod(0o755)

    for _ in range(4):
        assert "ANSWERED-BY-FAKE-CLI" in _run(work, [str(bin_dir)])

    calls = counter.read_text(encoding="utf-8").count("x")
    # Four decisions, but only ONE of the calls may be a version probe.
    assert calls == 5, f"expected 4 decisions + 1 probe, got {calls} invocations"


def test_a_remembered_binary_that_has_gone_away_is_not_used(work, tmp_path):
    """A cache entry can only ever pick the wrong ENGINE, never the wrong verdict, and a stale
    entry naming a binary that no longer exists has to fall back rather than fail."""
    bin_dir = tmp_path / "vanishing"
    _fake_pr(bin_dir, "99.0.0")
    assert "ANSWERED-BY-FAKE-CLI" in _run(work, [str(bin_dir)])

    (bin_dir / "pr").unlink()
    out = _run(work, [str(bin_dir)])
    assert "ANSWERED-BY-FAKE-CLI" not in out
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_the_bundled_engine_is_not_spawned_at_all_for_a_post_event(work):
    """PostToolUse is the recorder, and the bundled engine is not a recorder: on a post event it
    does nothing but emit a notice the pre path emits anyway. Spawning Python per tool call for
    that is around 40 ms an agent pays for nothing, now that hooks are wired to every tool."""
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
               "tool_input": {"command": "rm -rf /"}, "session_id": "shim", "cwd": str(work)}
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work),
           "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "TMPDIR": str(work / "tmp")}
    (work / "tmp").mkdir(exist_ok=True)
    proc = subprocess.run(["bash", "-x", str(HOOK), "post"], input=json.dumps(payload),
                          capture_output=True, text=True, cwd=str(work), env=env)
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert "guard_standalone.py" not in proc.stderr, "the bundled engine ran on a post event"


def test_a_post_event_still_reaches_an_installed_cli(work, tmp_path):
    """That skip must not cost the recorder its input: recording what the agent DID is the whole
    reason the post hook exists, and it is what installing the CLI adds."""
    bin_dir = tmp_path / "recorder"
    _fake_pr(bin_dir, "99.0.0")
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
               "tool_input": {"command": "ls"}, "session_id": "shim", "cwd": str(work)}
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(work),
           "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "TMPDIR": str(work / "tmp")}
    (work / "tmp").mkdir(exist_ok=True)
    proc = subprocess.run(["bash", str(HOOK), "post"], input=json.dumps(payload),
                          capture_output=True, text=True, cwd=str(work), env=env)
    assert proc.returncode == 0
    assert "ANSWERED-BY-FAKE-CLI" in proc.stdout
