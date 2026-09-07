"""The shareable card, and the one property that makes it shareable.

A block is the only moment this product is visible, and until there was a card it left nothing
behind but a rule id in a terminal that scrolls away. The card exists so the story can be told
before the loss rather than after it.

Everything here is really one test asked several ways: the card must never carry an operand.
A path names a person's machine, a hostname names their infrastructure, and an argument is
where an API key lives. If any of those can reach the card then it is not something anyone can
paste without reading it first, and a thing you have to read before pasting does not get
pasted.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from provenrail import guard
from provenrail.easy import load_policy
from provenrail.shell import command_shape

STANDALONE = (Path(__file__).resolve().parent.parent / "plugins" / "provenrail-guard" /
              "scripts" / "guard_standalone.py")

# (command, the shape it must reduce to)
SHAPES = [
    ("git reset --hard origin/main", "git reset --hard"),
    ("git checkout -- .", "git checkout --"),
    ("git clean -fd", "git clean -fd"),
    ("git stash drop", "git stash drop"),
    ("rm -rf ~/Projects", "rm -rf"),
    ("rm -rf /Users/ana/Documents", "rm -rf"),
    ("npx prisma migrate reset --force", "npx prisma migrate reset --force"),
    ("supabase db reset", "supabase db reset"),
    ("docker compose down -v", "docker compose down -v"),
    ("terraform destroy", "terraform destroy"),
    ("chmod 777 /etc/passwd", "chmod 777"),
    ("dropdb myapp_production", "dropdb"),
    ("psql -c \"DROP TABLE users\"", "psql -c"),
    ("aws s3 rb s3://acme-prod-uploads --force", "aws s3 rb"),
    ("export OPENAI_API_KEY=sk-proj-aaaabbbbccccdddd", "export"),
    ("curl -H 'Authorization: token ghp_ccccccccccccccccccccc' https://api.github.com",
     "curl -H"),
    ("SCRATCH=/Users/ana/secret-client-work/tmp rm -rf $SCRATCH", "rm -rf"),
    ("/Volumes/T7/venv/bin/python -c 'print(1)'", "python -c"),
]


@pytest.mark.parametrize(("command", "expected"), SHAPES, ids=[c for c, _ in SHAPES])
def test_a_command_is_reduced_to_its_verb_and_flags(command, expected):
    assert command_shape(command) == expected


#: Anything that would identify a machine, a person, an employer or an account.
IDENTIFYING = re.compile(
    r"sk-[A-Za-z0-9]|sk-ant|ghp_|gho_|xox[baprs]-|AKIA|AIza|eyJ[A-Za-z0-9]"
    r"|BEGIN [A-Z ]*PRIVATE KEY"
    r"|/Users/|/home/|/Volumes/|C:\\\\"
    r"|[a-z0-9.-]+\.(com|net|org|io|dev|internal)\b"
    r"|s3://|postgres://|mysql://|https?://",
    re.IGNORECASE)


def test_no_shape_of_a_dangerous_command_carries_anything_identifying():
    """Every command the guard is likely to stop, run through the reducer. The list is the
    dangerous corpus precisely because those are the ones that reach a card."""
    from tests.test_predicates import DATA_INCIDENTS, GIT_INCIDENTS, UNRECOVERABLE

    for command in GIT_INCIDENTS + DATA_INCIDENTS + UNRECOVERABLE + [c for c, _ in SHAPES]:
        shape = command_shape(command)
        assert not IDENTIFYING.search(shape), f"{command!r} leaked through as {shape!r}"


def _run_hook(work: Path, command: str) -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}, "session_id": "s1", "cwd": str(work)}
    proc = subprocess.run([sys.executable, str(STANDALONE), "pre"], input=json.dumps(payload),
                          capture_output=True, text=True, cwd=str(work),
                          env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(work)})
    assert proc.returncode == 0, proc.stderr


def _card(work: Path) -> str:
    proc = subprocess.run([sys.executable, str(STANDALONE), "--card"], capture_output=True,
                          text=True, cwd=str(work),
                          env={"PATH": "/usr/bin:/bin", "HOME": str(work)})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture()
def armed_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=tmp_path, check=True)
    (tmp_path / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": list(guard.DEFAULT_PACKS)}}), encoding="utf-8")
    return tmp_path


def test_the_card_says_so_plainly_when_nothing_has_been_stopped(armed_repo):
    """A guard that has never fired and a guard that is silently broken read the same from
    outside, so the empty card must not read like a clean bill of health."""
    text = _card(armed_repo)
    assert "has not had to stop anything here yet" in text
    assert "stopped 0" not in text


def test_the_card_carries_nothing_identifying_end_to_end(armed_repo):
    """The whole point, driven through the real hook rather than asserted about the reducer."""
    for command in ("git reset --hard origin/main",
                    "rm -rf /Users/ana/Documents",
                    "export OPENAI_API_KEY=sk-proj-aaaabbbbccccddddeeee",
                    "curl -H 'Authorization: token ghp_ccccccccccccccccccccc' "
                    "https://api.acme-internal.com/v1",
                    "aws s3 rb s3://acme-prod-uploads --force"):
        _run_hook(armed_repo, command)

    text = _card(armed_repo)
    assert "Provenrail guard stopped 5 commands" in text
    assert "git reset --hard" in text
    assert "rm -rf" in text
    assert not IDENTIFYING.search(text), f"card leaked something identifying:\n{text}"
    # Not the project name either, only a hash of the directory.
    assert armed_repo.name not in text


def test_the_installed_engine_produces_the_same_kind_of_card(tmp_path, monkeypatch):
    """Two engines, one story. A card that only exists in the zero-install path would be a
    feature people lose by upgrading."""
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / ".provenrail-guard.jsonl"))
    policy = load_policy({"use": guard.DEFAULT_PACKS})
    decision = guard.decide(policy, "Bash",
                            {"command": "rm -rf /Volumes/BackupDisk"}, None, str(tmp_path))
    assert decision["verdict"] == "deny"
    assert decision["shape"] == "rm -rf"

    guard.journal({"at": 0, "event": "pre", "tool": "Bash", "session_id": "s1",
                   "verdict": decision["verdict"], "rule": decision["rule"],
                   "shape": decision["shape"], "reason": decision["reason"]})
    text = guard.card()
    assert "Provenrail guard stopped 1 command " in text
    assert "rm -rf" in text
    assert not IDENTIFYING.search(text), text


def test_an_allowed_call_gets_no_shape():
    """Computing one costs a regex pass per rule, and the overwhelming majority of calls are
    allowed. It is also the honest shape of the data: there is nothing to show."""
    policy = load_policy({"use": guard.DEFAULT_PACKS})
    decision = guard.decide(policy, "Bash", {"command": "ls -la"}, None, str(Path.cwd()))
    assert decision["verdict"] == "allow"
    assert decision["shape"] == ""


def test_the_journal_records_when_a_decision_happened(tmp_path, monkeypatch):
    """The card prints a date next to every entry, and an entry with no timestamp printed
    1970-01-01, which reads as a broken tool rather than a recent block."""
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / ".provenrail-guard.jsonl"))
    (tmp_path / ".provenrail.json").write_text(
        json.dumps({"policy": {"use": list(guard.DEFAULT_PACKS)}}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "rm -rf /Volumes/BackupDisk"},
               "session_id": "s1", "cwd": str(tmp_path)}
    guard.run_hook(json.dumps(payload))

    entries = [e for e in guard.read_journal() if e.get("verdict") == "deny"]
    assert entries, "a denied call was not journalled"
    assert entries[-1]["at"] > 1_700_000_000
    assert entries[-1]["shape"] == "rm -rf"
