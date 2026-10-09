"""The brief is only worth reading if every line of it is a fact the checkpoints recorded.

So these tests build a real git repository, drive real snapshots between real file changes, and
then compare the brief to the changes the test itself made. Nothing here reads the expected
answer back out of the module under test.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from provenrail import brief, checkpoint, guard, localstate, report

SESSION_A = "sessAAAA1111"
SESSION_B = "sessBBBB2222"
T0 = 1_760_000_000
STEP = 60


def git(repo: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True,
                          capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv(localstate.HOME_ENV, str(tmp_path / "state"))
    monkeypatch.setenv("PROVENRAIL_GUARD_JOURNAL", str(tmp_path / "journal.jsonl"))
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "app.py").write_text("print('one')\n")
    (root / "src" / "util.py").write_text("x = 1\n")
    (root / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n")
    (root / "tests" / "test_old.py").write_text("def test_old():\n    assert True\n")
    (root / "README.md").write_text("# proj\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    monkeypatch.chdir(root)
    return root


def snap(root: Path, session: str, tool: str, label: str, step: int, **kw) -> dict:
    return checkpoint.snapshot(root, session_id=session, host="claude-code", tool=tool,
                               label=label, now=T0 + step * STEP, **kw)


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


SHELL_COMMAND = "python gen.py --token hunter2-secret"


@pytest.fixture
def story(repo):
    """Two sessions of work. B is older and small; A is the latest and does the interesting things.

    The final working tree, against A's first checkpoint, differs by exactly:
      added    src/new.py, package-lock.json, migrations/0002_users.sql,
               .github/workflows/ci.yml, .mcp.json, docs/café.md
      modified src/app.py, tests/test_app.py
      deleted  tests/test_old.py
    src/tmp.py and src/util.py were changed and put back.
    """
    # Session B (older): one doc, written before A starts.
    snap(repo, SESSION_B, "Write", "docs/b.md", 0)
    write(repo, "docs/b.md", "from session b\n")
    snap(repo, SESSION_B, "Read", "src/app.py", 1)

    # Session A.
    snap(repo, SESSION_A, "Write", "src/new.py", 10)            # A#1 (the scope's start)
    write(repo, "src/new.py", "def new():\n    return 1\n")
    snap(repo, SESSION_A, "Edit", "src/app.py", 11)
    write(repo, "src/app.py", "print('two')\n")
    snap(repo, SESSION_A, "Write", "src/tmp.py", 12)
    write(repo, "src/tmp.py", "scratch = 1\n")
    snap(repo, SESSION_A, "Bash", "rm", 13)
    (repo / "src" / "tmp.py").unlink()
    snap(repo, SESSION_A, "Edit", "src/util.py", 14)
    write(repo, "src/util.py", "x = 2\n")
    snap(repo, SESSION_A, "Edit", "src/util.py", 15)
    write(repo, "src/util.py", "x = 1\n")                         # put back exactly
    shape = checkpoint.label_for("Bash", {"command": SHELL_COMMAND})
    snap(repo, SESSION_A, "Bash", shape, 16)
    write(repo, "package-lock.json", "{}\n")
    write(repo, "migrations/0002_users.sql", "alter table users add column x int;\n")
    snap(repo, SESSION_A, "Bash", "git rm", 17)
    (repo / "tests" / "test_old.py").unlink()
    snap(repo, SESSION_A, "Edit", "tests/test_app.py", 18)
    write(repo, "tests/test_app.py", "def test_app():\n    assert 1 == 1\n")
    snap(repo, SESSION_A, "Write", ".github/workflows/ci.yml", 19)
    write(repo, ".github/workflows/ci.yml", "on: push\n")
    snap(repo, SESSION_A, "Write", ".mcp.json", 20)
    write(repo, ".mcp.json", "{}\n")
    snap(repo, SESSION_A, "Write", "docs/café.md", 21)
    write(repo, "docs/café.md", "x\n")
    snap(repo, SESSION_A, checkpoint.UNDO_TOOL, "pr undo 3", 22, undo_to=3)

    guard.journal({"at": T0 + 15 * STEP, "event": "pre", "tool": "Bash", "session_id": SESSION_A,
                   "host": "claude-code", "verdict": "deny", "rule": "destructive.git-reset",
                   "shape": "git reset --hard", "reason": "x"})
    guard.journal({"at": T0 + 16 * STEP, "event": "pre", "tool": "Bash", "session_id": SESSION_A,
                   "host": "claude-code", "verdict": "ask", "rule": "cloud.deploy",
                   "shape": "wrangler deploy", "reason": "x", "remote": "approve"})
    guard.journal({"at": T0 + 17 * STEP, "event": "pre", "tool": "Bash", "session_id": SESSION_A,
                   "host": "claude-code", "verdict": "deny", "rule": "supervisor.loop",
                   "shape": "pytest -q", "reason": "x"})
    guard.journal({"at": T0 + 18 * STEP, "event": "pre", "tool": "Bash", "session_id": SESSION_A,
                   "host": "claude-code", "verdict": "allow", "rule": "fine.rule",
                   "shape": "allowed-shape", "reason": "x", "warning": "w"})
    guard.journal({"at": T0 + 1 * STEP, "event": "pre", "tool": "Bash", "session_id": SESSION_B,
                   "host": "claude-code", "verdict": "deny", "rule": "other.session",
                   "shape": "b-only-shape", "reason": "x"})
    return repo


def paths(data: dict, status: str) -> set[str]:
    return {i["path"] for i in data["net"] if i["status"] == status}


def test_net_change_matches_what_the_test_did(story):
    data = brief.build(story)
    assert paths(data, "A") == {"src/new.py", "package-lock.json", "migrations/0002_users.sql",
                                ".github/workflows/ci.yml", ".mcp.json", "docs/café.md"}
    assert paths(data, "M") == {"src/app.py", "tests/test_app.py"}
    assert paths(data, "D") == {"tests/test_old.py"}
    assert data["counts"] == {"added": 6, "modified": 2, "deleted": 1}


def test_default_scope_is_the_latest_session(story):
    data = brief.build(story)
    assert data["scope"]["sessions"] == [SESSION_A]
    assert "docs/b.md" not in {i["path"] for i in data["net"]}
    # Twelve snapshots of real actions (steps 10 to 21); the undo's safety snapshot is not one.
    assert data["actions"] == 12


def test_touched_and_reverted(story):
    data = brief.build(story)
    assert data["reverted"] == ["src/tmp.py", "src/util.py"]
    md = brief.render(data)
    section = md.split("### Touched and reverted")[1].split("## Needs a careful look")[0]
    assert "`src/tmp.py`" in section and "`src/util.py`" in section
    assert "src/app.py" not in section


def test_sensitive_categories(story):
    data = brief.build(story)
    flagged = {c["category"]: {i["path"] for i in c["paths"]}
               for c in data["flags"]["categories"]}
    assert "package-lock.json" in flagged["Dependency manifests and lockfiles"]
    assert "migrations/0002_users.sql" in flagged["Database migrations and schema"]
    assert ".github/workflows/ci.yml" in flagged["CI and deploy configuration"]
    assert ".mcp.json" in flagged["Agent and editor configuration"]
    assert ".github/workflows/ci.yml" in flagged["Agent and editor configuration"]
    # Ordinary source is never flagged.
    every = set().union(*flagged.values())
    assert "src/new.py" not in every and "src/app.py" not in every
    for entry in data["flags"]["categories"]:
        assert entry["reason"]


def test_test_file_flags_are_facts_to_check(story):
    data = brief.build(story)
    assert data["flags"]["deleted_tests"] == ["tests/test_old.py"]
    assert data["flags"]["edited_tests_with_source"] == ["tests/test_app.py"]
    md = brief.render(data)
    assert "Test files deleted" in md
    assert "Test files modified in the same change as non-test files" in md


def test_modified_test_alone_is_not_flagged(repo):
    snap(repo, SESSION_A, "Edit", "tests/test_app.py", 1)
    write(repo, "tests/test_app.py", "def test_app():\n    assert 2 == 2\n")
    data = brief.build(repo)
    assert data["flags"]["edited_tests_with_source"] == []
    assert data["flags"]["deleted_tests"] == []


def test_shell_command_listed_with_counts_and_no_operands(story):
    data = brief.build(story)
    by_shape = {c["shape"]: c for c in data["commands"]}
    generated = [c for c in data["commands"] if c["files"] == 2]
    assert len(generated) == 1
    assert generated[0]["added"] == 2 and generated[0]["modified"] == 0
    assert by_shape["git rm"]["deleted"] == 1 and by_shape["git rm"]["files"] == 1
    assert by_shape["rm"]["deleted"] == 1  # src/tmp.py, which was created one action earlier
    # An Edit or Write is not a shell command, however much it changed.
    assert all(c["shape"] not in ("src/app.py", "src/new.py") for c in data["commands"])
    md = brief.render(data)
    assert "hunter2-secret" not in md
    assert "hunter2-secret" not in json.dumps(data)
    section = md.split("## Shell commands that changed files")[1].split("## Stopped")[0]
    assert "`git rm`: 1 file (0 added, 0 modified, 1 deleted)" in section


def test_stopped_and_questioned(story):
    data = brief.build(story)
    got = {(j["verdict"], j["rule"], j["shape"], j["remote"]) for j in data["journal"]}
    assert got == {("deny", "destructive.git-reset", "git reset --hard", ""),
                   ("ask", "cloud.deploy", "wrangler deploy", "approve"),
                   ("deny", "supervisor.loop", "pytest -q", "")}
    md = brief.render(data)
    assert "approved from the phone" in md
    assert "b-only-shape" not in md and "allowed-shape" not in md
    assert "undo performed back to checkpoint #3" in md
    assert data["undos"][0]["to"] == 3


def test_ask_without_a_phone_answer_says_so(repo):
    snap(repo, SESSION_A, "Write", "a.txt", 1)
    write(repo, "a.txt", "x\n")
    guard.journal({"at": T0, "event": "pre", "tool": "Bash", "session_id": SESSION_A,
                   "verdict": "ask", "rule": "cloud.deploy", "shape": "wrangler deploy"})
    md = brief.render(brief.build(repo))
    assert "no phone answer recorded" in md


def test_session_prefix_scoping(story):
    data = brief.build(story, session="sessBBBB")
    assert data["scope"]["sessions"] == [SESSION_B]
    assert data["actions"] == 2
    assert "docs/b.md" in {i["path"] for i in data["net"]}
    assert [j["shape"] for j in data["journal"]] == ["b-only-shape"]
    assert data["commands"] == []


def test_unknown_session_is_empty(story):
    data = brief.build(story, session="nope")
    assert data["empty"] is True and "nope" in data["reason"]


def test_since_starts_at_a_checkpoint_number(story):
    log = checkpoint.read_log(story)
    start = next(e["n"] for e in log if e["label"] == "package-lock.json" or e["label"] ==
                 checkpoint.label_for("Bash", {"command": SHELL_COMMAND}))
    data = brief.build(story, since=start)
    added = paths(data, "A")
    assert "package-lock.json" in added and "src/new.py" not in added
    assert paths(data, "M") == {"tests/test_app.py"}
    assert data["scope"]["first_checkpoint"] == start
    # Journal lines older than the first checkpoint in scope are not this brief's business.
    assert all(j["at"] >= log[start - 1]["at"] for j in data["journal"])


def test_all_sessions(story):
    data = brief.build(story, all_sessions=True)
    assert data["scope"]["sessions"] == sorted([SESSION_A, SESSION_B])
    assert "docs/b.md" in paths(data, "A") and "src/new.py" in paths(data, "A")
    assert {j["shape"] for j in data["journal"]} >= {"b-only-shape", "git reset --hard"}


def test_header_and_time(story):
    data = brief.build(story)
    md = brief.render(data)
    first = time.strftime("%Y-%m-%d %H:%M", time.localtime(T0 + 10 * STEP))
    last = time.strftime("%Y-%m-%d %H:%M", time.localtime(T0 + 22 * STEP))
    assert "claude-code" in md and "sessAAAA" in md and "sessAAAA1111" not in md
    assert f"{first} to {last} (12 min)" in md
    assert "12 actions that could write" in md


def test_markdown_is_plain_ascii(story):
    md = brief.render(brief.build(story, all_sessions=True))
    assert md.isascii()
    assert "—" not in md and "–" not in md
    assert "caf\\xe9.md" in md  # the non-ASCII name is shown escaped, not dropped


def test_not_covered_is_fixed_and_lists_skipped_large(repo):
    snap(repo, SESSION_A, "Write", "a.txt", 1)
    write(repo, "a.txt", "x\n")
    plain = brief.render(brief.build(repo))
    section = plain.split("## Not covered")[1]
    for needle in ("git ignores", "outside this repository", "Whether the tests pass"):
        assert needle in section
    assert "Skipped as too large" not in section
    log = repo.parent / "state"
    big = checkpoint.read_log(repo)[-1]
    big["skipped_large"] = ["huge.bin"]
    # Rewrite the log entry the way the checkpoint store would have recorded a skipped file.
    path = localstate.project_dir(repo, create=False) / checkpoint.LOG_FILENAME
    path.write_text(json.dumps(big) + "\n")
    assert log.exists()
    assert "Skipped as too large in this scope: `huge.bin`" in brief.render(brief.build(repo))


def test_cap_names_how_many_were_left_out(repo, monkeypatch):
    monkeypatch.setattr(brief, "MAX_PATHS_LISTED", 3)
    snap(repo, SESSION_A, "Bash", "make", 1)
    for i in range(7):
        write(repo, f"gen/f{i}.txt", "x\n")
    data = brief.build(repo)
    md = brief.render(data)
    assert len(data["net"]) == 7  # the data is never capped
    assert md.count("  - A `gen/") == 3
    assert "4 more paths not listed" in md


def test_cost_comes_from_the_transcript_and_is_unknown_without_one(story, tmp_path, monkeypatch):
    monkeypatch.setattr(report, "DEFAULT_ROOT", tmp_path / "claude-projects")
    assert "cost" not in brief.build(story)
    assert "Cost:" not in brief.render(brief.build(story))
    folder = tmp_path / "claude-projects" / "-some-project"
    folder.mkdir(parents=True)
    line = {"type": "assistant", "message": {"model": "claude-sonnet-4-5", "usage": {
        "input_tokens": 1_000_000, "output_tokens": 100_000}}}
    transcript_file = folder / f"{SESSION_A}.jsonl"
    transcript_file.write_text(json.dumps(line) + "\n")
    data = brief.build(story)
    assert data["cost"]["usd"] > 0
    assert "Cost:" in brief.render(data)
    # A scope that is not one whole session must not borrow the session's total.
    assert "cost" not in brief.build(story, since=1)
    # A transcript that cannot be fully read is unknown, never zero.
    transcript_file.write_text("{not json}\n" + json.dumps(line) + "\n")
    assert "cost" not in brief.build(story)


def parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    brief.add_arguments(parser)
    return parser.parse_args(argv)


def test_run_markdown_json_and_out(story, tmp_path):
    buf = io.StringIO()
    assert brief.run(parse([]), out=buf) == 0
    assert buf.getvalue().startswith("# Agent review brief")

    buf = io.StringIO()
    assert brief.run(parse(["--json"]), out=buf) == 0
    parsed = json.loads(buf.getvalue())
    assert parsed["counts"]["deleted"] == 1 and parsed["schema"] == brief.SCHEMA

    target = tmp_path / "brief.md"
    buf = io.StringIO()
    assert brief.run(parse(["--out", str(target)]), out=buf) == 0
    assert target.read_text().startswith("# Agent review brief")
    assert str(target) in buf.getvalue() and "Agent review brief" not in buf.getvalue()

    buf = io.StringIO()
    assert brief.run(parse(["--session", "sessBBBB", "--since", "1"]), out=buf) == 0
    assert "sessBBBB" in buf.getvalue()


def test_no_checkpoints_exits_1_and_says_how_to_get_them(repo):
    buf = io.StringIO()
    assert brief.run(parse([]), out=buf) == 1
    text = buf.getvalue()
    assert "pr guard install" in text and text.count("\n") == 1


def test_not_a_git_repository_exits_2(tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    assert brief.run(parse([]), out=io.StringIO()) == 2
    assert "git repository" in capsys.readouterr().err


@pytest.mark.parametrize("path,category", [
    ("yarn.lock", "Dependency manifests and lockfiles"),
    ("services/api/package.json", "Dependency manifests and lockfiles"),
    ("db/migrations/001_init.py", "Database migrations and schema"),
    ("src/auth/token.py", "Authentication, sessions and permissions"),
    ("infra/main.tf", "Infrastructure"),
    ("deploy/Dockerfile", "Infrastructure"),
    (".env.production", "Secrets and environment files"),
    ("LICENSE", "Licence files"),
    ("CLAUDE.md", "Agent and editor configuration"),
    (".cursor/rules/a.mdc", "Agent and editor configuration"),
])
def test_category_table(path, category):
    assert category in brief.sensitive_categories(path)


@pytest.mark.parametrize("path", ["src/app.py", "README.md", "docs/author-notes.md"])
def test_ordinary_paths_are_not_flagged(path):
    assert brief.sensitive_categories(path) == []
