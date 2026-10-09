"""Undo has one job, and it is only ever tested at the moment it matters.

So every claim the docs make about it is driven here against a real git repository on disk:
what comes back, what is removed, what is deliberately not covered, and above all that the
user's own repository is never touched by the thing that is supposed to protect it.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from provenrail import checkpoint, localstate

ROOT = Path(__file__).resolve().parent.parent


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
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('one')\n")
    (root / "src" / "util.py").write_text("x = 1\n")
    (root / "README.md").write_text("# proj\n")
    (root / ".gitignore").write_text("build/\n.env\n.env.*\n")
    (root / ".env").write_text("SECRET=1\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    monkeypatch.chdir(root)
    return root


def tree_digest(root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts or not path.is_file():
            continue
        out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def real_repo_fingerprint(root: Path) -> tuple:
    index = (root / ".git" / "index").read_bytes()
    refs = git(root, "for-each-ref")
    return (hashlib.sha256(index).hexdigest(), refs, git(root, "stash", "list"),
            (root / ".git" / "HEAD").read_text())


# ---------------------------------------------------------------- what gets a snapshot


@pytest.mark.parametrize("tool,tool_input,expected", [
    ("Read", {"file_path": "a"}, False),
    ("Grep", {"pattern": "x"}, False),
    ("Edit", {"file_path": "a"}, True),
    ("Write", {"file_path": "a"}, True),
    ("mcp__anything__do", {}, True),
    ("SomeToolNobodyHasHeardOf", {}, True),
    ("Bash", {"command": "ls -la"}, False),
    ("Bash", {"command": "git status && git diff"}, False),
    ("Bash", {"command": "cat a | grep b | wc -l"}, False),
    ("Bash", {"command": "rm -rf src"}, True),
    ("Bash", {"command": "git checkout ."}, True),
    ("Bash", {"command": "git"}, True),
    ("Bash", {"command": "ls > out.txt"}, True),
    ("Bash", {"command": "echo $(rm -rf src)"}, True),
    ("Bash", {"command": "cat `rm x`"}, True),
    ("Bash", {"command": "find . -delete"}, True),
    ("Bash", {"command": "sed -i s/a/b/ f"}, True),
    ("Bash", {"command": "ls; rm x"}, True),
    ("Bash", {"command": ""}, True),
    ("Bash", "not a dict", True),
    ("Bash", {"command": 7}, True),
])
def test_only_provably_read_only_calls_are_skipped(tool, tool_input, expected):
    assert checkpoint.needs_snapshot(tool, tool_input) is expected


def test_a_label_never_carries_an_operand(repo):
    label = checkpoint.label_for("Bash", {"command": "curl -H 'Authorization: sk-live-abc' x"})
    assert "sk-live-abc" not in label and label.startswith("curl")
    inside = checkpoint.label_for("Edit", {"file_path": str(repo / "src" / "app.py")}, repo)
    assert inside == os.path.join("src", "app.py")


# ---------------------------------------------------------------- the round trip


def test_a_shell_delete_comes_back_byte_for_byte(repo):
    (repo / "src" / "wip.py").write_text("uncommitted work\n")      # never committed, never staged
    before = tree_digest(repo)
    entry = checkpoint.snapshot(repo, session_id="s1", tool="Bash", label="rm -rf")
    subprocess.run(["rm", "-rf", "src", ".env"], cwd=repo, check=True)
    assert not (repo / "src").exists()

    result = checkpoint.restore(repo, entry["n"])

    assert tree_digest(repo) == before
    assert result["verified"] is True
    assert sorted(result["restored"]) == [".env", "src/app.py", "src/util.py", "src/wip.py"]
    assert result["deleted"] == [] and result["errors"] == []


def test_files_the_action_created_are_removed(repo):
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "gen" / "deep").mkdir(parents=True)
    (repo / "gen" / "deep" / "out.txt").write_text("generated\n")
    (repo / "src" / "app.py").write_text("print('two')\n")

    result = checkpoint.restore(repo, entry["n"])

    assert result["deleted"] == ["gen/deep/out.txt"]
    assert not (repo / "gen").exists()                # the emptied directories go with it
    assert (repo / "src" / "app.py").read_text() == "print('one')\n"
    assert result["verified"] is True


def test_ignored_files_are_left_alone_and_said_to_be(repo):
    (repo / "build").mkdir()
    (repo / "build" / "big.o").write_text("object\n")
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "build" / "big.o").write_text("rebuilt\n")
    (repo / "build" / "new.o").write_text("new\n")

    result = checkpoint.restore(repo, entry["n"])

    assert result["restored"] == [] and result["deleted"] == []
    assert (repo / "build" / "big.o").read_text() == "rebuilt\n"
    assert (repo / "build" / "new.o").exists()
    assert "gitignore" in checkpoint.__doc__


def test_an_undo_is_itself_undoable(repo):
    entry = checkpoint.snapshot(repo, tool="Edit")
    (repo / "src" / "app.py").write_text("print('agent version')\n")
    result = checkpoint.restore(repo, entry["n"])
    assert (repo / "src" / "app.py").read_text() == "print('one')\n"

    again = checkpoint.restore(repo, result["safety"])

    assert (repo / "src" / "app.py").read_text() == "print('agent version')\n"
    assert again["verified"] is True


def test_restore_can_be_limited_to_one_path(repo):
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "app.py").write_text("changed\n")
    (repo / "src" / "util.py").write_text("changed too\n")

    result = checkpoint.restore(repo, entry["n"], paths=["src/app.py"])

    assert result["restored"] == ["src/app.py"]
    assert (repo / "src" / "app.py").read_text() == "print('one')\n"
    assert (repo / "src" / "util.py").read_text() == "changed too\n"
    assert result["verified"] is None            # a partial restore makes no whole-tree claim


def test_a_dry_run_changes_nothing(repo):
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "app.py").unlink()
    result = checkpoint.restore(repo, entry["n"], dry_run=True)
    assert result["restored"] == ["src/app.py"] and result["dry_run"] is True
    assert not (repo / "src" / "app.py").exists()


def test_a_file_that_became_a_directory_is_put_back(repo):
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "README.md").unlink()
    (repo / "README.md").mkdir()
    (repo / "README.md" / "inner.txt").write_text("x\n")

    result = checkpoint.restore(repo, entry["n"])

    assert (repo / "README.md").read_text() == "# proj\n"
    assert result["verified"] is True


# ---------------------------------------------------------------- the user's repository


def test_the_real_repository_is_never_touched(repo):
    (repo / "src" / "app.py").write_text("dirty\n")
    before = real_repo_fingerprint(repo)
    status_before = git(repo, "status", "--porcelain")

    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "util.py").unlink()
    checkpoint.restore(repo, entry["n"])

    assert real_repo_fingerprint(repo) == before
    assert git(repo, "status", "--porcelain") == status_before
    assert not list(repo.glob(".provenrail*"))       # and nothing is written into the tree


def test_a_stray_git_environment_cannot_redirect_it(repo, monkeypatch):
    before = real_repo_fingerprint(repo)
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(repo / ".git" / "index"))
    monkeypatch.setenv("GIT_WORK_TREE", str(repo))
    (repo / "new.txt").write_text("untracked\n")

    checkpoint.snapshot(repo, tool="Bash")

    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_INDEX_FILE")
    monkeypatch.delenv("GIT_WORK_TREE")
    assert real_repo_fingerprint(repo) == before
    assert "?? new.txt" in git(repo, "status", "--porcelain")


def test_a_delete_is_refused_when_its_directory_now_points_outside(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.txt").write_text("not ours\n")
    first = checkpoint.snapshot(repo, tool="Bash")
    (repo / "link").mkdir()
    (repo / "link" / "victim.txt").write_text("ours\n")
    checkpoint.snapshot(repo, tool="Bash")           # the tree now holds link/victim.txt
    # Swap the directory for a symlink to somewhere this tool was never pointed at.
    (repo / "link" / "victim.txt").unlink()
    (repo / "link").rmdir()
    (repo / "link").symlink_to(outside, target_is_directory=True)
    # Make the safety snapshot believe link/victim.txt is still a tracked file to delete.
    pdir = localstate.project_dir(repo)
    assert checkpoint._inside(repo.resolve(), "link/victim.txt") is None
    assert checkpoint._inside(repo.resolve(), "src/app.py") == repo.resolve() / "src" / "app.py"

    checkpoint.restore(repo, first["n"])

    assert (outside / "victim.txt").read_text() == "not ours\n"
    assert pdir.is_dir()


@pytest.mark.parametrize("where", ["home", "plain"])
def test_it_refuses_to_snapshot_what_is_not_a_project(tmp_path, monkeypatch, where):
    monkeypatch.setenv(localstate.HOME_ENV, str(tmp_path / "state"))
    target = tmp_path / "somewhere"
    target.mkdir()
    if where == "home":
        (target / ".git").mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: target))
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.snapshot(target, tool="Bash")
    assert not (tmp_path / "state" / "projects").exists() or not any(
        (tmp_path / "state" / "projects").rglob(checkpoint.LOG_FILENAME))


# ---------------------------------------------------------------- bounds


def test_an_unchanged_tree_adds_a_log_line_but_no_new_object(repo):
    a = checkpoint.snapshot(repo, tool="Bash", label="one")
    b = checkpoint.snapshot(repo, tool="Bash", label="two")
    (repo / "README.md").write_text("# changed\n")
    c = checkpoint.snapshot(repo, tool="Bash", label="three")
    assert (a["tree"], a["ref"]) == (b["tree"], b["ref"])
    assert c["tree"] != b["tree"] and c["ref"] == c["n"]
    assert [e["n"] for e in checkpoint.read_log(repo)] == [1, 2, 3]


def test_an_oversized_file_is_skipped_and_named(repo, monkeypatch):
    monkeypatch.setattr(checkpoint, "MAX_FILE_BYTES", 100)     # every fixture file is smaller
    (repo / "dump.bin").write_bytes(b"x" * 500)
    entry = checkpoint.snapshot(repo, tool="Bash")
    assert entry["skipped_large"] == ["dump.bin"]
    (repo / "dump.bin").unlink()
    result = checkpoint.restore(repo, entry["n"])
    assert "dump.bin" not in result["restored"]


def test_running_out_of_time_pauses_loudly_and_init_resumes(repo, monkeypatch):
    real = checkpoint._write_tree

    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", 10)

    monkeypatch.setattr(checkpoint, "_write_tree", slow)
    with pytest.raises(checkpoint.CheckpointPaused) as first:
        checkpoint.snapshot(repo, tool="Bash")
    assert "pr undo init" in str(first.value)
    monkeypatch.setattr(checkpoint, "_write_tree", real)
    with pytest.raises(checkpoint.CheckpointPaused):
        checkpoint.snapshot(repo, tool="Bash")       # stays paused, and cheap, until resumed
    assert "pr undo init" in checkpoint.render_list(repo, 5)

    entry = checkpoint.snapshot(repo, tool="init", force=True, budget_s=None)

    assert entry["n"] == 1 and checkpoint.paused_reason(repo) == ""
    assert checkpoint.snapshot(repo, tool="Bash")["n"] == 2


def test_old_checkpoints_are_pruned_with_their_refs(repo):
    day = 24 * 3600
    old = checkpoint.snapshot(repo, tool="Bash", now=1_000_000)
    (repo / "README.md").write_text("# later\n")
    recent = checkpoint.snapshot(repo, tool="Bash",
                                 now=1_000_000 + (checkpoint.KEEP_DAYS + 2) * day)
    kept = [e["n"] for e in checkpoint.read_log(repo)]
    assert kept == [recent["n"]]
    shadow = localstate.project_dir(repo) / checkpoint.SHADOW_DIRNAME
    refs = subprocess.run(["git", "for-each-ref", "--format=%(refname)"], cwd=repo,
                          env=checkpoint._env(shadow, repo.resolve()), capture_output=True,
                          text=True, check=True).stdout.split()
    assert refs == [f"{checkpoint.REF_PREFIX}{recent['n']}"]
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.find(repo, old["n"])


# ---------------------------------------------------------------- command line


def run_cli(*argv: str) -> tuple[int, str]:
    parser = argparse.ArgumentParser()
    checkpoint.add_arguments(parser)
    out = io.StringIO()
    code = checkpoint.run(parser.parse_args(list(argv)), out=out)
    return code, out.getvalue()


def test_the_list_says_what_each_action_did(repo):
    checkpoint.snapshot(repo, session_id="abcdef123", tool="Bash", label="rm -rf")
    (repo / "src" / "util.py").unlink()
    checkpoint.snapshot(repo, session_id="abcdef123", tool="Edit", label="src/app.py")
    (repo / "src" / "app.py").write_text("edited\n")
    (repo / "added.txt").write_text("new\n")

    code, text = run_cli()

    assert code == 0
    first, second = [line for line in text.splitlines() if line.lstrip().startswith("#")]
    assert "Bash rm -rf" in first and "1 file (-1)" in first
    assert "Edit src/app.py" in second and "2 files (+1 ~1)" in second


def test_undo_last_and_diff_from_the_command_line(repo):
    checkpoint.snapshot(repo, tool="Bash", label="rm")
    (repo / "src" / "app.py").unlink()

    code, text = run_cli("last", "--diff")
    assert code == 0 and "Would restore" in text and not (repo / "src" / "app.py").exists()

    code, text = run_cli("last")
    assert code == 0 and "Verified" in text and (repo / "src" / "app.py").exists()
    assert "Changed your mind? `pr undo" in text

    code, text = run_cli("999")
    assert code == 1


def test_last_means_the_last_action_that_changed_something(repo):
    damage = checkpoint.snapshot(repo, tool="Bash", label="rm")
    (repo / "src" / "app.py").unlink()
    checkpoint.snapshot(repo, tool="Bash", label="npm test")      # wrote nothing
    checkpoint.snapshot(repo, tool="Bash", label="npm test")

    assert checkpoint.last_change(repo) == damage["n"]
    code, text = run_cli("last")
    assert code == 0 and (repo / "src" / "app.py").exists()

    # A second "undo last" must go further back or stop. It must never step forward into the
    # state the first one just escaped.
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.last_change(repo)


def test_repeated_undo_last_walks_backwards_and_a_redo_is_respected(repo):
    one = checkpoint.snapshot(repo, tool="Edit", label="first")
    (repo / "src" / "app.py").write_text("v2\n")
    two = checkpoint.snapshot(repo, tool="Edit", label="second")
    (repo / "src" / "app.py").write_text("v3\n")

    assert checkpoint.last_change(repo) == two["n"]
    undone = checkpoint.restore(repo, two["n"])
    assert (repo / "src" / "app.py").read_text() == "v2\n"
    assert checkpoint.last_change(repo) == one["n"]

    checkpoint.restore(repo, undone["safety"])        # redo: back to v3
    assert (repo / "src" / "app.py").read_text() == "v3\n"
    assert checkpoint.last_change(repo) == two["n"]

    (repo / "src" / "app.py").write_text("v4\n")     # new work after the redo
    three = checkpoint.snapshot(repo, tool="Edit", label="third")
    (repo / "src" / "app.py").write_text("v5\n")
    assert checkpoint.last_change(repo) == three["n"]


def test_looking_leaves_no_mark(repo):
    checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "app.py").unlink()
    before = checkpoint.read_log(repo)
    run_cli("last", "--diff")
    run_cli()
    assert checkpoint.read_log(repo) == before


def test_outside_a_repository_it_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv(localstate.HOME_ENV, str(tmp_path / "state"))
    monkeypatch.chdir(tmp_path)
    code, _ = run_cli()
    assert code == 2


@pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="no system python3")
def test_it_imports_as_a_top_level_module_on_the_system_python():
    # The plugin runs it vendored, beside its siblings, under whatever python3 exists.
    code = (f"import sys; sys.path.insert(0, {str(ROOT / 'src' / 'provenrail')!r}); "
            "import checkpoint, localstate; "
            "print(checkpoint.needs_snapshot('Bash', {'command': 'rm x'}))")
    done = subprocess.run(["/usr/bin/python3", "-I", "-c", code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True"
    assert sys.version_info >= (3, 9)
