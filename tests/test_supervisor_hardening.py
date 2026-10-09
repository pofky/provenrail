"""Every defect an adversarial review found in the supervisor, held shut.

Each test here is a reproduction that worked against the first version of 0.6.0. They are
kept apart from the feature tests on purpose: these are not descriptions of what the product
does, they are the specific ways it was wrong, and the list should only ever grow.
"""
# ruff: noqa: F811 - a fixture imported by name is "redefined" by every test that uses it

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from test_supervisor import (  # noqa: F401 - `repo` and `phone` are fixtures
    ASKS,
    ENGINES,
    FakeTelegram,
    decision_of,
    git,
    installed,
    payload,
    phone,
    repo,
    standalone,
)

from provenrail import checkpoint, guard, localstate, remote, supervise, watch

DELETE_EVERYTHING = "rm" + " -rf /"


# ---------------------------------------------------------------- restore must not destroy


def test_a_restore_never_touches_a_nested_repository(repo):
    """A snapshot holds only a pointer to a nested repository's commit. Restoring an older
    pointer used to mean deleting the whole nested repository, unpushed commits included."""
    sub = repo / "vendor" / "lib"
    sub.mkdir(parents=True)
    git(sub, "init", "-q")
    (sub / "a.txt").write_text("one\n")
    git(sub, "add", "-A")
    git(sub, "commit", "-qm", "first")
    before = checkpoint.snapshot(repo, tool="Bash")
    (sub / "a.txt").write_text("two\n")
    git(sub, "commit", "-qam", "second, never pushed")
    head = git(sub, "rev-parse", "HEAD")

    result = checkpoint.restore(repo, before["n"])

    assert (sub / ".git").is_dir()
    assert git(sub, "rev-parse", "HEAD") == head
    assert (sub / "a.txt").read_text() == "two\n"
    assert result["refused"] == ["vendor/lib"]
    assert result["verified"] is False            # it does not claim a match it did not make


def test_a_restore_never_empties_a_directory_of_files_no_checkpoint_holds(repo):
    (repo / ".gitignore").write_text("*.o\n")
    (repo / "thing").write_text("a tracked file\n")
    before = checkpoint.snapshot(repo, tool="Bash")
    (repo / "thing").unlink()
    (repo / "thing").mkdir()
    (repo / "thing" / "build.o").write_text("ignored, so in no checkpoint\n")

    result = checkpoint.restore(repo, before["n"])

    assert (repo / "thing" / "build.o").read_text() == "ignored, so in no checkpoint\n"
    assert "thing" in result["refused"] and result["verified"] is False
    assert any("in no checkpoint" in line for line in result["errors"])


def test_a_safety_snapshot_of_a_tree_the_agent_emptied_is_allowed(repo):
    before = checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "app.py").unlink()
    (repo / "src").rmdir()                        # the working tree now holds nothing at all
    result = checkpoint.restore(repo, before["n"])
    assert result["verified"] is True and (repo / "src" / "app.py").exists()


# ---------------------------------------------------------------- the repository is hostile


def test_the_repository_cannot_break_snapshots_with_its_own_attributes(repo):
    (repo / ".gitattributes").write_text("* working-tree-encoding=bogus filter=evil\n")
    entry = checkpoint.snapshot(repo, tool="Bash")
    (repo / "src" / "app.py").unlink()
    assert checkpoint.restore(repo, entry["n"])["verified"] is True
    assert (repo / "src" / "app.py").read_text() == "print('one')\n"


def test_a_repository_that_ignores_everything_is_reported_not_recorded(repo):
    (repo / ".gitignore").write_text("*\n")
    with pytest.raises(checkpoint.CheckpointError) as failure:
        checkpoint.snapshot(repo, tool="Bash")
    assert "empty" in str(failure.value)
    assert checkpoint.read_log(repo) == []
    # And the gap is visible where someone reaching for undo will look, not once a day.
    assert "NOT being taken" in checkpoint.render_list(repo, 5) or \
        "paused" in checkpoint.render_list(repo, 5)

    (repo / ".gitignore").write_text("build/\n")
    checkpoint.snapshot(repo, tool="Bash")
    assert checkpoint.last_error(repo) == ""      # a later success clears the warning


@pytest.mark.parametrize("command", [
    "git diff --output=src/app.py",
    "git log -o out.txt",
    "git show --ext-diff HEAD",
    "git diff --textconv",
    "rg --pre ./run.sh pattern .",
    "tree -o listing.txt",
    "grep -r x . --output-file=y",
    "file src/app.py",
])
def test_a_reader_that_can_write_or_launch_gets_a_snapshot(command):
    assert checkpoint.needs_snapshot("Bash", {"command": command}) is True


def test_the_background_poller_never_runs_from_the_repository(repo, monkeypatch):
    """`python -m` puts the working directory first on its import path. Spawned from the hook
    it ran inside the repository, so a `provenrail/__init__.py` planted there was executed."""
    (repo / "provenrail").mkdir()
    (repo / "provenrail" / "__init__.py").write_text("raise SystemExit('planted code ran')\n")
    seen = {}

    def fake_popen(command, **kwargs):
        seen.update(kwargs, command=command)

    monkeypatch.setattr(remote.subprocess, "Popen", fake_popen)
    assert remote.poll_in_background() is True
    assert Path(seen["cwd"]).resolve() == localstate.home().resolve()
    assert Path(seen["cwd"]).resolve() != repo.resolve()


# ---------------------------------------------------------------- the stop switch is first


@ENGINES
@pytest.mark.parametrize("broken", ['{"policy": ', '{"policy": {"rules": "x"}}', "not json"])
def test_a_broken_config_is_not_a_way_past_a_stop_order(repo, engine, broken):
    watch.halt(by="pr stop")
    (repo / ".provenrail.json").write_text(broken)
    verdict, reason = engine("Bash", {"command": "ls"}, repo)
    assert verdict == "deny" and supervise.RULE_STOPPED in reason


def test_an_unparseable_payload_is_not_a_way_past_a_stop_order(repo):
    watch.halt(by="pr stop")
    code, out, _ = guard.run_hook("{ this is not json")
    assert decision_of(out)[0] == "deny"
    done = subprocess.run(
        [sys.executable, str(Path(guard.__file__).resolve().parents[2] / "plugins" /
                             "provenrail-guard" / "scripts" / "guard_standalone.py")],
        input="{ this is not json", capture_output=True, text=True, cwd=str(repo),
        env={"PATH": os.environ["PATH"], "HOME": str(repo.parent),
             "PROVENRAIL_HOME": os.environ["PROVENRAIL_HOME"]})
    assert decision_of(done.stdout)[0] == "deny"


# ---------------------------------------------------------------- repo config only tightens


def test_the_repository_cannot_make_the_remote_send_more_or_ask_less(repo, phone):
    cfg = remote.load()
    cfg["detail"] = "shape"                       # the user's own privacy choice
    remote.save(cfg)
    (repo / ".provenrail.json").write_text(json.dumps({
        "remote": {"detail": "full", "ask": "never", "enabled": False, "wait_s": 9999}}))
    phone.on_question = lambda rid: phone.tap(f"a:{rid}")

    verdict, _ = installed("Bash", {"command": "npx wrangler pages deploy web --token hunter2"},
                           repo)

    assert verdict == "allow" and len(phone.sent) == 1         # still asked, still answered
    assert "hunter2" not in phone.sent[0]["text"]


def test_the_repository_may_make_the_remote_more_private(repo, phone):
    (repo / ".provenrail.json").write_text(json.dumps({"remote": {"detail": "shape",
                                                                  "wait_s": 1}}))
    installed("Bash", {"command": "npx wrangler pages deploy web --token hunter2"}, repo)
    assert "hunter2" not in phone.sent[0]["text"]


def test_a_feature_switched_off_by_the_repository_is_said_out_loud(repo):
    (repo / ".provenrail.json").write_text(json.dumps({"undo": {"enabled": False},
                                                       "watch": {"enabled": False}}))
    _, _, err = guard.run_hook(payload("Bash", {"command": "python build.py"}, repo),
                               budget_s=guard.HOOK_TIMEOUT_S)
    assert "switched OFF for this project" in err
    assert "undo checkpoints" in err and "the loop breaker" in err and "file lanes" not in err


def test_a_long_command_is_never_shown_as_if_it_were_the_whole_command(repo, phone):
    tail = " && " + "npx wrangler pages deploy web"
    command = "echo " + "a" * remote.MAX_BODY_CHARS + tail
    (repo / ".provenrail.json").write_text(json.dumps({"remote": {"wait_s": 1}}))
    installed("Bash", {"command": command}, repo)
    text = phone.sent[0]["text"]
    assert "NOT shown" in text and str(len(command) - remote.MAX_BODY_CHARS) in text


# ---------------------------------------------------------------- answers


def test_a_refusal_stands_whatever_is_tapped_after_it(phone):
    cfg = remote.load()
    phone.tap("d:rid1")
    phone.tap("a:rid1")
    remote.fetch(cfg)
    assert remote._take_answer("rid1") == "deny"


def test_only_the_account_that_paired_can_answer_in_a_shared_chat(phone):
    cfg = remote.load()
    cfg["user_id"] = 7
    remote.save(cfg)
    phone.pending.append({"update_id": 500, "callback_query": {
        "id": "x", "data": "a:rid2", "from": {"id": 8},
        "message": {"chat": {"id": phone.chat_id}}}})
    phone.pending.append({"update_id": 501, "message": {
        "text": "stop", "from": {"id": 8}, "chat": {"id": phone.chat_id}}})
    remote.fetch(cfg)
    assert remote._take_answer("rid2") == "" and remote.apply_commands(cfg) == []
    phone.pending.append({"update_id": 502, "callback_query": {
        "id": "y", "data": "a:rid2", "from": {"id": 7},
        "message": {"chat": {"id": phone.chat_id}}}})
    remote.fetch(cfg)
    assert remote._take_answer("rid2") == "approve"


def test_the_wait_is_measured_from_before_the_question_is_sent(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(remote.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(remote.time, "sleep", lambda s: None)

    def slow_send(*args, **kwargs):
        clock["now"] += 40                        # the send alone used up the whole wait

    fetched = []
    monkeypatch.setattr(remote, "send", slow_send)
    monkeypatch.setattr(remote, "fetch", lambda *a, **k: fetched.append(k))
    cfg = {"provider": "ntfy", "topic": "t", "installed_at": 1}
    assert remote.ask(cfg, "q", "b", wait_s=30) == "timeout"
    assert fetched == []                          # no further network call past the deadline


# ---------------------------------------------------------------- nothing waits forever


def _hold(path, seconds, ready):
    with localstate.locked(path):
        ready.set()
        time.sleep(seconds)


def test_a_hook_does_not_queue_behind_a_slow_snapshot(repo, monkeypatch):
    monkeypatch.setattr(checkpoint, "LOCK_WAIT_S", 0.2)
    ready = threading.Event()
    lock = localstate.project_dir(repo) / checkpoint.LOCK_FILENAME
    holder = threading.Thread(target=_hold, args=(lock, 2.0, ready))
    holder.start()
    ready.wait(5)
    started = time.monotonic()
    with pytest.raises(checkpoint.CheckpointError) as failure:
        checkpoint.snapshot(repo, tool="Bash")
    waited = time.monotonic() - started
    holder.join()
    assert waited < 1.5 and "still running" in str(failure.value)


def test_the_background_check_never_waits_for_someone_elses_long_poll(repo, monkeypatch):
    monkeypatch.setattr(remote.subprocess, "Popen", lambda *a, **k: None)
    ready = threading.Event()
    holder = threading.Thread(target=_hold, args=(localstate.home() / remote.LOCK_FILENAME,
                                                  2.0, ready))
    holder.start()
    ready.wait(5)
    started = time.monotonic()
    assert remote.poll_in_background() is False
    waited = time.monotonic() - started
    holder.join()
    assert waited < 1.0


def test_the_reserve_covers_everything_that_follows_a_phone_wait():
    assert supervise.RESERVE_S >= remote._HTTP_TIMEOUT_S + checkpoint.SNAPSHOT_BUDGET_S
    assert remote.MAX_WAIT_S + supervise.RESERVE_S <= guard.HOOK_TIMEOUT_S


# ---------------------------------------------------------------- what is on disk


def test_the_store_and_its_secrets_are_owner_only(repo, phone):
    (repo / ".env").write_text("SECRET=1\n")
    checkpoint.snapshot(repo, tool="Bash")
    for folder in (localstate.home(), localstate.project_dir(repo)):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700, folder
    for name in (remote.CONFIG_FILENAME,):
        assert stat.S_IMODE((localstate.home() / name).stat().st_mode) == 0o600


def test_a_home_directory_created_loose_is_tightened(tmp_path, monkeypatch, repo):
    loose = tmp_path / "loose-home"
    loose.mkdir(mode=0o755)
    (loose / "projects").mkdir(mode=0o755)
    monkeypatch.setenv(localstate.HOME_ENV, str(loose))
    localstate.project_dir(repo)
    assert stat.S_IMODE(loose.stat().st_mode) == 0o700
