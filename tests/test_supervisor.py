"""The supervisor: stop switch, loop breaker, file lanes, phone remote, and the checkpoint hook.

Two properties are tested harder than the features themselves. The supervisor may never turn
a refusal into an allow by failing, and both enforcement engines must reach the same verdict
with it switched on, because the zero-install plugin and the installed CLI answer the same
hook on the same machine depending on which one is newer.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from provenrail import checkpoint, guard, lanes, localstate, remote, supervise, watch

ROOT = Path(__file__).resolve().parent.parent
STANDALONE = ROOT / "plugins" / "provenrail-guard" / "scripts" / "guard_standalone.py"

#: `tools/measure_loops.py` on the development machine, 2026-10-09: 3,186 Claude Code
#: sessions, 147,356 tool calls. Keyed by "longest back-to-back run of an identical block of
#: one to three calls in the session", value is how many sessions had exactly that.
MEASURED = {1: 3095, 2: 49, 3: 15, 4: 6, 5: 5, 6: 1, 8: 2, 9: 1, 10: 2, 11: 2, 12: 1, 13: 1,
            14: 1, 15: 1, 16: 1, 22: 1, 39: 1, 64: 1}
#: The share of sessions the breaker may question at all. One in a hundred sessions is the
#: most this is allowed to interrupt; the measured rate at the shipped threshold is under half
#: of that, and the assertion below is what stops the threshold drifting down.
MAX_SESSIONS_QUESTIONED = 0.01


def git(repo: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True,
                          text=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('one')\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    monkeypatch.chdir(root)
    monkeypatch.setattr(remote, "idle_seconds", lambda: None)
    return root


def payload(tool: str, tool_input: dict, cwd: Path, session: str = "s1",
            event: str = "PreToolUse") -> str:
    return json.dumps({"hook_event_name": event, "tool_name": tool, "tool_input": tool_input,
                       "session_id": session, "cwd": str(cwd)})


def decision_of(stdout: str) -> tuple[str, str]:
    """(verdict, reason) from a Claude-shaped hook reply. No output means no objection."""
    if not stdout.strip():
        return "allow", ""
    out = json.loads(stdout).get("hookSpecificOutput") or {}
    return out.get("permissionDecision", "allow"), out.get("permissionDecisionReason", "")


def installed(tool: str, tool_input: dict, cwd: Path, session: str = "s1",
              event: str = "PreToolUse", host: str = "claude-code") -> tuple[str, str]:
    code, out, _ = guard.run_hook(payload(tool, tool_input, cwd, session, event),
                                  default_event="pre" if event == "PreToolUse" else "post",
                                  host=host, budget_s=guard.HOOK_TIMEOUT_S)
    assert code == 0
    return decision_of(out)


def standalone(tool: str, tool_input: dict, cwd: Path, session: str = "s1",
               event: str = "PreToolUse", host: str = "claude-code") -> tuple[str, str]:
    done = subprocess.run(
        [sys.executable, str(STANDALONE), "--host", host, "--event",
         "pre" if event == "PreToolUse" else "post"],
        input=payload(tool, tool_input, cwd, session, event), capture_output=True, text=True,
        cwd=str(cwd), env={"PATH": os.environ["PATH"], "HOME": str(cwd.parent),
                           "PROVENRAIL_HOME": os.environ["PROVENRAIL_HOME"]})
    assert done.returncode == 0, done.stderr
    return decision_of(done.stdout)


ENGINES = pytest.mark.parametrize("engine", [installed, standalone], ids=["cli", "plugin"])


# ---------------------------------------------------------------- loop breaker


@pytest.mark.parametrize("calls,expected", [
    ([], 0),
    (["a"], 1),
    (["a", "b", "c"], 1),
    (["a", "a", "a", "a"], 4),
    (["x", "a", "a", "a"], 3),
    (["a", "b", "a", "b", "a", "b"], 3),
    (["a", "b", "c", "a", "b", "c"], 2),
    (["a", "a", "b", "a", "a", "b", "a", "a", "b"], 3),
    (["a", "b", "a", "b", "a"], 1),                 # the tail `b a` then `a b a`: no clean block
    (["a", "b", "c", "d", "a", "b", "c", "d"], 1),  # a cycle of four is past MAX_PERIOD
])
def test_repeat_counting(calls, expected):
    got = watch.repeats(calls)
    if calls == ["a", "b", "a", "b", "a"]:
        # `b a` repeated twice is also a fair reading of this tail, and it is the larger one.
        assert got == 2
    else:
        assert got == expected


def test_the_threshold_is_the_one_the_measurement_supports():
    sessions = sum(MEASURED.values())
    questioned = sum(n for run, n in MEASURED.items() if run >= watch.DEFAULT_REPEATS)
    assert questioned / sessions <= MAX_SESSIONS_QUESTIONED
    one_lower = sum(n for run, n in MEASURED.items() if run >= watch.DEFAULT_REPEATS - 1)
    assert one_lower >= questioned               # lowering it can only question more sessions
    assert watch.WINDOW >= watch.DEFAULT_REPEATS * watch.MAX_PERIOD


def test_the_breaker_fires_once_per_full_run_not_on_every_call_after():
    fired = [watch.observe("sess", "same", threshold=4) for _ in range(9)]
    assert fired == [0, 0, 0, 4, 0, 0, 0, 4, 0]
    assert watch.observe("other-session", "same", threshold=4) == 0


def test_a_fingerprint_is_stable_and_does_not_contain_the_arguments():
    a = watch.fingerprint("Bash", {"command": "echo sk-live-SECRET", "timeout": 5})
    b = watch.fingerprint("Bash", {"timeout": 5, "command": "echo sk-live-SECRET"})
    assert a == b and "SECRET" not in a and len(a) == 16
    assert a != watch.fingerprint("Bash", {"command": "echo other", "timeout": 5})


@ENGINES
def test_a_stuck_agent_is_put_to_a_human(repo, engine):
    for i in range(watch.DEFAULT_REPEATS - 1):
        assert engine("Bash", {"command": "npm test"}, repo)[0] == "allow", i
    verdict, reason = engine("Bash", {"command": "npm test"}, repo)
    assert verdict == "ask"
    assert supervise.RULE_LOOP in reason and str(watch.DEFAULT_REPEATS) in reason


@ENGINES
def test_ordinary_work_between_identical_calls_is_not_a_loop(repo, engine):
    for i in range(watch.DEFAULT_REPEATS * 2):
        assert engine("Bash", {"command": "npm test"}, repo)[0] == "allow"
        assert engine("Edit", {"file_path": str(repo / "src" / "app.py"),
                               "old_string": str(i), "new_string": "x"}, repo)[0] == "allow"


@ENGINES
def test_the_loop_breaker_can_be_switched_off_or_retuned(repo, engine):
    (repo / ".provenrail.json").write_text(json.dumps({"watch": {"repeats": 3}}))
    verdicts = [engine("Bash", {"command": "npm test"}, repo)[0] for _ in range(3)]
    assert verdicts == ["allow", "allow", "ask"]
    (repo / ".provenrail.json").write_text(json.dumps({"watch": {"enabled": False}}))
    assert {engine("Bash", {"command": "npm run x"}, repo, session="s9")[0]
            for _ in range(20)} == {"allow"}


@ENGINES
def test_arming_no_rules_does_not_switch_the_supervisor_off(repo, engine):
    (repo / ".provenrail.json").write_text(json.dumps({"policy": {"use": []},
                                                       "watch": {"repeats": 2}}))
    assert engine("Bash", {"command": "rm -rf /"}, repo)[0] == "allow"     # no rules: allowed
    assert len(checkpoint.read_log(repo)) == 1                             # and still undoable
    assert engine("Bash", {"command": "rm -rf /"}, repo)[0] == "ask"       # and still watched
    watch.halt()
    assert engine("Bash", {"command": "ls"}, repo)[0] == "deny"


@ENGINES
def test_a_config_that_only_tunes_the_supervisor_keeps_the_default_rules(repo, engine):
    (repo / ".provenrail.json").write_text(json.dumps({"undo": {"enabled": True}}))
    assert engine("Bash", {"command": "rm -rf /"}, repo)[0] == "deny"


def test_a_host_that_cannot_ask_refuses_a_loop_instead_of_waving_it_through(repo):
    verdicts = [installed("Bash", {"command": "npm test"}, repo, host="codex")[0]
                for _ in range(watch.DEFAULT_REPEATS)]
    assert verdicts[-1] == "deny" and set(verdicts[:-1]) == {"allow"}


# ---------------------------------------------------------------- stop switch


@ENGINES
def test_stop_refuses_everything_until_resume(repo, engine):
    watch.halt(by="pr stop", reason="looked wrong")
    for tool, tool_input in (("Bash", {"command": "ls"}), ("Read", {"file_path": "x"}),
                             ("Edit", {"file_path": str(repo / "src" / "app.py")})):
        verdict, reason = engine(tool, tool_input, repo)
        assert verdict == "deny"
        assert supervise.RULE_STOPPED in reason and "pr resume" in reason
        assert "looked wrong" in reason
    assert checkpoint.read_log(repo) == []           # a stopped agent does no work at all
    assert watch.resume() is True
    assert engine("Bash", {"command": "ls"}, repo)[0] == "allow"
    assert watch.resume() is False


@ENGINES
def test_a_stop_file_that_cannot_be_read_still_stops(repo, engine):
    path = localstate.home() / watch.HALT_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ truncated")
    assert engine("Bash", {"command": "ls"}, repo)[0] == "deny"


# ---------------------------------------------------------------- lanes


@ENGINES
def test_a_second_session_is_asked_before_it_overwrites_the_first(repo, engine):
    target = {"file_path": str(repo / "src" / "app.py"), "old_string": "a", "new_string": "b"}
    assert engine("Edit", target, repo, session="alpha")[0] == "allow"

    verdict, reason = engine("Edit", target, repo, session="bravo")
    assert verdict == "ask"
    assert supervise.RULE_LANE in reason and "src/app.py" in reason and "alpha" in reason

    assert engine("Edit", target, repo, session="alpha")[0] == "allow"       # its own lane
    other = dict(target, file_path=str(repo / "README.md"))
    assert engine("Edit", other, repo, session="bravo")[0] == "allow"        # another file


def test_an_edit_that_was_only_asked_about_takes_no_lane(repo):
    target = {"file_path": str(repo / "src" / "app.py")}
    lanes.claim(repo, "zulu", "claude-code", "src/app.py")
    assert installed("Edit", target, repo, session="alpha")[0] == "ask"     # never said to run
    note = lanes.held_by_other(repo, "bravo", "src/app.py")
    assert note["session"] == "zulu"


def test_a_lane_expires_and_never_reaches_outside_the_root(repo, tmp_path):
    lanes.claim(repo, "alpha", "claude-code", "src/app.py", now=1000)
    assert lanes.held_by_other(repo, "bravo", "src/app.py", now=1000 + 60)["session"] == "alpha"
    assert lanes.held_by_other(repo, "bravo", "src/app.py",
                               now=1000 + lanes.DEFAULT_TTL_S + 1) is None
    assert lanes.target("Edit", {"file_path": str(tmp_path / "elsewhere.py")}, repo) == ""
    assert lanes.target("Bash", {"command": "sed -i x src/app.py"}, repo) == ""
    assert lanes.target("Edit", {"file_path": "src/app.py"}, repo, str(repo)) == "src/app.py"


# ---------------------------------------------------------------- checkpoints in the hook


@ENGINES
def test_a_checkpoint_is_taken_before_a_write_and_not_before_a_read(repo, engine):
    engine("Read", {"file_path": str(repo / "src" / "app.py")}, repo)
    engine("Bash", {"command": "git status"}, repo)
    assert checkpoint.read_log(repo) == []

    engine("Bash", {"command": "python build.py --all"}, repo)
    log = checkpoint.read_log(repo)
    assert [(e["tool"], e["label"], e["session"]) for e in log] == [
        ("Bash", "python", "s1")]         # the shape: the script name is an operand

    (repo / "src" / "app.py").unlink()               # what the command "did"
    assert checkpoint.restore(repo, log[0]["n"])["verified"] is True
    assert (repo / "src" / "app.py").read_text() == "print('one')\n"


@ENGINES
def test_a_refused_call_takes_no_checkpoint_and_undo_can_be_switched_off(repo, engine):
    assert engine("Bash", {"command": "rm -rf /"}, repo)[0] == "deny"
    assert checkpoint.read_log(repo) == []
    (repo / ".provenrail.json").write_text(json.dumps({"undo": {"enabled": False}}))
    assert engine("Bash", {"command": "python build.py"}, repo)[0] == "allow"
    assert checkpoint.read_log(repo) == []


def test_a_failing_checkpoint_never_blocks_the_call_and_says_so_once(repo, monkeypatch):
    def broken(*args, **kwargs):
        raise checkpoint.CheckpointError("disk full")

    monkeypatch.setattr(checkpoint, "snapshot", broken)
    code, out, err = guard.run_hook(payload("Bash", {"command": "python build.py"}, repo))
    assert decision_of(out)[0] == "allow"
    assert "no checkpoint was taken (disk full)" in err and "pr undo" in err
    _, _, again = guard.run_hook(payload("Bash", {"command": "python build2.py"}, repo))
    assert "no checkpoint" not in again


# ---------------------------------------------------------------- the phone


class FakeTelegram:
    """Stands in for api.telegram.org. Records what was sent and plays scripted updates."""

    def __init__(self, chat_id: int = 42):
        self.chat_id = chat_id
        self.sent: list[dict] = []
        self.pending: list[dict] = []
        self.next_update = 100
        self.on_question = None          # callable(request_id) -> list of updates to queue
        self.fail = False

    def tap(self, data: str, chat_id: int | None = None) -> None:
        self.pending.append({"update_id": self.next_update, "callback_query": {
            "id": "cb", "data": data,
            "message": {"chat": {"id": self.chat_id if chat_id is None else chat_id}}}})
        self.next_update += 1

    def say(self, text: str, chat_id: int | None = None) -> None:
        self.pending.append({"update_id": self.next_update, "message": {
            "text": text, "chat": {"id": self.chat_id if chat_id is None else chat_id}}})
        self.next_update += 1

    def __call__(self, method, url, body=None, timeout=10):
        if self.fail:
            raise OSError("network down while calling " + url)
        call = url.rsplit("/", 1)[-1]
        if call == "sendMessage":
            self.sent.append(body)
            buttons = (body.get("reply_markup") or {}).get("inline_keyboard")
            if buttons and self.on_question:
                self.on_question(buttons[0][0]["callback_data"][2:])
            return b'{"ok":true,"result":{}}'
        if call == "getUpdates":
            ready = [u for u in self.pending if u["update_id"] >= body["offset"]]
            self.pending = []
            return json.dumps({"ok": True, "result": ready}).encode()
        if call == "getMe":
            return b'{"ok":true,"result":{"username":"my_bot"}}'
        return b'{"ok":true,"result":true}'


@pytest.fixture
def phone(monkeypatch):
    fake = FakeTelegram()
    monkeypatch.setattr(remote, "_http", fake)
    monkeypatch.setattr(remote, "poll_in_background", lambda: False)
    monkeypatch.setattr(remote, "idle_seconds", lambda: None)
    remote.save({"provider": "telegram", "token": "123:SECRET-TOKEN", "chat_id": fake.chat_id,
                 "installed_at": int(time.time())})
    remote.set_away(True)
    return fake


ASKS = ("Bash", {"command": "npx wrangler pages deploy web"})


def test_approving_on_the_phone_lets_the_call_through_and_is_journalled(repo, phone):
    phone.on_question = lambda rid: phone.tap(f"a:{rid}")
    verdict, _ = installed(*ASKS, repo)
    assert verdict == "allow"
    question = phone.sent[0]
    assert question["chat_id"] == 42 and "npx wrangler pages deploy web" in question["text"]
    assert "Approve?" in question["text"] and "proj" in question["text"]
    entry = [e for e in guard.read_journal() if e.get("remote")][-1]
    assert entry["remote"] == "approve" and entry["verdict"] == "allow" and entry["rule"]


def test_denying_on_the_phone_refuses_the_call(repo, phone):
    phone.on_question = lambda rid: phone.tap(f"d:{rid}")
    verdict, reason = installed(*ASKS, repo)
    assert verdict == "deny" and "refused from the phone remote" in reason
    assert checkpoint.read_log(repo) == []


def test_an_answer_from_any_other_chat_is_not_an_answer(repo, phone):
    phone.on_question = lambda rid: phone.tap(f"a:{rid}", chat_id=666)
    (repo / ".provenrail.json").write_text(json.dumps({"remote": {"wait_s": 1}}))
    verdict, _ = installed(*ASKS, repo)
    assert verdict == "ask"                          # falls back to the host's own prompt


@pytest.mark.parametrize("how", ["silence", "network", "send-fails"])
def test_no_answer_and_no_network_both_leave_the_verdict_alone(repo, phone, how, monkeypatch):
    (repo / ".provenrail.json").write_text(json.dumps({"remote": {"wait_s": 1}}))
    if how == "send-fails":
        phone.fail = True
    elif how == "network":
        def die(rid):
            phone.fail = True
        phone.on_question = die
        monkeypatch.setattr(remote.time, "sleep", lambda s: None)
    code, out, err = guard.run_hook(payload(*ASKS, repo), budget_s=guard.HOOK_TIMEOUT_S)
    assert decision_of(out)[0] == "ask"
    assert "stays here" in err
    assert "SECRET-TOKEN" not in err and "SECRET-TOKEN" not in out


def test_a_hook_installed_with_a_short_timeout_never_waits_on_the_phone(repo, phone):
    """A host kills a hook at its timeout and reads the silence as "no opinion". A question
    still open on the phone at that moment would have become an allow."""
    phone.on_question = lambda rid: phone.tap(f"a:{rid}")
    code, out, err = guard.run_hook(payload(*ASKS, repo))        # the legacy 15 second budget
    assert decision_of(out)[0] == "ask" and phone.sent == []
    assert "pr guard install" in err and "15-second timeout" in err


def test_the_installed_timeout_and_the_stated_budget_are_one_number(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = guard.install_claude_hooks(tmp_path)
    pre = json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    assert pre["timeout"] == guard.HOOK_TIMEOUT_S == remote.HOOK_TIMEOUT_S
    assert pre["command"].endswith(f"--budget {pre['timeout']}")
    assert remote.MAX_WAIT_S + supervise.RESERVE_S <= guard.HOOK_TIMEOUT_S
    plugin = json.loads((ROOT / "plugins" / "provenrail-guard" / "hooks" /
                         "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    assert plugin["timeout"] == guard.HOOK_TIMEOUT_S
    assert plugin["command"].endswith(f" pre {plugin['timeout']}")


def test_at_the_keyboard_the_question_stays_on_the_machine(repo, phone):
    remote.set_away(False)
    assert installed(*ASKS, repo)[0] == "ask"
    assert phone.sent == []


def test_a_host_with_no_prompt_of_its_own_always_uses_the_phone(repo, phone):
    remote.set_away(False)
    phone.on_question = lambda rid: phone.tap(f"a:{rid}")
    assert installed(*ASKS, repo, host="codex")[0] == "allow"
    assert len(phone.sent) == 1


def test_a_refusal_is_reported_to_the_phone_without_a_question(repo, phone):
    assert installed("Bash", {"command": "rm -rf /"}, repo)[0] == "deny"
    assert len(phone.sent) == 1 and "reply_markup" not in phone.sent[0]
    assert phone.sent[0]["text"].startswith("Blocked: Bash in proj")


def test_shape_detail_keeps_every_operand_on_the_machine(repo, phone):
    (repo / ".provenrail.json").write_text(json.dumps({"remote": {"detail": "shape",
                                                                  "wait_s": 1}}))
    installed("Bash", {"command": "npx wrangler pages deploy web --token hunter2"}, repo)
    assert "hunter2" not in phone.sent[0]["text"]
    assert "npx wrangler pages deploy" in phone.sent[0]["text"]


def test_stop_from_the_phone_halts_and_answers_an_open_question(repo, phone):
    phone.on_question = lambda rid: phone.say("/stop")
    assert installed(*ASKS, repo)[0] == "deny"
    assert watch.halted()["by"] == "the phone remote"
    assert installed("Bash", {"command": "ls"}, repo)[0] == "deny"
    phone.say("resume")
    assert remote.poll_once() == ["resume"]
    assert watch.halted() is None
    phone.say("stop", chat_id=666)                   # a stranger cannot stop your agents either
    assert remote.poll_once() == [] and watch.halted() is None


def test_two_questions_in_flight_each_get_their_own_answer(phone):
    cfg = remote.load()
    remote.send(cfg, "q1", "", "aaaa")
    remote.send(cfg, "q2", "", "bbbb")
    phone.tap("d:bbbb")
    phone.tap("a:aaaa")
    remote.fetch(cfg)                                # one caller drains both updates
    assert remote._take_answer("aaaa") == "approve"
    assert remote._take_answer("bbbb") == "deny"
    assert remote._take_answer("aaaa") == ""         # an answer is used once


@pytest.mark.parametrize("age_days,licensed,usable", [
    (0, None, True), (remote.TRIAL_DAYS - 1, False, True), (remote.TRIAL_DAYS, False, False),
    (remote.TRIAL_DAYS + 30, None, False), (remote.TRIAL_DAYS + 30, True, True),
])
def test_the_evaluation_window_and_the_licence(age_days, licensed, usable):
    now = 2_000_000_000
    cfg = {"provider": "ntfy", "topic": "t", "installed_at": now - age_days * 86400}
    ok, note = remote.entitled(cfg, licensed, now=now)
    assert ok is usable
    if not usable:
        assert "pr activate" in note and "provenrail.com/pricing" in note


def test_an_expired_evaluation_stops_using_the_phone_and_never_weakens_the_verdict(
        repo, phone):
    cfg = remote.load()
    cfg["installed_at"] = int(time.time()) - (remote.TRIAL_DAYS + 1) * 86400
    remote.save(cfg)
    phone.on_question = lambda rid: phone.tap(f"a:{rid}")
    code, out, err = guard.run_hook(payload(*ASKS, repo), budget_s=guard.HOOK_TIMEOUT_S)
    assert decision_of(out)[0] == "ask" and phone.sent == []
    assert "evaluation of the phone remote has ended" in err


def test_ntfy_sends_buttons_that_post_to_a_reply_topic_and_reads_them_back(monkeypatch):
    calls = []

    def fake(method, url, body=None, timeout=10):
        calls.append((method, url, body))
        if method == "GET":
            return (b'{"event":"open"}\n{"event":"message","id":"m1","message":"a:rid1"}\n'
                    b'{"event":"message","id":"m2","message":"stop"}\nnot json\n')
        return b"{}"

    monkeypatch.setattr(remote, "_http", fake)
    cfg = {"provider": "ntfy", "topic": "pr-abc", "installed_at": 1_700_000_000}
    remote.send(cfg, "Approve?", "body", "rid1")
    method, url, body = calls[0]
    assert (method, url) == ("POST", "https://ntfy.sh/")
    assert body["topic"] == "pr-abc"
    assert [(a["label"], a["url"], a["body"]) for a in body["actions"]] == [
        ("Approve", "https://ntfy.sh/pr-abc-r", "a:rid1"),
        ("Deny", "https://ntfy.sh/pr-abc-r", "d:rid1")]
    remote.fetch(cfg)
    assert calls[1][1] == "https://ntfy.sh/pr-abc-r/json?poll=1&since=1700000000"
    assert remote._take_answer("rid1") == "approve"
    remote.fetch(cfg)
    assert calls[2][1].endswith("since=m2")          # resumes after the last message seen


def test_pairing_needs_the_code_this_machine_printed(monkeypatch):
    fake = FakeTelegram(chat_id=77)
    monkeypatch.setattr(remote, "_http", fake)
    monkeypatch.setattr(remote.secrets, "randbelow", lambda n: 23456)     # code 123456
    fake.say("hello", chat_id=666)                   # a stranger gets there first
    fake.say("123456", chat_id=77)
    parser = argparse.ArgumentParser()
    remote.add_arguments(parser)
    out = io.StringIO()
    code = remote.run(parser.parse_args(["setup", "telegram", "--token", "1:T", "--wait", "5"]),
                      out=out)
    assert code == 0 and "123456" in out.getvalue() and "t.me/my_bot" in out.getvalue()
    assert remote.load()["chat_id"] == 77
    mode = stat.S_IMODE(os.stat(remote.config_file()).st_mode)
    assert mode == 0o600


def test_pairing_fails_closed_without_the_code(monkeypatch):
    fake = FakeTelegram(chat_id=77)
    monkeypatch.setattr(remote, "_http", fake)
    monkeypatch.setattr(remote, "_SLICE_S", 0)
    fake.say("not the code", chat_id=666)
    parser = argparse.ArgumentParser()
    remote.add_arguments(parser)
    out = io.StringIO()
    code = remote.run(parser.parse_args(["setup", "telegram", "--token", "1:T", "--wait", "1"]),
                      out=out)
    assert code == 1 and remote.load() is None


def test_only_http_urls_are_ever_opened():
    with pytest.raises(remote.RemoteError):
        remote._http("GET", "file:///etc/passwd")


# ---------------------------------------------------------------- vendoring


@pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="no system python3")
def test_the_plugin_copy_runs_on_the_system_python(repo):
    done = subprocess.run(
        ["/usr/bin/python3", str(STANDALONE), "--host", "claude-code", "--event", "pre"],
        input=payload("Bash", {"command": "python build.py"}, repo), capture_output=True,
        text=True, cwd=str(repo),
        env={"PATH": os.environ["PATH"], "HOME": str(repo.parent),
             "PROVENRAIL_HOME": os.environ["PROVENRAIL_HOME"]})
    assert done.returncode == 0, done.stderr
    assert "Traceback" not in done.stderr
    assert len(checkpoint.read_log(repo)) == 1


def test_the_names_the_supervisor_keeps_to_avoid_an_import_match_the_remote():
    assert supervise._REMOTE_CONFIG == remote.CONFIG_FILENAME
    assert supervise._MAX_PREVIEW == remote.MAX_BODY_CHARS


def test_a_machine_with_no_remote_never_loads_the_remote_module(repo):
    code = ("import sys, json; sys.path.insert(0, %r); import guard_standalone as g; "
            "g.run(json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', "
            "'tool_input': {'command': 'python x.py'}, 'session_id': 's', 'cwd': %r})); "
            "print('remote' in sys.modules, 'scan' in sys.modules)")
    code = code % (str(STANDALONE.parent), str(repo))  # noqa: UP031
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          cwd=str(repo), env={"PATH": os.environ["PATH"],
                                              "HOME": str(repo.parent),
                                              "PROVENRAIL_HOME": os.environ["PROVENRAIL_HOME"]})
    assert done.stdout.split() == ["False", "False"], done.stderr


def test_every_number_in_the_readme_is_the_number_in_the_code():
    """The README is the product's claim sheet. A constant changed without the sentence that
    quotes it is how copy ends up promising something the code stopped doing."""
    from provenrail import rulesets
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    armed = sum(len(rulesets.CATALOG[pack]["rules"]) for pack in guard.DEFAULT_PACKS)
    sessions = sum(MEASURED.values())
    asked = sum(n for run, n in MEASURED.items() if run >= watch.DEFAULT_REPEATS)
    for claim in (
        f"{armed} rules",
        f"runs {watch.DEFAULT_REPEATS} times back to back",
        f'"repeats": {watch.DEFAULT_REPEATS}',
        f"in the last {lanes.DEFAULT_TTL_S // 60} minutes",
        f'"minutes": {lanes.DEFAULT_TTL_S // 60}',
        f"over {checkpoint.MAX_FILE_BYTES // (1024 * 1024)} MiB",
        f"free for {remote.TRIAL_DAYS} days",
        f"kept for {checkpoint.KEEP_DAYS} days",
        f"finish in {checkpoint.SNAPSHOT_BUDGET_S:g} seconds",
        f"--wait-s {remote.DEFAULT_WAIT_S}",
        f"longer than {remote.MAX_BODY_CHARS} characters",
        f"{sessions:,} sessions",
        f"{100 * MEASURED[1] / sessions:.1f}% of sessions never repeated",
        f"{100 * asked / sessions:.2f}% would have been asked",
        "Verified: the working tree now matches the checkpoint exactly.",
    ):
        assert claim in text, claim
    assert list(checkpoint.DEFAULT_INCLUDE) == [".env", ".env.*"]
    assert '"include": [".env", ".env.*"]' in text
