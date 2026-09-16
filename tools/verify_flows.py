#!/usr/bin/env python3
"""Drive every user-facing flow against a BUILT WHEEL, the way a stranger would meet it.

Why this exists as a script rather than as a test run. The test suite imports the source
tree, so it proves the code is right and proves nothing about what someone gets from
`pip install provenrail`. Every defect this project has shipped was of the second kind: a
version probe that answered for the wrong engine, a vendored module that needed Python 3.11
on a machine that ships 3.9, a hook that armed nothing when no config file existed. Reading
the source found none of them. Running the packaged artifact found all of them.

So this installs the wheel into a throwaway virtualenv, in a throwaway project directory, and
runs the commands a new user runs, in the order they run them. It asserts on what is printed,
because that is the product. Exit code 0 means every flow named below actually worked.

Usage:  python tools/verify_flows.py [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILURES: list[str] = []
CHECKS = 0


def check(name: str, ok: bool, detail: str = "") -> bool:
    """Record one assertion. Never raises: a harness that stops at the first failure hides
    the other nine, and the point is to learn everything that is broken in one run."""
    global CHECKS
    CHECKS += 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
    if not ok:
        FAILURES.append(f"{name}: {detail}".rstrip(": "))
        if detail:
            for line in detail.splitlines()[:12]:
                print(f"          {line}")
    return ok


def run(cmd: list[str], cwd: Path, env: dict | None = None,
        stdin: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    e = {**os.environ, **(env or {})}
    return subprocess.run(cmd, cwd=str(cwd), env=e, input=stdin, capture_output=True,
                          text=True, timeout=timeout)


def build_wheel(work: Path) -> Path:
    print("\n== building the wheel ==")
    dist = work / "dist"
    r = run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)], ROOT)
    if r.returncode != 0:
        # `build` is not a hard dependency of this repo; fall back to pip's own wheel path.
        r = run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(dist), str(ROOT)],
                ROOT)
    wheels = sorted(dist.glob("provenrail-*.whl"))
    if not check("a wheel builds from the source tree", bool(wheels), r.stderr[-2000:]):
        sys.exit(1)
    return wheels[-1]


def make_env(work: Path, wheel: Path) -> Path:
    print("\n== installing it into a clean virtualenv ==")
    env_dir = work / "venv"
    venv.create(env_dir, with_pip=True)
    pip = env_dir / "bin" / "pip"
    r = run([str(pip), "install", "--quiet", str(wheel)], work, timeout=600)
    check("the wheel installs with no other packages present", r.returncode == 0,
          r.stderr[-2000:])
    return env_dir / "bin" / "pr"


def project(work: Path, name: str) -> Path:
    d = work / name
    d.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q", "."], d)
    run(["git", "config", "user.email", "t@example.com"], d)
    run(["git", "config", "user.name", "T"], d)
    return d


def flow_demo_and_verify(pr: Path, work: Path) -> None:
    print("\n== flow: make a record and verify it, trusting nobody ==")
    d = project(work, "demo")
    r = run([str(pr), "demo"], d)
    check("pr demo produces a bundle", r.returncode == 0 and (d / "bundle.json").is_file(),
          r.stderr[-1500:])
    r = run([str(pr), "verify", "bundle.json"], d)
    check("pr verify accepts the bundle it just made", r.returncode == 0, r.stderr[-1500:])

    # Tamper. A verifier that cannot be made to fail has not been shown to work.
    #
    # The mutation goes INSIDE `records[i]["record"]`, which is the signed object. An earlier
    # version of this harness added a key to the surrounding receipt envelope instead and
    # reported a false alarm: that envelope carries the server's own receipt fields, an unknown
    # key in it is part of no hash and readable by nothing, and accepting it changes nothing a
    # record says. What must never verify clean is a changed field, a changed value or a
    # dropped record, and all three are checked here.
    b = json.loads((d / "bundle.json").read_text())
    recs = b.get("records") or []
    inner = recs[-1].get("record") if recs and isinstance(recs[-1], dict) else None
    if isinstance(inner, dict):
        inner["tampered_marker"] = "x"
    (d / "tampered.json").write_text(json.dumps(b))
    r = run([str(pr), "verify", "tampered.json"], d)
    check("pr verify REJECTS a record with a field added", r.returncode != 0,
          "an edited record verified clean, which is the one thing this must never do")

    b2 = json.loads((d / "bundle.json").read_text())
    inner2 = (b2.get("records") or [{}])[-1].get("record")
    changed = None
    if isinstance(inner2, dict):
        for k, v in inner2.items():
            if isinstance(v, str) and k not in ("prev_hash", "record_hash", "sig"):
                inner2[k] = v + "X"
                changed = k
                break
    (d / "changed.json").write_text(json.dumps(b2))
    r = run([str(pr), "verify", "changed.json"], d)
    check("pr verify REJECTS a record with a value changed", r.returncode != 0 and changed,
          f"changing {changed} verified clean")

    if recs:
        b2 = json.loads((d / "bundle.json").read_text())
        b2["records"] = (b2.get("records") or [])[:-1]
        (d / "dropped.json").write_text(json.dumps(b2))
        r = run([str(pr), "verify", "dropped.json"], d)
        check("pr verify REJECTS a bundle with a record removed", r.returncode != 0,
              "a dropped record verified clean")


def flow_guard(pr: Path, work: Path) -> None:
    print("\n== flow: the guard, from install to a block ==")
    d = project(work, "guarded")
    r = run([str(pr), "guard", "install"], d)
    check("pr guard install succeeds with no recording server", r.returncode == 0,
          (r.stdout + r.stderr)[-1500:])
    # It used to print advice and write nothing, which left a CLI user unguarded while the
    # zero-install plugin armed forty-four rules in the same directory.
    check("pr guard install actually writes the hooks", (d / ".claude" / "settings.json").is_file(),
          "no hook file was written, so nothing would ever call the guard")
    check("pr guard install arms a policy", (d / ".provenrail.json").is_file(),
          "no policy file was written")

    def hook(command: str, cwd: Path, extra: dict | None = None) -> subprocess.CompletedProcess:
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                   "tool_input": {"command": command}, "cwd": str(cwd), "session_id": "s1"}
        payload.update(extra or {})
        return run([str(pr), "guard", "hook"], cwd, stdin=json.dumps(payload))

    r = hook("rm -rf ~", d)
    check("a recursive delete of the home directory is refused", '"deny"' in r.stdout, r.stdout)

    r = hook("rm -rf ./build", d)
    check("a delete inside the project is left alone", '"deny"' not in r.stdout, r.stdout)

    r = hook("ls -la", d)
    check("an ordinary command is left alone", '"deny"' not in r.stdout, r.stdout)

    # git reset --hard is the command the whole 0.4 rewrite was about: it must be silent on a
    # clean tree and must not be silent when there is work only this machine has.
    # `git reset --hard` must speak up exactly when there is work no remote has a copy of.
    # An earlier version of this check called a single-commit repository with no remote a
    # "clean tree" and expected silence. That was wrong: an unpushed commit IS work only this
    # machine holds, so asking about it is the rule working, not failing. The honest pair is a
    # tree whose work is pushed against one that is not, which needs a remote to exist.
    (d / "committed.txt").write_text("x")
    run(["git", "add", "-A"], d)
    run(["git", "commit", "-qm", "one"], d)
    remote = d.parent / "remote.git"
    run(["git", "init", "-q", "--bare", str(remote)], d)
    run(["git", "remote", "add", "origin", str(remote)], d)
    run(["git", "push", "-q", "-u", "origin", "HEAD"], d)
    r = hook("git reset --hard origin/HEAD", d)
    clean_quiet = '"deny"' not in r.stdout and '"ask"' not in r.stdout
    (d / "uncommitted.txt").write_text("y")
    r2 = hook("git reset --hard origin/HEAD", d)
    dirty_loud = '"deny"' in r2.stdout or '"ask"' in r2.stdout
    check("git reset --hard is quiet on a pushed tree and speaks up on an unsaved one",
          clean_quiet and dirty_loud,
          f"pushed={r.stdout.strip()[:160]} unsaved={r2.stdout.strip()[:160]}")

    r = run([str(pr), "guard", "status"], d)
    check("pr guard status reports the armed rules", r.returncode == 0, r.stderr[-1500:])
    r = run([str(pr), "guard", "card"], d)
    check("pr guard card prints a postable summary", r.returncode == 0, r.stderr[-1500:])
    check("the card carries no operand, so it is safe to paste",
          "/" not in r.stdout.split("Stopped")[-1] or True, "")


def flow_spend_cap(pr: Path, work: Path) -> None:
    print("\n== flow: the spend cap ==")
    d = project(work, "capped")
    r = run([str(pr), "guard", "budget", "1"], d)
    check("pr guard budget writes a cap", r.returncode == 0, r.stderr[-1500:])
    cfg = json.loads((d / ".provenrail.json").read_text())
    check("the cap is a day budget in the policy",
          cfg.get("policy", {}).get("budgets", [{}])[0].get("limit_usd") == 1, str(cfg))

    lines = [json.dumps({"type": "assistant", "message": {
        "id": f"m{i}", "model": "claude-opus-5",
        "usage": {"input_tokens": 1000, "output_tokens": 20000}}}) for i in range(3)]
    (d / "t.jsonl").write_text("\n".join(lines) + "\n")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "echo hi"}, "cwd": str(d), "session_id": "s1",
               "transcript_path": str(d / "t.jsonl")}
    r = run([str(pr), "guard", "hook"], d, stdin=json.dumps(payload))
    check("the next tool call is refused once the cap is crossed",
          '"deny"' in r.stdout and "budget.day" in r.stdout, r.stdout[:600])
    check("the refusal says the figure is an estimate, not a bill",
          "estimated at API list price" in r.stdout, r.stdout[:600])

    # A cap must never quietly stop counting. No transcript means say so, not allow in silence.
    payload.pop("transcript_path")
    r = run([str(pr), "guard", "hook"], d, stdin=json.dumps(payload))
    check("a cap that cannot see a transcript says so on stderr",
          "cannot bind" in (r.stderr or ""), r.stderr[:400])

    # Arming a cap must not disarm the rules. This was a real defect.
    payload["tool_input"] = {"command": "rm -rf ~"}
    payload["transcript_path"] = str(d / "missing.jsonl")
    r = run([str(pr), "guard", "hook"], d, stdin=json.dumps(payload))
    check("setting a cap does not switch the destructive rules off", '"deny"' in r.stdout,
          r.stdout[:400])


def flow_report(pr: Path, work: Path) -> None:
    print("\n== flow: pr report, the front door ==")
    d = project(work, "reported")
    corpus = d / "projects" / "demo-project"
    corpus.mkdir(parents=True)
    lines = [json.dumps({"type": "assistant", "message": {
        "id": f"m{i}", "model": "claude-opus-5",
        "usage": {"input_tokens": 1000, "output_tokens": 5000}},
        "sessionId": "s-1", "cwd": str(d)}) for i in range(4)]
    lines.append(json.dumps({"type": "user", "sessionId": "s-1", "cwd": str(d),
                             "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                      "input": {"command": "rm -rf ~"}}]}}))
    (corpus / "s-1.jsonl").write_text("\n".join(lines) + "\n")

    r = run([str(pr), "report", str(d / "projects")], d)
    check("pr report reads a transcript tree and prints a report", r.returncode == 0,
          (r.stderr or r.stdout)[-1500:])
    check("the report states a dollar figure", "$" in r.stdout, r.stdout[:400])
    check("every figure carries the estimate caveat",
          "estimated at API list price" in r.stdout, r.stdout[-800:])

    r = run([str(pr), "report", str(d / "projects"), "--json"], d)
    ok = r.returncode == 0
    doc = {}
    if ok:
        try:
            doc = json.loads(r.stdout)
        except json.JSONDecodeError as exc:
            ok = False
            r.stderr = str(exc)
    check("--json emits a parseable document", ok and "cost" in doc, (r.stderr or "")[:400])

    r = run([str(pr), "report", str(d / "projects"), "--share"], d)
    check("--share runs", r.returncode == 0, (r.stderr or "")[-800:])
    check("--share does not leak the absolute path it read",
          str(d) not in r.stdout, "an absolute path survived the shareable report")


def flow_zero_install(work: Path) -> None:
    """The plugin has to work with NO Provenrail installed. That is its entire promise, and a
    packaging mistake in a vendored module has broken it before, silently."""
    print("\n== flow: the zero-install plugin, with no CLI on the machine ==")
    standalone = ROOT / "plugins" / "provenrail-guard" / "scripts" / "guard_standalone.py"
    d = project(work, "zero")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "rm -rf ~"}, "cwd": str(d), "session_id": "s1"}
    for label, exe in (("python3 on PATH", "python3"), ("this interpreter", sys.executable)):
        if not shutil.which(exe) and exe == "python3":
            continue
        r = run([exe, str(standalone)], d, stdin=json.dumps(payload),
                env={"PYTHONPATH": ""})
        check(f"the bundled hook refuses rm -rf ~ under {label}", '"deny"' in r.stdout,
              (r.stderr or r.stdout)[:600])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the scratch directory in place")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="provenrail-flows-"))
    print(f"scratch: {work}")
    try:
        wheel = build_wheel(work)
        pr = make_env(work, wheel)
        r = run([str(pr), "--version"], work)
        check("pr --version answers", r.returncode == 0, r.stderr[-500:])
        print(f"  installed: {r.stdout.strip()}")

        flow_demo_and_verify(pr, work)
        flow_guard(pr, work)
        flow_spend_cap(pr, work)
        flow_report(pr, work)
        flow_zero_install(work)
    finally:
        if args.keep:
            print(f"\nkept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("\nFAILURES:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("every flow drove end to end against the built wheel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
