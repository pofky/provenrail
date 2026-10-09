"""Undo for agents: a snapshot of the working tree before every action that can change it.

Every coding agent can rewind its own file edits. None of them can rewind what a shell command
did, and a shell command is how a working tree is actually lost: `rm -rf`, `git checkout .`,
a formatter run over the wrong directory, a codemod, a script the agent wrote a minute ago.
So the snapshot is taken in the one place that sees every action on every host, the tool hook,
and it is taken of the TREE rather than of the file the tool says it will touch, because a
shell command does not say.

How it works. A second git object store lives outside the repository, under
`~/.provenrail/projects/<key>/shadow`. Before a tool call that can write, the hook stages the
working tree into that store's own index and writes a tree object. The project's real `.git`
is never opened, never written, and never asked anything: no stash, no commit, no ref, nothing
for `git status` to show. Restoring checks files out of the shadow store back into the working
tree and deletes the ones that did not exist yet.

What it does NOT cover, said here because a recovery tool that overstates itself fails at the
worst possible moment:

* Files your `.gitignore` excludes are not snapshotted, apart from the root-level `.env` files
  named in `DEFAULT_INCLUDE`. `node_modules` and build output are regenerable and enormous.
* A file larger than `MAX_FILE_BYTES` is skipped and listed.
* Nested repositories and submodules are recorded as a pointer, not by content.
* Commits, branches and stashes in your real repository are not rewound. The working tree is.
* Anything outside the repository root: a home directory, a database, a deployed service.

Standard library only, Python 3.9 compatible: vendored into the zero-install plugin.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

try:                                  # installed as part of the package
    from . import localstate
    from .shell import command_shape, segments
except ImportError:                   # vendored: the hook imports it as a top-level module
    import localstate  # type: ignore[no-redef]
    from shell import command_shape, segments  # type: ignore[no-redef]

LOG_FILENAME = "checkpoints.jsonl"
HEAD_FILENAME = "checkpoint-head.json"
PAUSED_FILENAME = "checkpoint-paused.json"
LOCK_FILENAME = "checkpoint.lock"
SHADOW_DIRNAME = "shadow"
REF_PREFIX = "refs/provenrail/cp/"
#: The `tool` of a snapshot that an undo took of the state it was about to replace.
UNDO_TOOL = "undo"

#: Seconds the hook will spend on one snapshot before giving up and pausing checkpoints for the
#: project. Measured on this repository on 2026-10-09 (381 files in the snapshot, an SSD over
#: USB): 1.04 s for the first snapshot, 0.03 s for each one after it with nothing changed and
#: 0.045 s after a file was added. Ten seconds is two orders of magnitude of headroom for the
#: incremental case. A repository that cannot be staged in ten seconds needs `pr undo init`,
#: which has no limit, rather than a hook that stalls every tool call.
SNAPSHOT_BUDGET_S = 10.0

#: A single file above this is left out of the snapshot. 50 MiB is GitHub's own warning
#: threshold for a file in a repository, which makes it a size past which a file is far more
#: likely a dataset, a model or a dump than something an agent edits.
MAX_FILE_BYTES = 50 * 1024 * 1024

#: Checkpoints older than this are pruned. Two weeks covers "I noticed on Monday what the agent
#: did the Friday before last" and bounds the store.
KEEP_DAYS = 14
_PRUNE_INTERVAL_S = 24 * 3600

#: Ignored files that are snapshotted anyway, as globs relative to the root. An `.env` is the
#: one ignored file that is neither regenerable nor backed up anywhere, and agents do delete it.
DEFAULT_INCLUDE = (".env", ".env.*")

#: State this project writes into the working tree on every hook. Snapshotting it would make
#: every tree differ from the last and, worse, an undo would roll the guard's journal back.
_ALWAYS_EXCLUDE = ("/.provenrail-guard*", "/.provenrail-spend.json")

#: Tools that cannot change the working tree. Everything else is snapshotted, including tools
#: this list has never heard of: the cost of a needless snapshot is a few milliseconds, and
#: the cost of a missing one is the file. `Task` and `Agent` are here because a subagent's
#: own tool calls pass through the hook themselves.
READ_ONLY_TOOLS = frozenset({
    "Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "TodoWrite", "TodoRead",
    "AskUserQuestion", "Task", "Agent", "NotebookRead", "BashOutput", "KillShell", "KillBash",
    "ToolSearch", "Skill", "ExitPlanMode", "EnterPlanMode", "ListMcpResourcesTool",
    "ReadMcpResourceTool",
})

#: Shell verbs that only read. A command is skipped only when EVERY segment starts with one of
#: these and the command contains no redirection or substitution at all. This is a speed
#: optimisation that may only ever fail toward taking a snapshot: `find` is absent because of
#: `-delete`, `sed` because of `-i`, and anything unlisted is snapshotted.
_READ_ONLY_VERBS = frozenset({
    "ls", "cat", "head", "tail", "wc", "grep", "rg", "pwd", "which", "date", "file", "stat",
    "du", "df", "tree", "sleep", "true", "test", "whoami", "uname", "printenv",
})
_READ_ONLY_GIT = frozenset({
    "status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog",
})
#: Any of these in a command means it can write somewhere or run something we have not read.
_WRITE_MARKERS = (">", "`", "$(", "<(")


class CheckpointError(RuntimeError):
    """A snapshot or restore could not be completed. The message is meant for the user."""


class CheckpointPaused(CheckpointError):
    """Checkpoints are paused for this project, and the message says why and how to resume."""


# ---------------------------------------------------------------- what to snapshot


def needs_snapshot(tool: str, tool_input: Any) -> bool:
    """Whether a snapshot should be taken before this tool call."""
    if tool in READ_ONLY_TOOLS:
        return False
    if tool != "Bash":
        return True
    command = tool_input.get("command") if isinstance(tool_input, dict) else tool_input
    if not isinstance(command, str) or not command.strip():
        return True
    if any(marker in command for marker in _WRITE_MARKERS):
        return True
    parts = segments(command)
    if not parts:
        return True
    for part in parts:
        words = part.split()
        if not words:
            continue
        verb = words[0].rsplit("/", 1)[-1]
        if verb == "git":
            if len(words) < 2 or words[1] not in _READ_ONLY_GIT:
                return True
        elif verb not in _READ_ONLY_VERBS:
            return True
    return False


def label_for(tool: str, tool_input: Any, root: Any = None) -> str:
    """What the list shows for this action: the command's shape, or the file it names.

    A shell command is reduced to its verb and flags, the same rule the guard's journal uses,
    because an operand is where a secret lives and this log is something people paste.
    """
    data = tool_input if isinstance(tool_input, dict) else {}
    if tool == "Bash":
        command = data.get("command") if data else tool_input
        return command_shape(command) if isinstance(command, str) else ""
    for key in ("file_path", "path", "notebook_path"):
        value = data.get(key)
        if isinstance(value, str) and value:
            if root:
                try:
                    return str(Path(value).resolve().relative_to(Path(root).resolve()))
                except (ValueError, OSError):
                    pass
            return value
    return ""


# ---------------------------------------------------------------- git plumbing


def _env(shadow: Path, root: Path, index: Path | None = None) -> dict[str, str]:
    # Every inherited GIT_* variable is dropped first. An agent's shell routinely carries
    # GIT_DIR or GIT_INDEX_FILE from a hook or a rebase in progress, and one stray variable
    # here would point this at the user's real repository, the one thing it must never touch.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_DIR": str(shadow),
        "GIT_WORK_TREE": str(root),
        # The user's own git config is not consulted: no signing prompt, no hooks path, no
        # global excludes, no credential helper, nothing that could block or change a snapshot.
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "provenrail", "GIT_AUTHOR_EMAIL": "checkpoint@localhost",
        "GIT_COMMITTER_NAME": "provenrail", "GIT_COMMITTER_EMAIL": "checkpoint@localhost",
        "LC_ALL": "C",
    })
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return env


def _git(shadow: Path, root: Path, args: list[str], timeout: float | None,
         stdin: bytes | None = None, index: Path | None = None, check: bool = True) -> bytes:
    try:
        done = subprocess.run(["git", *args], cwd=str(root), env=_env(shadow, root, index),
                              input=stdin, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise CheckpointError("git is not installed, and checkpoints are stored with it") from exc
    if check and done.returncode != 0:
        tail = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        raise CheckpointError(f"git {args[0]} failed: {tail[0]}")
    return done.stdout


def _ensure_shadow(pdir: Path, root: Path) -> Path:
    shadow = pdir / SHADOW_DIRNAME
    if (shadow / "HEAD").is_file():
        return shadow
    shadow.mkdir(parents=True, exist_ok=True)
    _git(shadow, root, ["init", "-q"], 30)
    for key, value in (("core.hooksPath", os.devnull), ("gc.auto", "0"),
                       ("core.autocrlf", "false"), ("core.fsmonitor", "false"),
                       ("commit.gpgsign", "false"), ("core.untrackedCache", "true")):
        _git(shadow, root, ["config", key, value], 30)
    info = shadow / "info"
    info.mkdir(exist_ok=True)
    (info / "exclude").write_text("\n".join(_ALWAYS_EXCLUDE) + "\n", encoding="utf-8")
    return shadow


def _escape_exclude(path: str) -> str:
    out = []
    for char in path:
        out.append("\\" + char if char in "\\*?[]!# " else char)
    return "/" + "".join(out)


def _write_tree(shadow: Path, root: Path, include: Any, budget_s: float | None) -> tuple:
    """Stage the working tree into the shadow index and return (tree_sha, skipped_large)."""
    deadline = None if budget_s is None else time.monotonic() + budget_s

    def left() -> float | None:
        if deadline is None:
            return None
        return max(0.05, deadline - time.monotonic())

    # We hold the project lock, so a lock file in the shadow store is from a snapshot that was
    # killed mid-write, and leaving it would fail every snapshot from here on.
    try:
        (shadow / "index.lock").unlink()
    except OSError:
        pass

    skipped: list[str] = []
    listing = _git(shadow, root, ["ls-files", "--others", "--exclude-standard", "-z"], left())
    oversized = []
    for raw in listing.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8", "surrogateescape")
        try:
            if os.lstat(os.path.join(str(root), rel)).st_size > MAX_FILE_BYTES:
                oversized.append(rel)
        except OSError:
            continue
    if oversized:
        with open(shadow / "info" / "exclude", "a", encoding="utf-8",
                  errors="surrogateescape") as fh:
            for rel in oversized:
                fh.write(_escape_exclude(rel) + "\n")
        skipped = oversized

    _git(shadow, root, ["add", "-A", "--", "."], left())
    import glob  # here and below: imported where used, this runs on every call
    forced = []
    for pattern in include or ():
        for match in glob.glob(os.path.join(glob.escape(str(root)), pattern)):
            if os.path.isfile(match) and os.path.getsize(match) <= MAX_FILE_BYTES:
                forced.append(os.path.relpath(match, str(root)))
    if forced:
        _git(shadow, root, ["add", "-f", "--", *forced], left())
    tree = _git(shadow, root, ["write-tree"], left()).decode("ascii").strip()
    return tree, skipped


def _real_head(root: Path) -> str:
    """The branch or commit the user's repository is on, read without running git."""
    try:
        text = (root / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if text.startswith("ref: refs/heads/"):
        return text[len("ref: refs/heads/"):]
    return text[:12]


# ---------------------------------------------------------------- the log


def _refuse(root: Path) -> str:
    """Why this directory must not be snapshotted, or an empty string."""
    if root == Path(root.anchor):
        return "the filesystem root is not a project"
    try:
        if root == Path.home().resolve():
            return "the home directory is not a project"
    except (OSError, RuntimeError):
        pass
    if not (root / ".git").exists():
        return "not a git repository, and checkpoints only run inside one"
    return ""


def read_log(root: Any) -> list[dict[str, Any]]:
    path = localstate.project_dir(root, create=False) / LOG_FILENAME
    out: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict) and "n" in entry and "tree" in entry:
                    out.append(entry)
    except OSError:
        pass
    return out


def paused_reason(root: Any) -> str:
    data = localstate.read_json(localstate.project_dir(root, create=False) / PAUSED_FILENAME, None)
    return str(data.get("reason") or "paused") if isinstance(data, dict) else ""


def snapshot(root: Any, session_id: str = "", host: str = "", tool: str = "", label: str = "",
             include: Any = DEFAULT_INCLUDE, budget_s: float | None = SNAPSHOT_BUDGET_S,
             force: bool = False, now: float | None = None,
             undo_to: int | None = None) -> dict[str, Any]:
    """Record the working tree as it is right now. Returns the log entry.

    Raises `CheckpointPaused` when the project is paused or the snapshot ran out of time, and
    `CheckpointError` for anything else. It never raises anything other than those two, so a
    caller inside a hook can catch one type and carry on.
    """
    root = Path(root).resolve()
    reason = _refuse(root)
    if reason:
        raise CheckpointError(reason)
    pdir = localstate.project_dir(root)
    stamp = time.time() if now is None else now
    try:
        with localstate.locked(pdir / LOCK_FILENAME):
            paused = pdir / PAUSED_FILENAME
            if paused.exists():
                if not force:
                    raise CheckpointPaused(paused_reason(root))
                paused.unlink()
            shadow = _ensure_shadow(pdir, root)
            try:
                tree, skipped = _write_tree(shadow, root, include, budget_s)
            except subprocess.TimeoutExpired:
                why = (f"a snapshot of this repository took longer than {budget_s:g} seconds. "
                       "Run `pr undo init` once to build it outside the hook.")
                localstate.write_json(paused, {"reason": why, "at": int(stamp)})
                raise CheckpointPaused(why) from None
            head = localstate.read_json(pdir / HEAD_FILENAME, {})
            if not isinstance(head, dict):
                head = {}
            n = int(head.get("n") or 0) + 1
            if head.get("tree") == tree and head.get("ref"):
                # Nothing changed since the last snapshot, so the last action wrote nothing and
                # there is no new tree to keep alive. The entry still goes in the log: "state
                # before action N" is a fact about the action even when it equals N-1.
                ref = head["ref"]
            else:
                commit = _git(shadow, root, ["commit-tree", tree, "-m", f"checkpoint {n}"],
                              30).decode("ascii").strip()
                _git(shadow, root, ["update-ref", f"{REF_PREFIX}{n}", commit], 30)
                ref = n
            entry: dict[str, Any] = {
                "n": n, "at": int(stamp), "tree": tree, "ref": ref,
                "session": session_id or "", "host": host or "", "tool": tool or "",
                "label": label or "", "head": _real_head(root),
            }
            if skipped:
                entry["skipped_large"] = skipped
            if undo_to is not None:
                entry["to"] = undo_to
            with open(pdir / LOG_FILENAME, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            pruned_at = float(head.get("pruned_at") or 0)
            if stamp - pruned_at > _PRUNE_INTERVAL_S:
                _prune(pdir, shadow, root, stamp)
                pruned_at = stamp
            localstate.write_json(pdir / HEAD_FILENAME,
                                  {"n": n, "tree": tree, "ref": ref, "pruned_at": pruned_at})
            return entry
    except subprocess.TimeoutExpired:
        raise CheckpointError("git did not answer in time") from None
    except OSError as exc:
        raise CheckpointError(f"could not write the checkpoint store ({exc})") from exc


def _prune(pdir: Path, shadow: Path, root: Path, now: float) -> None:
    """Drop checkpoints older than `KEEP_DAYS` and let git reclaim what only they held."""
    cutoff = now - KEEP_DAYS * 24 * 3600
    entries = read_log(root)
    keep = [e for e in entries if e.get("at", 0) >= cutoff]
    if len(keep) != len(entries):
        live = {e.get("ref") for e in keep}
        dead = sorted({e.get("ref") for e in entries} - live, key=str)
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=str(pdir), prefix=LOG_FILENAME + ".", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for entry in keep:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        os.replace(tmp, pdir / LOG_FILENAME)
        commands = "".join(f"delete {REF_PREFIX}{ref}\n" for ref in dead)
        if commands:
            _git(shadow, root, ["update-ref", "--stdin"], 30, stdin=commands.encode("ascii"),
                 check=False)
    # Packing is slow on a big store and nothing is waiting for it, so it runs detached and
    # its outcome is not this call's business. The next prune will run it again.
    #
    # Never `--prune=now`. This process is detached, so it overlaps the next snapshot, and a
    # tree that snapshot has just written is unreachable until its ref exists a moment later.
    # Pruning "now" deleted exactly that object in testing. Git's default expiry of two weeks
    # cannot race a snapshot and happens to equal `KEEP_DAYS`.
    try:
        subprocess.Popen(["git", "gc", "--quiet"], cwd=str(root),
                         env=_env(shadow, root), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError:
        pass


# ---------------------------------------------------------------- reading and restoring


def find(root: Any, n: int) -> dict[str, Any]:
    for entry in read_log(root):
        if entry.get("n") == n:
            return entry
    raise CheckpointError(f"there is no checkpoint #{n} for this project (they are kept for "
                          f"{KEEP_DAYS} days). `pr undo` lists the ones that exist.")


def changes(root: Any, from_tree: str, to_tree: str, paths: Any = None) -> list[tuple]:
    """(status, path) for what turns `from_tree` into `to_tree`. Status is A, M, D or T."""
    root = Path(root).resolve()
    shadow = localstate.project_dir(root) / SHADOW_DIRNAME
    args = ["diff-tree", "-r", "--no-renames", "--name-status", "-z", from_tree, to_tree]
    if paths:
        args += ["--", *paths]
    fields = _git(shadow, root, args, 60).split(b"\0")
    out = []
    for i in range(0, len(fields) - 1, 2):
        status = fields[i].decode("ascii", "replace")[:1]
        out.append((status, fields[i + 1].decode("utf-8", "surrogateescape")))
    return out


def current_tree(root: Any, include: Any = DEFAULT_INCLUDE) -> str:
    """The tree the working directory is right now, without adding a log entry."""
    root = Path(root).resolve()
    pdir = localstate.project_dir(root)
    with localstate.locked(pdir / LOCK_FILENAME):
        shadow = _ensure_shadow(pdir, root)
        tree, _ = _write_tree(shadow, root, include, None)
        return tree


def _inside(root: Path, rel: str) -> Path | None:
    """`root/rel`, or None when its directory resolves outside the root.

    A snapshot can hold `build/cache.bin` from a time when `build` was a directory, and the
    working tree can now hold `build` as a symlink to somewhere else. Deleting through that
    link would delete a file this tool never snapshotted, in a place it was never pointed at.
    """
    target = root / rel
    try:
        parent = target.parent.resolve()
    except OSError:
        return None
    if parent != root and root not in parent.parents:
        return None
    return target


def restore(root: Any, n: int, paths: Any = None, dry_run: bool = False,
            include: Any = DEFAULT_INCLUDE) -> dict[str, Any]:
    """Put the working tree back to checkpoint `n`. Returns what was done.

    The current state is snapshotted first, so an undo is itself undoable: the returned
    `safety` is the checkpoint to restore if this was the wrong call. A full restore is then
    verified by snapshotting again and comparing tree hashes, and the result says whether the
    working tree now matches the checkpoint exactly.
    """
    root = Path(root).resolve()
    target = find(root, n)
    pdir = localstate.project_dir(root)
    shadow = pdir / SHADOW_DIRNAME
    if dry_run:
        # Looking must not leave a mark: a dry run that logged a safety snapshot would make
        # itself the newest checkpoint, and `pr undo last` would then restore to it.
        safety = {"n": None, "tree": current_tree(root, include)}
    else:
        safety = snapshot(root, tool=UNDO_TOOL, label=f"before undo to #{n}", include=include,
                          budget_s=None, force=True, undo_to=None if paths else n)
    todo = changes(root, safety["tree"], target["tree"], paths)
    result: dict[str, Any] = {
        "checkpoint": n, "safety": safety["n"],
        "restored": [p for s, p in todo if s != "D"], "deleted": [p for s, p in todo if s == "D"],
        "refused": [], "errors": [], "dry_run": dry_run, "verified": None,
    }
    if dry_run or not todo:
        if not dry_run:
            result["verified"] = True
        return result

    import shutil
    import tempfile
    with localstate.locked(pdir / LOCK_FILENAME):
        fd, tmp_index = tempfile.mkstemp(dir=str(pdir), prefix="restore-index.")
        os.close(fd)
        os.unlink(tmp_index)                     # git wants to create the index itself
        index = Path(tmp_index)
        try:
            _git(shadow, root, ["read-tree", target["tree"]], 120, index=index)
            if result["restored"]:
                # A path that is a file in the checkpoint and a directory now cannot be
                # written until the directory is gone, and git will not remove it for us.
                for rel in result["restored"]:
                    where = _inside(root, rel)
                    if where is not None and where.is_dir() and not where.is_symlink():
                        shutil.rmtree(where, ignore_errors=True)
                payload = b"".join(p.encode("utf-8", "surrogateescape") + b"\0"
                                   for p in result["restored"])
                done = subprocess.run(["git", "checkout-index", "-f", "-z", "--stdin"],
                                      cwd=str(root), env=_env(shadow, root, index),
                                      input=payload, capture_output=True, check=False)
                if done.returncode != 0:
                    result["errors"].extend(
                        done.stderr.decode("utf-8", "replace").strip().splitlines()[:20])
        finally:
            for leftover in (index, Path(str(index) + ".lock")):
                try:
                    leftover.unlink()
                except OSError:
                    pass
        for rel in result["deleted"]:
            where = _inside(root, rel)
            if where is None:
                result["refused"].append(rel)
                continue
            try:
                where.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                result["errors"].append(f"{rel}: {exc}")
                continue
            # Directories the deleted files leave empty did not exist in the checkpoint either.
            parent = where.parent
            while parent != root and root in parent.parents:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
    result["deleted"] = [p for p in result["deleted"] if p not in result["refused"]]
    if not paths:
        result["verified"] = current_tree(root, include) == target["tree"]
    return result


def last_change(root: Any) -> int:
    """The newest checkpoint an undo would actually change something by restoring.

    "Undo the last thing" means the last action that changed a file, not the last action. The
    newest checkpoint is very often the one taken before a test run that wrote nothing, and
    restoring to it would report success while leaving the damage in place. An undo's own
    safety snapshots are skipped for the same reason: they are the state being escaped.
    """
    log = read_log(root)
    if not log:
        raise CheckpointError("there are no checkpoints for this project yet")
    now = current_tree(root)
    # An undo to #T makes everything from T up to its own safety snapshot the future that was
    # just escaped. Stepping "back" into it is how a second `pr undo last` would restore the
    # damage the first one removed, so those entries are passed over and the walk continues
    # with what came before T.
    floor = None
    for entry in reversed(log):
        if floor is not None and entry["n"] >= floor:
            continue
        if entry.get("tool") == UNDO_TOOL:
            to = entry.get("to")
            if isinstance(to, int):
                floor = to if floor is None else min(floor, to)
            continue
        if entry["tree"] != now:
            return int(entry["n"])
    raise CheckpointError("nothing has changed since the oldest checkpoint, so there is "
                          "nothing to undo")


def describe(root: Any, entries: list[dict[str, Any]], latest_tree: str | None = None
             ) -> list[dict[str, Any]]:
    """Each entry with `changed`: what the action it precedes did to the working tree.

    The effect of action N is the difference between checkpoint N and checkpoint N+1, or
    between N and the working tree as it is now for the newest one.
    """
    log = read_log(root)
    following = {log[i]["n"]: log[i + 1]["tree"] for i in range(len(log) - 1)}
    out = []
    for entry in entries:
        after = following.get(entry["n"], latest_tree)
        row = dict(entry)
        if after is None or after == entry["tree"]:
            row["changed"] = []
        else:
            try:
                row["changed"] = changes(root, entry["tree"], after)
            except CheckpointError:
                row["changed"] = None
        out.append(row)
    return out


# ---------------------------------------------------------------- command line


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def _summary(changed: Any) -> str:
    if changed is None:
        return "unknown"
    if not changed:
        return "no file changes"
    counts = {"A": 0, "M": 0, "D": 0}
    for status, _ in changed:
        counts["M" if status == "T" else status] = counts.get("M" if status == "T" else status,
                                                              0) + 1
    parts = [f"{sign}{counts[key]}" for key, sign in (("A", "+"), ("M", "~"), ("D", "-"))
             if counts.get(key)]
    return f"{len(changed)} file{'s' if len(changed) != 1 else ''} ({' '.join(parts)})"


def render_list(root: Any, limit: int, session: str = "", now: float | None = None) -> str:
    log = read_log(root)
    if session:
        log = [e for e in log if str(e.get("session", "")).startswith(session)]
    if not log:
        reason = paused_reason(root)
        if reason:
            return f"Checkpoints are paused for this project: {reason}\n"
        return ("No checkpoints yet for this project. One is taken before every agent action "
                "that can change a file, once the hook is installed (`pr guard install`).\n")
    stamp = time.time() if now is None else now
    shown = log[-limit:]
    rows = describe(root, shown, current_tree(root))
    lines = [f"Checkpoints for {root} (newest last). Each is the working tree BEFORE the action.",
             ""]
    for row in rows:
        action = (row.get("tool") or "?") + ((" " + row["label"]) if row.get("label") else "")
        lines.append(f"  #{row['n']:<5} {_ago(stamp - row.get('at', stamp)):<9} "
                     f"{str(row.get('session', ''))[:8]:<8}  {action[:44]:<44}  "
                     f"{_summary(row['changed'])}")
    lines += ["", "  pr undo last        put the tree back to before the most recent action",
              "  pr undo <n>         put the tree back to checkpoint #n",
              "  pr undo <n> --diff  list what that would change, and change nothing", ""]
    return "\n".join(lines)


def add_arguments(parser: Any) -> None:
    parser.add_argument("target", nargs="?", default="",
                        help="a checkpoint number, `last`, `init`, or nothing to list them")
    parser.add_argument("paths", nargs="*", help="restore only these paths")
    parser.add_argument("--diff", action="store_true",
                        help="show what a restore would change and change nothing")
    parser.add_argument("--limit", type=int, default=20, help="how many to list (default 20)")
    parser.add_argument("--session", default="", help="list only this session id (prefix)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def run(args: Any, out: Any = None) -> int:
    import sys
    out = out or sys.stdout
    root = localstate.find_root()
    if root is None:
        print("pr undo: not inside a git repository. Checkpoints are per repository.",
              file=sys.stderr)
        return 2
    target = (args.target or "").strip().lstrip("#")
    try:
        if not target:
            if args.json:
                rows = describe(root, read_log(root)[-args.limit:], current_tree(root))
                json.dump(rows, out, indent=2)
                out.write("\n")
            else:
                out.write(render_list(root, args.limit, args.session))
            return 0
        if target == "init":
            entry = snapshot(root, tool="init", label="pr undo init", budget_s=None, force=True)
            out.write(f"Checkpoint #{entry['n']} taken. The store is built, so snapshots in "
                      "the hook are now incremental.\n")
            return 0
        if target == "last":
            n = last_change(root)
        else:
            try:
                n = int(target)
            except ValueError:
                raise CheckpointError(f"`{args.target}` is not a checkpoint number") from None
        result = restore(root, n, paths=args.paths or None, dry_run=args.diff)
    except CheckpointError as exc:
        print(f"pr undo: {exc}", file=sys.stderr)
        return 1
    if args.json:
        json.dump(result, out, indent=2)
        out.write("\n")
        return 1 if result["errors"] or result["refused"] else 0
    verb = "Would restore" if args.diff else "Restored"
    total = len(result["restored"]) + len(result["deleted"])
    if not total:
        out.write(f"The working tree already matches checkpoint #{n}. Nothing to do.\n")
        return 0
    out.write(f"{verb} checkpoint #{n}: {len(result['restored'])} file(s) written back, "
              f"{len(result['deleted'])} removed.\n")
    for rel in result["restored"][:40]:
        out.write(f"  ~ {rel}\n")
    for rel in result["deleted"][:40]:
        out.write(f"  - {rel}\n")
    if total > 80:
        out.write(f"  ... and more ({total} in all; --json lists every path)\n")
    for rel in result["refused"]:
        out.write(f"  ! not removed, its directory now points outside the project: {rel}\n")
    for line in result["errors"]:
        out.write(f"  ! {line}\n")
    if not args.diff:
        if result["verified"] is True:
            out.write("Verified: the working tree now matches the checkpoint exactly.\n")
        elif result["verified"] is False:
            out.write("NOT verified: the working tree still differs from the checkpoint. "
                      "See the lines marked ! above.\n")
        out.write(f"Changed your mind? `pr undo {result['safety']}` puts it back.\n")
    return 1 if result["errors"] or result["refused"] or result["verified"] is False else 0
