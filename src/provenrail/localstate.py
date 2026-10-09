"""Where the supervisor keeps what it knows about a project, and how it is read and written.

Checkpoints, file lanes, the loop watcher and the stop switch all need state that outlives one
hook invocation and is shared by every agent session working in the same repository. None of
it belongs inside the repository: a shadow object store in the working tree would be committed
by the first `git add -A`, and a lanes file there would be rolled back by the very undo it
sits beside. So it lives under one directory in the user's home, keyed by the project root.

Standard library only, and it must import on Python 3.9: this file is vendored into the
zero-install plugin, where it runs under whatever `python3` the machine has.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:                                              # POSIX only; absent on Windows
    import fcntl as _fcntl
except ImportError:                               # pragma: no cover - platform dependent
    _fcntl = None  # type: ignore[assignment]

#: Overrides the state directory. Tests use it, and so can anyone who wants the state on
#: another disk.
HOME_ENV = "PROVENRAIL_HOME"

#: Characters of the root's SHA-256 kept in the directory name. Twelve hex characters is 48
#: bits, which makes a collision between two projects on one machine a non-event, and the
#: readable prefix in front of it is what a person looks for when they open the folder.
_KEY_HEX = 12

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def home() -> Path:
    override = os.environ.get(HOME_ENV)
    return Path(override) if override else Path.home() / ".provenrail"


def find_root(start: Any = None) -> Path | None:
    """The repository root above `start`, or None when `start` is not inside one.

    Found by walking up to a `.git` entry rather than by asking git, because this runs on
    every tool call and a process spawn to learn a path is the single most expensive way to
    learn it. `.git` is a directory in a clone and a FILE in a worktree or submodule, and both
    mark a root.
    """
    try:
        here = Path(start or os.getcwd()).resolve()
    except OSError:
        return None
    for directory in (here, *here.parents):
        if (directory / ".git").exists():
            return directory
    return None


def project_key(root: Any) -> str:
    resolved = str(Path(root).resolve())
    digest = hashlib.sha256(resolved.encode("utf-8", "surrogateescape")).hexdigest()[:_KEY_HEX]
    name = _SAFE_NAME.sub("-", Path(resolved).name).strip("-") or "root"
    return f"{name}-{digest}"


def project_dir(root: Any, create: bool = True) -> Path:
    path = home() / "projects" / project_key(root)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Any, default: Any) -> Any:
    """The parsed file, or `default` when it is missing or unreadable.

    Callers that must tell "empty" from "corrupt" should not use this. Everything here treats a
    corrupt state file as an empty one on purpose: the state is a cache of observations, and a
    half-written file after a crash must not stop the next tool call.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path: Any, data: Any) -> None:
    """Write atomically, so a reader never sees half a file and a crash leaves the old one."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # A name unique to this process is all that is needed, and `tempfile` costs several
    # milliseconds to import on a path that runs on every tool call.
    tmp = f"{target}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"))
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def locked(path: Any):
    """Hold an exclusive lock for the duration of the block.

    Two agents in one repository run their hooks at the same moment as a matter of course, and
    every structure here is read, changed and written back. On a platform with no `flock` the
    block runs unlocked: a lost update to a lane or a loop counter is a missed warning, which is
    the direction this is allowed to fail in.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle = open(target, "a+")  # noqa: SIM115 - held open across the yield on purpose
    try:
        if _fcntl is not None:
            _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        yield
    finally:
        try:
            if _fcntl is not None:
                _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
        finally:
            handle.close()


def section(config_path: Any, name: str) -> dict[str, Any]:
    """One top-level object from `.provenrail.json`, or `{}`.

    Read here rather than through either engine's policy loader because these settings are not
    policy: a malformed `undo` block must not stop the delete rules loading, and the delete
    rules failing to load must not switch checkpoints off.
    """
    if not config_path:
        return {}
    data = read_json(config_path, {})
    value = data.get(name) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}
