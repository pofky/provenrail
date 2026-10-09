"""File lanes: two agents in one repository do not silently overwrite each other.

Running several agent sessions against one checkout is now ordinary, and nothing tells any of
them that another one exists. The failure is quiet: session B edits a file session A changed
two minutes ago, from a copy it read before that change, and A's work is gone with no error
anywhere. Worktrees avoid it, and many people do not use worktrees.

A lane is a note that a session wrote a file recently. Before an edit, the hook looks for a
fresh note from a DIFFERENT session on the same file and, if it finds one, puts the edit to a
human with the other session named. It asks rather than blocks: the second edit is often
exactly what the user wants, and only they know.

What it is not. It is not a lock, and it sees only edits made through a file-editing tool. A
shell command that rewrites a file takes no lane, because a shell command does not say which
files it will touch.

Standard library only, Python 3.9 compatible: vendored into the zero-install plugin.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

try:                                  # installed as part of the package
    from . import localstate
except ImportError:                   # vendored: the hook imports it as a top-level module
    import localstate  # type: ignore[no-redef]

LANES_FILENAME = "lanes.json"
LOCK_FILENAME = "lanes.lock"

#: How long a lane is held after a session's last edit to the file. A tool hook is never told
#: that a session ended, so the only signal is silence. Fifteen minutes is three times the
#: five-minute prompt-cache lifetime that agent sessions are paced around: a session that has
#: not come back to a file in that long has moved on or stopped.
DEFAULT_TTL_S = 15 * 60

#: Canonical names of the tools that write one named file.
EDIT_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})

_PATH_KEYS = ("file_path", "path", "notebook_path")


def target(tool: str, tool_input: Any, root: Any, cwd: str = "") -> str:
    """The file an edit names, relative to the root, or "" when there is no lane to take."""
    if tool not in EDIT_TOOLS or not isinstance(tool_input, dict) or not root:
        return ""
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            path = Path(value)
            if not path.is_absolute():
                path = Path(cwd or os.getcwd()) / path
            try:
                return str(path.resolve().relative_to(Path(root).resolve()))
            except (ValueError, OSError):
                return ""
    return ""


def _fresh(data: Any, now: float, ttl_s: float) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    return {path: note for path, note in data.items()
            if isinstance(note, dict) and now - float(note.get("at") or 0) < ttl_s}


def held_by_other(root: Any, session_id: str, rel: str, ttl_s: float = DEFAULT_TTL_S,
                  now: float | None = None) -> dict[str, Any] | None:
    """The other session's note on this file, or None. Read-only, and unlocked on purpose:
    a stale read here costs one missed or one extra question, never a lost write."""
    if not rel or not session_id:
        return None
    stamp = time.time() if now is None else now
    path = localstate.project_dir(root, create=False) / LANES_FILENAME
    note = _fresh(localstate.read_json(path, {}), stamp, ttl_s).get(rel)
    if note and note.get("session") and note["session"] != session_id:
        return note
    return None


def claim(root: Any, session_id: str, host: str, rel: str, ttl_s: float = DEFAULT_TTL_S,
          now: float | None = None) -> None:
    """Note that this session has just written the file. Called after the edit ran, so a
    refused or declined edit never takes a lane it did not use."""
    if not rel or not session_id:
        return
    stamp = time.time() if now is None else now
    pdir = localstate.project_dir(root)
    with localstate.locked(pdir / LOCK_FILENAME):
        data = _fresh(localstate.read_json(pdir / LANES_FILENAME, {}), stamp, ttl_s)
        data[rel] = {"session": session_id, "host": host or "", "at": int(stamp)}
        localstate.write_json(pdir / LANES_FILENAME, data)


def reason(rel: str, note: dict[str, Any], now: float | None = None) -> str:
    stamp = time.time() if now is None else now
    minutes = max(0, int((stamp - float(note.get("at") or stamp)) // 60))
    when = "less than a minute ago" if minutes == 0 else (
        "a minute ago" if minutes == 1 else f"{minutes} minutes ago")
    who = f"{note.get('host') or 'agent'} session {str(note.get('session'))[:8]}"
    return (f"another session ({who}) wrote {rel} {when} and may still be working on it. "
            "An edit made from an older copy of the file would silently discard that work")
