"""The loop breaker and the stop switch.

Two things an unattended agent does that no permission prompt catches, because every single
call is one the user would approve: it makes the same call again, and again, for six hours;
and it keeps going after the person responsible has decided it should stop.

**The loop breaker** watches each session's recent tool calls for a block of one, two or
three calls repeated back to back, and puts the next call to a human once the run is long
enough. It asks rather than blocks, because polling a build is also a run of identical calls
and only a person can tell the two apart.

**The stop switch** is a file. While it exists every tool call on this machine, in every
project and on every host, is refused with the reason. `pr stop` writes it, `pr resume`
removes it, and the phone remote can do both. It is deliberately machine-wide: the person
reaching for it is not in a position to remember which of four terminals is the runaway.

Standard library only, Python 3.9 compatible: vendored into the zero-install plugin.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

try:                                  # installed as part of the package
    from . import localstate
except ImportError:                   # vendored: the hook imports it as a top-level module
    import localstate  # type: ignore[no-redef]

HALT_FILENAME = "stop.json"
WATCH_DIRNAME = "watch"

#: How many recent calls are remembered per session. It only has to hold the longest block
#: (3) repeated `DEFAULT_REPEATS` times, with room for a threshold set higher by config.
WINDOW = 64

#: The longest repeating block that is looked for. One catches the same call again and again;
#: two and three catch edit-then-test and read-edit-test cycles that make no progress. Longer
#: cycles exist, and past three the chance that the "cycle" is simply work grows faster than
#: the chance that it is a loop.
MAX_PERIOD = 3

#: Back-to-back repeats of a block before the next call is put to a human. Chosen from
#: `tools/measure_loops.py` run over this machine's own transcripts; the figures are in
#: `tests/test_watch.py::MEASURED`, and the test there fails if this number is moved below
#: what that measurement supports.
DEFAULT_REPEATS = 8

#: Session files untouched for this long are removed. A session that has been silent for a
#: week is over, and nothing here has any other way to learn that.
_STALE_S = 7 * 24 * 3600
_SWEEP_INTERVAL_S = 24 * 3600


def fingerprint(tool: str, tool_input: Any) -> str:
    """A short stable id for "this exact call". Never reversible to the arguments."""
    try:
        body = json.dumps(tool_input, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        body = repr(tool_input)
    return hashlib.sha256((tool + "\0" + body).encode("utf-8", "replace")).hexdigest()[:16]


def repeats(calls: list, max_period: int = MAX_PERIOD) -> int:
    """How many times the block at the END of `calls` is repeated back to back.

    For each block length it counts how many consecutive copies of the final block the list
    ends with, and returns the largest count. A list ending `a b a b a b` is three repeats of
    a block of two. A count of one means the tail is not repeating at all.
    """
    best = 1 if calls else 0
    for period in range(1, max_period + 1):
        if len(calls) < period * 2:
            break
        block = calls[-period:]
        if period > 1 and len(set(block)) == 1:
            # `a a a a` is a block of one repeated four times, not a block of two repeated
            # twice. Counting it again under a longer period would only ever undercount.
            continue
        count = 1
        end = len(calls) - period
        while end - period >= 0 and calls[end - period:end] == block:
            count += 1
            end -= period
        best = max(best, count)
    return best


# ---------------------------------------------------------------- the loop breaker


def _session_file(session_id: str):
    digest = hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:20]
    return localstate.home() / WATCH_DIRNAME / f"{digest}.json"


def observe(session_id: str, fp: str, threshold: int = DEFAULT_REPEATS,
            now: float | None = None) -> int:
    """Record one call and return the repeat count if it has reached the threshold, else 0.

    When it fires the memory is cleared, so a human who looks and says "carry on" is asked
    again only after another full run, not on every call from then on.
    """
    if not session_id or threshold < 2:
        return 0
    stamp = time.time() if now is None else now
    path = _session_file(session_id)
    with localstate.locked(str(path) + ".lock"):
        data = localstate.read_json(path, {})
        calls = data.get("calls") if isinstance(data, dict) else None
        calls = [c for c in calls if isinstance(c, str)] if isinstance(calls, list) else []
        calls = (calls + [fp])[-WINDOW:]
        count = repeats(calls)
        fired = count >= threshold
        localstate.write_json(path, {"calls": [] if fired else calls, "at": int(stamp)})
    _sweep(stamp)
    return count if fired else 0


def _sweep(now: float) -> None:
    folder = localstate.home() / WATCH_DIRNAME
    marker = folder / ".swept"
    try:
        if now - marker.stat().st_mtime < _SWEEP_INTERVAL_S:
            return
    except OSError:
        pass
    try:
        marker.write_text(str(int(now)), encoding="utf-8")
        for entry in os.scandir(folder):
            if entry.name.startswith("."):
                continue
            if now - entry.stat().st_mtime > _STALE_S:
                os.unlink(entry.path)
    except OSError:
        pass


def loop_reason(count: int) -> str:
    return (f"the same tool call, or the same short cycle of calls, has now run {count} times "
            "back to back in this session with nothing different between them. That is what "
            "a stuck agent looks like, and also what polling a build looks like, so it is "
            "yours to judge")


# ---------------------------------------------------------------- the stop switch


def _halt_path():
    return localstate.home() / HALT_FILENAME


def halted() -> dict[str, Any] | None:
    """The stop order in force, or None. One `stat` when there is none."""
    path = _halt_path()
    if not path.exists():
        return None
    data = localstate.read_json(path, None)
    # A stop file that cannot be read is still a stop file. Someone asked for everything to
    # halt, and a truncated write must not turn that into "carry on".
    return data if isinstance(data, dict) else {"by": "unknown", "reason": "", "at": 0}


def halt(by: str = "pr stop", reason: str = "", now: float | None = None) -> dict[str, Any]:
    order = {"by": by, "reason": reason, "at": int(time.time() if now is None else now)}
    localstate.write_json(_halt_path(), order)
    return order


def resume() -> bool:
    try:
        _halt_path().unlink()
        return True
    except FileNotFoundError:
        return False


def halt_reason(order: dict[str, Any]) -> str:
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(order.get("at") or 0))
    why = f" ({order['reason']})" if order.get("reason") else ""
    return (f"every agent on this machine was stopped by {order.get('by') or 'unknown'} at "
            f"{when}{why}. Nothing will run until a person runs `pr resume`")
