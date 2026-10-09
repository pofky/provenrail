"""Measure how often real sessions repeat the same tool call, to set the loop breaker.

A loop breaker that fires on ordinary work is uninstalled within the day, and one set too
high never fires. The threshold cannot be reasoned out: it depends on how long a run of
identical calls an agent makes while doing honest work, such as polling a build.

So this reads your own Claude Code transcripts and, for every session, finds the longest tail
of back-to-back repeats of a block of 1, 2 or 3 tool calls. It prints the distribution, which
is what `watch.DEFAULT_REPEATS` was chosen from.

    python tools/measure_loops.py

**Nothing leaves the machine.** Only counts are printed.
"""

from __future__ import annotations

import collections
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from provenrail import watch  # noqa: E402


def sessions(root: pathlib.Path):
    for path in sorted(root.rglob("*.jsonl")):
        calls = []
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    message = record.get("message") if isinstance(record, dict) else None
                    content = message.get("content") if isinstance(message, dict) else None
                    if not isinstance(content, list):
                        continue
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            calls.append(watch.fingerprint(block.get("name") or "",
                                                           block.get("input")))
        except OSError:
            continue
        if calls:
            yield path, calls


def main() -> int:
    root = pathlib.Path.home() / ".claude" / "projects"
    worst = collections.Counter()
    total_sessions = total_calls = 0
    for _path, calls in sessions(root):
        total_sessions += 1
        total_calls += len(calls)
        longest = 0
        for end in range(1, len(calls) + 1):
            longest = max(longest, watch.repeats(calls[max(0, end - watch.WINDOW):end]))
        worst[longest] += 1
    print(f"{total_sessions} sessions, {total_calls} tool calls")
    print("longest run of an identical block (period 1 to 3) per session:")
    running = 0
    for length in sorted(worst):
        running += worst[length]
        print(f"  {length:>3} repeats: {worst[length]:>5} sessions "
              f"({100 * running / total_sessions:.2f}% at or below)")
    digest = hashlib.sha256(str(sorted(worst.items())).encode()).hexdigest()[:8]
    print(f"distribution id {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
