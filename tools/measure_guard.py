"""Measure the guard against the commands agents actually run on THIS machine.

A guardrail has two failure modes and they pull in opposite directions. The one everybody
tests is "does it stop the bad thing". The one that decides whether anyone still has it
installed a week later is "how often does it stop the work", and that number cannot be
guessed: it depends on what your agents do all day.

So this reads your own Claude Code transcripts, replays every Bash command through the guard
offline, and prints the interruption rate with samples. It is the measurement that drove the
0.4.0 rules, where the shipped defaults turned out to interrupt 824 of 36,929 real commands
and almost none of them were dangerous.

    python tools/measure_guard.py                    # default packs
    python tools/measure_guard.py --use destructive  # one pack
    python tools/measure_guard.py --rule destructive.force-remove --samples 25

**Nothing leaves the machine.** Transcripts are read locally, the guard decides locally, and
the output is counts, rule ids, and command samples printed to your own terminal. There is no
network call anywhere in this file. The samples are the raw commands, so treat the output the
way you would treat your own shell history: it is fine on your screen and it is not something
to paste into an issue. `pr guard card` exists for the version that is safe to share.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def transcripts(root: pathlib.Path):
    """Every Bash call in every local transcript, with the directory it ran in.

    The working directory is half the input: `rm -rf .next` is a build step in one project and
    nothing at all outside one, and a replay that drops it measures a different guard from the
    one that runs.
    """
    files = 0
    for path in sorted(root.rglob("*.jsonl")):
        files += 1
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if '"tool_use"' not in line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    content = (obj.get("message") or {}).get("content")
                    if not isinstance(content, list):
                        continue
                    for block in content:
                        if not isinstance(block, dict) or block.get("type") != "tool_use":
                            continue
                        args = block.get("input") or {}
                        if block.get("name") == "Bash" and isinstance(args, dict):
                            command = args.get("command")
                            if isinstance(command, str):
                                yield {"command": command, "cwd": obj.get("cwd") or "",
                                       "tool": "Bash"}
                        elif isinstance(args, dict):
                            yield {"input": args, "cwd": obj.get("cwd") or "",
                                   "tool": block.get("name") or ""}
        except OSError:
            continue
    print(f"transcripts read: {files}", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--projects", default=str(pathlib.Path.home() / ".claude" / "projects"),
                        help="directory holding Claude Code transcripts")
    parser.add_argument("--use", nargs="*", default=None,
                        help="packs or rule ids to arm (default: the default packs)")
    parser.add_argument("--rule", default=None, help="show samples for this rule id only")
    parser.add_argument("--samples", type=int, default=4, help="samples to print per rule")
    parser.add_argument("--bash-only", action="store_true",
                        help="skip Write/Edit and other non-shell tools")
    args = parser.parse_args(argv)

    from provenrail import guard
    from provenrail.easy import load_policy

    policy = load_policy({"use": list(args.use) if args.use else list(guard.DEFAULT_PACKS)})
    print(f"rules armed: {len(policy.rules)}", file=sys.stderr)

    verdicts: collections.Counter[str] = collections.Counter()
    fired: collections.Counter[tuple] = collections.Counter()
    samples: dict[str, list[str]] = collections.defaultdict(list)
    total = 0

    for call in transcripts(pathlib.Path(args.projects)):
        if args.bash_only and call["tool"] != "Bash":
            continue
        total += 1
        payload = ({"command": call["command"]} if "command" in call else call["input"])
        decision = guard.decide(policy, call["tool"], payload, None, call["cwd"])
        verdicts[decision["verdict"]] += 1
        if decision["verdict"] == "allow":
            continue
        rule = decision["rule"] or "?"
        fired[(rule, decision["verdict"], call["tool"])] += 1
        if args.rule in (None, rule) and len(samples[rule]) < args.samples:
            text = call.get("command") or json.dumps(call.get("input"), default=str)
            samples[rule].append(text[:160].replace("\n", " | "))

    if not total:
        print("no commands found. Is --projects pointing at your Claude Code transcripts?",
              file=sys.stderr)
        return 1

    print(f"\ncalls replayed: {total}")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict:6} {count:6}  {count / total * 100:6.3f}%")
    print("\nrules that fired, most often first:")
    for (rule, verdict, tool), count in fired.most_common():
        print(f"  {count:5}  {verdict:5}  {tool:<12} {rule}")
        for sample in samples.get(rule, [])[:args.samples]:
            print(f"           {sample}")
    print("\nRead the samples, not just the totals. Every one of them is a moment your agent "
          "would have stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
