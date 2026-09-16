"""What your agents already did, read off the transcripts they left behind.

A guard is insurance. It is silent until the day it is not, and a thing that has never visibly
done anything gets uninstalled long before the day it would have paid out. Meanwhile the same
machine is carrying months of transcripts of work that already happened: on the machine this
was written on, 2,129 files and 3.5 GB of them. `ccusage` reads a strict subset of those same
files, reports cost alone, and is downloaded 332,083 times a month, which is the measurement
that this report's value is retroactive. Install, run one command, and learn what the agents
did over the last months, with nothing to set up and nothing to wait for.

So this is the front door, and four things have to be true of it or it is worse than nothing.

**Offline.** There is no network call in this module or anything it reaches, and
`tests/test_report.py` asserts it by breaking the socket. A tool that reads every transcript on
the machine and then opens a connection is a tool nobody can run at work.

**Nothing is invented.** A transcript that cannot be read is counted as unread, not as empty; a
model with no verified rate is reported as unpriced, not as free. This is the same rule
`transcript.accrue` and `spend.prior_spend` already hold, and for the same reason: a total
reported on authority is acted on, so it has to say where it stops.

**Shareable is a separate thing from readable.** The plain report prints the user's own paths
and project names on the user's own screen, which is fine. `--share` produces the version that
goes in a public post, and there the only thing said about a command is `shell.command_shape`
of it, which drops every operand, because an operand is where a path, a hostname and an API key
all live. That property is held by a test of the same shape as `tests/test_guard_card.py`.

**It streams.** 3.5 GB never lands in memory. Each file is read line by line, most lines are
rejected on a substring test before JSON ever sees them, and `--since` skips a whole file on
its mtime, since a transcript is append-only and one last written before the cutoff can hold no
line after it.

*Why the dollars are computed here rather than by calling `transcript.accrue`.* `accrue` is the
incremental reader a hook uses: it charges only the increase since a byte offset and keeps the
last `RECENT_IDS` message ids, which is exactly right for one live transcript and cannot
deduplicate one model call that appears in two files, as a forked session's copied history
does (78 such ids in the corpus above). So the pricing rules it holds are imported and applied
here over a whole corpus instead: `pricing.cost_for` for the rate, `pricing.reliable` for
whether the rate can be trusted, `transcript._message_id` for what counts as one call, and the
same "the largest usage seen for an id wins" rule for streamed partials. The two are pinned to
each other by a test that prices the shared fixture both ways and demands the same total.

JSON shape, stable and versioned by `SCHEMA`:

    {"schema": "provenrail.report/1", "root": str|null, "since": str|null, "share": bool,
     "read": {"transcripts", "unreadable_transcripts", "unreadable_lines", "bytes",
              "skipped_by_since", "seconds"},
     "cost": {"estimated_usd", "caveat", "model_calls", "unpriced_calls", "duplicate_calls",
              "by_model": [{"model", "calls", "estimated_usd", "priced"}]},
     "activity": {"sessions", "first", "last", "tool_calls", "bash_commands",
                  "files_written", "sessions_ended_mid_tool_call", "by_tool": [[name, n]]},
     "risk": {"screened", "deny", "ask", "by_rule": [{"rule", "verdict", "count"}],
              "by_shape": [{"shape", "verdict", "count"}]},
     "blast_radius": {"by_pack": [{"pack", "title", "count"}],
                      "busiest_session": {"project", "files", "tool_calls"}|null},
     "projects": [{"name", "sessions", "estimated_usd", "tool_calls", "deny", "ask",
                   "first", "last"}]}
"""

from __future__ import annotations

import collections
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pricing import cost_for, reliable
from .shell import command_shape

# `_message_id` is private because nothing outside the spend path had a reason to ask "which
# call is this", and re-deriving the answer here would be a second copy of a rule that decides
# whether a streamed reply is charged once or eleven times. It is imported rather than copied.
# `transcript.py` is vendored verbatim into the zero-install plugin, so it is not renamed.
from .transcript import ESTIMATE_CAVEAT, _message_id

#: Version of the `--json` document. Consumers pin on this, so a change of shape changes it.
SCHEMA = "provenrail.report/1"

#: Where Claude Code keeps its transcripts. One directory per project, one `.jsonl` per session.
DEFAULT_ROOT = Path.home() / ".claude" / "projects"

#: Lines worth handing to a JSON parser. Everything else in a transcript is host bookkeeping
#: (mode changes, titles, queue operations) that carries neither money nor a tool call, and on
#: a 3.5 GB corpus the difference between testing a substring and parsing the line is minutes.
_INTERESTING = ('"assistant"', "tool_use", "tool_result")

#: A worktree is the same project as the repo it was cut from. Folding them together keeps one
#: feature branch from reading as its own project in the per-project table.
_WORKTREE_MARKER = "/.claude/worktrees/"

#: How many rows the human output prints for each "top N" table. Long enough to see a pattern,
#: short enough that the whole report is a screenshot.
_TOP = 8


def _fold_worktree(cwd: str) -> str:
    return cwd.split(_WORKTREE_MARKER, 1)[0] if _WORKTREE_MARKER in cwd else cwd


def share_label(name: str) -> str:
    """A project's name replaced by a stable hash of it, the way `guard.card` hashes a repo.

    Two reports from the same project agree on the label without either of them naming it, and
    a project name is frequently a client's name, which is the single most identifying thing in
    the whole corpus.
    """
    return "project-" + hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:8]


@dataclass
class SessionStats:
    """One host session. Keyed on the id the transcript reports, not on the file.

    A forked session is a second file carrying a copy of the first one's history, so counting
    files would report sessions that were never held and would count their cost twice.
    """

    session_id: str
    project: str = ""
    first: str = ""
    last: str = ""
    cost_usd: float = 0.0
    tool_calls: int = 0
    bash_commands: int = 0
    deny: int = 0
    ask: int = 0
    #: Hashes of the file paths written or edited, never the paths. The question is "how many
    #: distinct files did this session touch", and holding 3.5 GB worth of real paths in memory
    #: to answer a count is both slower and a pile of the user's filenames we did not need.
    files_written: set[int] = field(default_factory=set)
    #: tool_use ids that never got a result. A session that still has one when the transcript
    #: ends stopped in the middle of a tool call rather than finishing.
    pending: set[str] = field(default_factory=set)

    def see(self, stamp: str) -> None:
        if not stamp:
            return
        if not self.first or stamp < self.first:
            self.first = stamp
        if stamp > self.last:
            self.last = stamp


@dataclass
class Report:
    """Everything the render functions are allowed to know. No file handles, no policy."""

    root: str = ""
    since: str = ""
    project_filter: str = ""
    transcripts: int = 0
    unreadable_transcripts: int = 0
    unreadable_lines: int = 0
    bytes_read: int = 0
    skipped_by_since: int = 0
    seconds: float = 0.0
    estimated_usd: float = 0.0
    model_calls: int = 0
    unpriced_calls: int = 0
    duplicate_calls: int = 0
    by_model: collections.Counter[str] = field(default_factory=collections.Counter)
    model_cost: dict[str, float] = field(default_factory=dict)
    unpriced_models: set[str] = field(default_factory=set)
    by_tool: collections.Counter[str] = field(default_factory=collections.Counter)
    #: Every Bash command reduced to its verb and flags. Kept instead of the commands because
    #: this table is printed in the shareable report, and an operand is where a secret lives.
    bash_shapes: collections.Counter[str] = field(default_factory=collections.Counter)
    screened: int = 0
    deny: int = 0
    ask: int = 0
    by_rule: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    by_shape: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    sessions: dict[str, SessionStats] = field(default_factory=dict)

    @property
    def tool_calls(self) -> int:
        return sum(self.by_tool.values())

    @property
    def bash_commands(self) -> int:
        return sum(s.bash_commands for s in self.sessions.values())

    @property
    def files_written(self) -> int:
        seen: set[int] = set()
        for session in self.sessions.values():
            seen |= session.files_written
        return len(seen)

    @property
    def abandoned(self) -> int:
        return sum(1 for s in self.sessions.values() if s.pending)

    @property
    def first(self) -> str:
        stamps = [s.first for s in self.sessions.values() if s.first]
        return min(stamps) if stamps else ""

    @property
    def last(self) -> str:
        stamps = [s.last for s in self.sessions.values() if s.last]
        return max(stamps) if stamps else ""


def _usage_of(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    usage = message.get("usage")
    if not isinstance(usage, dict) or not usage:
        return None
    return message, usage


def _transcripts(root: Path, since: str) -> tuple[list[Path], int]:
    """The files to read, and how many `--since` let us skip without opening them.

    A transcript is appended to, so its mtime is the time of its LAST line: one last written
    before the cutoff cannot hold a line after it. A file copied onto the machine gets a newer
    mtime, which only means it is opened and then filtered line by line, so the shortcut can
    only ever skip files that had nothing to contribute.
    """
    keep: list[Path] = []
    skipped = 0
    cutoff = 0.0
    if since:
        try:
            cutoff = time.mktime(time.strptime(since[:10], "%Y-%m-%d"))
        except ValueError as exc:
            raise ValueError(f"--since must be a date like 2026-09-01, not {since!r}") from exc
    for path in sorted(root.rglob("*.jsonl")):
        if cutoff:
            try:
                if path.stat().st_mtime < cutoff:
                    skipped += 1
                    continue
            except OSError:
                pass       # unreadable stat is not evidence of age; open it and find out
        keep.append(path)
    return keep, skipped


def scan(root: Path, policy: Any, since: str = "", project: str = "") -> Report:
    """Read every transcript under `root` once and answer all four questions from that pass.

    `policy` is a real `Policy` from the real catalogue, and every tool call is replayed through
    `guard.decide` with the `cwd` the transcript recorded, exactly as `tools/measure_guard.py`
    does. The working directory is half the input: `rm -rf .next` is a build step inside one
    project and something else entirely outside one, and a replay that drops it measures a
    guard nobody is running.
    """
    from . import guard

    started = time.time()
    report = Report(root=str(root), since=since, project_filter=project)
    paths, report.skipped_by_since = _transcripts(root, since)

    # Charged across the whole corpus, not per file, because a forked session is a second file
    # holding a copy of the first one's model calls. Per-file totals would bill them twice.
    charged: dict[str, float] = {}
    needle = project.lower()

    for path in paths:
        session: SessionStats | None = None
        readable = True
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            report.unreadable_transcripts += 1
            continue
        with handle:
            report.transcripts += 1
            for line in handle:
                report.bytes_read += len(line)
                if not any(marker in line for marker in _INTERESTING):
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    # A line we cannot read held a model call we cannot price and possibly a
                    # tool call we cannot screen. Skipping it silently would report a smaller,
                    # cleaner corpus than the one on disk.
                    report.unreadable_lines += 1
                    readable = False
                    continue
                if not isinstance(record, dict):
                    report.unreadable_lines += 1
                    readable = False
                    continue

                cwd = _fold_worktree(str(record.get("cwd") or ""))
                if session is None:
                    session = _session_for(report, record, path, cwd)
                    if needle and needle not in session.project.lower():
                        break
                elif cwd and not session.project:
                    session.project = Path(cwd).name or cwd
                stamp = str(record.get("timestamp") or "")
                if since and stamp and stamp[:10] < since[:10]:
                    continue
                session.see(stamp)

                if record.get("type") == "assistant":
                    _price(report, session, record, charged)
                _tools(report, session, record, policy, cwd, guard)
        if not readable:
            report.unreadable_transcripts += 1

    report.seconds = round(time.time() - started, 3)
    return report


def _session_for(report: Report, record: dict[str, Any], path: Path, cwd: str) -> SessionStats:
    """The session this file belongs to, created on first sight.

    The id comes from the transcript when it has one and from the filename when it does not,
    which is the same identity Claude Code uses. The project name comes from the recorded
    working directory rather than from the encoded directory name, because that name is a path
    with its separators replaced and splitting it back apart is guesswork.
    """
    session_id = str(record.get("sessionId") or record.get("session_id") or path.stem)
    session = report.sessions.get(session_id)
    if session is None:
        project = Path(cwd).name if cwd else path.parent.name
        session = SessionStats(session_id=session_id, project=project or path.parent.name)
        report.sessions[session_id] = session
    return session


def _price(report: Report, session: SessionStats, record: dict[str, Any],
           charged: dict[str, float]) -> None:
    """Add one assistant line's cost, charging each model call exactly once.

    A streamed message is written to the transcript several times as it grows, each copy sharing
    `message.id` and the last one carrying the final usage, so the largest figure seen for an id
    wins and only the increase is added. The same rule deduplicates the copy of a call that a
    forked session carries into a second file.
    """
    found = _usage_of(record)
    if found is None:
        return
    message, usage = found
    model = str(message.get("model") or "")
    priced = cost_for(model, usage)
    cost = float(priced.get("cost_usd", 0.0) or 0.0)
    key = _message_id(record, message, report.model_calls)
    already = charged.get(key)
    if already is None:
        report.model_calls += 1
        report.by_model[model or "(no model reported)"] += 1
        if not reliable(priced):
            # Unpriced is not free. It is counted and named so the total below it can be read
            # as the floor it is.
            report.unpriced_calls += 1
            report.unpriced_models.add(model or "(no model reported)")
    else:
        report.duplicate_calls += 1
    delta = cost if already is None else max(0.0, cost - already)
    charged[key] = max(already or 0.0, cost)
    report.estimated_usd = round(report.estimated_usd + delta, 6)
    report.model_cost[model or "(no model reported)"] = round(
        report.model_cost.get(model or "(no model reported)", 0.0) + delta, 6)
    session.cost_usd = round(session.cost_usd + delta, 6)


def _tools(report: Report, session: SessionStats, record: dict[str, Any], policy: Any,
           cwd: str, guard: Any) -> None:
    """Count and screen every tool call on this line, and resolve the ones that came back."""
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return
    for block in content:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "tool_result":
            session.pending.discard(str(block.get("tool_use_id") or ""))
            continue
        if kind != "tool_use":
            continue
        tool = str(block.get("name") or "")
        args = block.get("input")
        if not isinstance(args, dict):
            args = {}
        session.pending.add(str(block.get("id") or ""))
        session.tool_calls += 1
        report.by_tool[tool or "(unnamed tool)"] += 1
        command = args.get("command")
        if tool == "Bash" and isinstance(command, str):
            session.bash_commands += 1
            report.bash_shapes[command_shape(command) or "(empty command)"] += 1
        for key in ("file_path", "notebook_path"):
            target = args.get(key)
            if isinstance(target, str) and target:
                # Hashed, not kept: the answer wanted is "how many distinct files", and the
                # paths themselves are the user's filenames, which this never needs to hold.
                session.files_written.add(hash(target))
        payload = {"command": command} if tool == "Bash" and isinstance(command, str) else args
        decision = guard.decide(policy, tool, payload, None, cwd)
        report.screened += 1
        verdict = str(decision.get("verdict") or "allow")
        if verdict == "allow":
            continue
        rule = str(decision.get("rule") or "(unnamed rule)")
        report.by_rule[(rule, verdict)] += 1
        # `decide` already reduced the matched command for us and returns "" for a tool that
        # carries no command. Falling back to the tool name keeps a Write or an MCP call in the
        # table instead of filing it under a blank.
        report.by_shape[(str(decision.get("shape") or "") or tool or "(unnamed tool)",
                         verdict)] += 1
        if verdict == "deny":
            report.deny += 1
            session.deny += 1
        else:
            report.ask += 1
            session.ask += 1


# ---------------------------------------------------------------- shaping the answer


def _projects(report: Report) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for session in report.sessions.values():
        row = rows.setdefault(session.project or "(no working directory recorded)",
                              {"name": session.project, "sessions": 0, "estimated_usd": 0.0,
                               "tool_calls": 0, "deny": 0, "ask": 0, "first": "", "last": ""})
        row["sessions"] += 1
        row["estimated_usd"] = round(row["estimated_usd"] + session.cost_usd, 6)
        row["tool_calls"] += session.tool_calls
        row["deny"] += session.deny
        row["ask"] += session.ask
        if session.first and (not row["first"] or session.first < row["first"]):
            row["first"] = session.first
        if session.last > row["last"]:
            row["last"] = session.last
    return sorted(rows.values(), key=lambda r: (-r["estimated_usd"], -r["tool_calls"]))


def _packs(report: Report) -> list[dict[str, Any]]:
    """Blast radius, grouped by the pack whose rules fired.

    The categories are not a second list written here. "Deletions" and "git operations that
    discard work" are already defined, once, as the `destructive` and `git-worktree` packs in
    `rulesets.CATALOG`, and a category invented in this file would drift away from them the
    first time a rule moved.
    """
    from . import rulesets

    counts: collections.Counter[str] = collections.Counter()
    for (rule, _verdict), count in report.by_rule.items():
        counts[rule.split(".", 1)[0]] += count
    out = []
    for pack, count in counts.most_common():
        title = (rulesets.CATALOG.get(pack) or {}).get("title") or pack
        out.append({"pack": pack, "title": title, "count": count})
    return out


def hides_names(report: Report, share: bool) -> bool:
    """Whether project names are replaced by a hash of themselves.

    `--share` hides them, with one exception: `--project NAME` means the user typed that name
    and asked for a report about it, so printing it back tells nobody anything the user did not
    already choose to say.
    """
    return share and not report.project_filter


def _busiest(report: Report, share: bool) -> dict[str, Any] | None:
    """The session that touched the most distinct files.

    An average hides the one run that rewrote four hundred files, and that run is the whole
    reason anyone wants a blast-radius number at all.
    """
    if not report.sessions:
        return None
    session = max(report.sessions.values(), key=lambda s: (len(s.files_written), s.tool_calls))
    if not session.files_written:
        return None
    return {"project": share_label(session.project) if hides_names(report, share)
            else session.project,
            "files": len(session.files_written), "tool_calls": session.tool_calls}


def as_json(report: Report, share: bool = False) -> dict[str, Any]:
    """The same figures as the human output, in the shape documented at the top of this file."""
    by_model = []
    for model, calls in report.by_model.most_common():
        priced = model not in report.unpriced_models
        by_model.append({"model": model, "calls": calls,
                         "estimated_usd": round(report.model_cost.get(model, 0.0), 6),
                         "priced": priced})
    hide = hides_names(report, share)
    projects = []
    for row in _projects(report):
        row = dict(row)
        row["name"] = share_label(row["name"]) if hide else row["name"]
        projects.append(row)
    return {
        "schema": SCHEMA,
        # The root is a path on the user's machine, so the shareable document does not carry it.
        "root": None if share else report.root,
        "since": report.since or None,
        "share": share,
        "read": {"transcripts": report.transcripts,
                 "unreadable_transcripts": report.unreadable_transcripts,
                 "unreadable_lines": report.unreadable_lines,
                 "bytes": report.bytes_read,
                 "skipped_by_since": report.skipped_by_since,
                 "seconds": report.seconds},
        "cost": {"estimated_usd": round(report.estimated_usd, 2),
                 "caveat": ESTIMATE_CAVEAT,
                 "model_calls": report.model_calls,
                 "unpriced_calls": report.unpriced_calls,
                 "duplicate_calls": report.duplicate_calls,
                 "by_model": by_model},
        "activity": {"sessions": len(report.sessions),
                     "first": report.first or None,
                     "last": report.last or None,
                     "tool_calls": report.tool_calls,
                     "bash_commands": report.bash_commands,
                     "files_written": report.files_written,
                     "sessions_ended_mid_tool_call": report.abandoned,
                     "by_tool": [[tool, n] for tool, n in report.by_tool.most_common()]},
        "risk": {"screened": report.screened, "deny": report.deny, "ask": report.ask,
                 "by_rule": [{"rule": rule, "verdict": verdict, "count": n}
                             for (rule, verdict), n in report.by_rule.most_common()],
                 "by_shape": [{"shape": shape, "verdict": verdict, "count": n}
                              for (shape, verdict), n in report.by_shape.most_common(_TOP)]},
        "blast_radius": {"by_pack": _packs(report), "busiest_session": _busiest(report, share)},
        "projects": projects,
    }


# ---------------------------------------------------------------- the human output


def _money(value: float) -> str:
    return f"${value:,.2f}"


def _days(first: str, last: str) -> int:
    try:
        start = time.mktime(time.strptime(first[:10], "%Y-%m-%d"))
        end = time.mktime(time.strptime(last[:10], "%Y-%m-%d"))
    except ValueError:
        return 0
    return int(round((end - start) / 86400)) + 1


def _headline(report: Report) -> list[str]:
    """The one true sentence at the top, sized to the data it describes.

    A report on forty sessions and twelve dollars must not be laid out like a fleet dashboard.
    So the numbers are written into a sentence rather than into tiles, and the second sentence
    only exists when the guard would actually have done something.
    """
    sessions = len(report.sessions)
    projects = len({s.project for s in report.sessions.values()})
    span = _days(report.first, report.last)
    where = f"{projects} project{'' if projects == 1 else 's'}"
    when = f"over {span} day{'' if span == 1 else 's'}" if span else "in the transcripts read"
    lines = [f"  {sessions:,} session{'' if sessions == 1 else 's'} across {where}, {when}, ran "
             f"{report.tool_calls:,} tool calls",
             f"  and spent an estimated {_money(report.estimated_usd)}."]
    stopped = report.deny + report.ask
    if stopped:
        lines.append(f"  {stopped:,} of those tool calls would have been stopped: "
                     f"{report.deny:,} refused, {report.ask:,} sent to you to approve.")
    else:
        lines.append("  None of those tool calls would have been stopped by the default rules.")
    return lines


def _table(rows: list[tuple[str, str]], indent: str = "    ", width: int = 34) -> list[str]:
    return [f"{indent}{left:<{width}}{right}" for left, right in rows]


def render_text(report: Report, share: bool = False) -> str:
    """The report a person reads, and the one they screenshot.

    Plain text, aligned, no colour and nothing wider than 80 columns, because the two places
    this ends up are a terminal on somebody else's machine and an image in a post.
    """
    hide = hides_names(report, share)
    name = share_label if hide else (lambda value: value)
    out: list[str] = ["", "PROVENRAIL REPORT", ""]
    out += _headline(report)
    out.append("")

    read = [f"{report.transcripts:,} transcripts", f"{report.bytes_read / 1e9:.2f} GB",
            f"{report.seconds:.1f}s"]
    if report.since:
        read.append(f"since {report.since[:10]}")
    if report.skipped_by_since:
        read.append(f"{report.skipped_by_since:,} skipped as older")
    if not share:
        out.append(f"  read {report.root}")
    out.append("  " + ", ".join(read))
    if report.unreadable_transcripts or report.unreadable_lines:
        # Never folded into the totals as zero. A corpus that could not be fully read produces
        # a floor, and the only honest thing to do with a floor is to say it is one.
        out.append(f"  {report.unreadable_transcripts:,} transcripts had lines that could not be "
                   f"read ({report.unreadable_lines:,} lines). Everything below is a floor.")
    out.append("")

    out.append("COST")
    rows = [("estimated total", _money(report.estimated_usd)),
            ("model calls priced", f"{report.model_calls - report.unpriced_calls:,}")]
    if report.unpriced_calls:
        rows.append(("model calls with no verified rate", f"{report.unpriced_calls:,}"))
    if report.duplicate_calls:
        rows.append(("repeated calls counted once", f"{report.duplicate_calls:,}"))
    out += _table(rows)
    out.append("    by model")
    for model, calls in report.by_model.most_common(_TOP):
        amount = ("unpriced" if model in report.unpriced_models
                  else _money(report.model_cost.get(model, 0.0)))
        out.append(f"      {model[:34]:<34}{amount:>12}   {calls:,} calls")
    if report.unpriced_calls:
        out.append(f"    {report.unpriced_calls:,} calls have no verified price and add $0.00 "
                   f"to the total above.")
    out.append(f"    Spend is {ESTIMATE_CAVEAT}.")
    out.append("")

    out.append("ACTIVITY")
    out += _table([("sessions", f"{len(report.sessions):,}"),
                   ("first and last", f"{report.first[:10] or '?'} to {report.last[:10] or '?'}"),
                   ("tool calls", f"{report.tool_calls:,}"),
                   ("bash commands", f"{report.bash_commands:,}"),
                   ("files written or edited", f"{report.files_written:,} distinct"),
                   ("sessions that ended mid tool call", f"{report.abandoned:,}")])
    out.append("    tools most used")
    for tool, count in report.by_tool.most_common(_TOP):
        out.append(f"      {tool[:34]:<34}{count:>12,}")
    if report.bash_shapes:
        out.append("    bash commands most run (verb and flags only, operands dropped)")
        for shape, count in report.bash_shapes.most_common(_TOP):
            out.append(f"      {shape[:34]:<34}{count:>12,}")
    out.append("")

    out.append("RISK   your own commands, replayed offline through the shipped default rules")
    def pct(n: int) -> str:
        return f"{n / report.screened * 100:.2f}%" if report.screened else "0%"

    out += _table([("tool calls screened", f"{report.screened:,}"),
                   ("would have been refused", f"{report.deny:,}   {pct(report.deny)}"),
                   ("would have been sent to you", f"{report.ask:,}   {pct(report.ask)}")])
    if report.by_rule:
        out.append("    rules that would have fired")
        for (rule, verdict), count in report.by_rule.most_common(_TOP):
            out.append(f"      {count:>6,}  {verdict:<5} {rule}")
        out.append("    the commands behind them")
        for (shape, verdict), count in report.by_shape.most_common(_TOP):
            out.append(f"      {count:>6,}  {verdict:<5} {shape[:48]}")
    out.append("")

    out.append("BLAST RADIUS")
    packs = _packs(report)
    if packs:
        for row in packs:
            out.append(f"    {row['title'][:34]:<34}{row['count']:>12,}")
    else:
        out.append("    Nothing in the corpus would have been stopped.")
    busiest = _busiest(report, share)
    if busiest:
        out.append(f"    busiest single session: {busiest['files']:,} distinct files touched, "
                   f"{busiest['tool_calls']:,} tool calls")
        out.append(f"      in {busiest['project']}")
    out.append("")

    out.append("BY PROJECT")
    out.append(f"    {'project':<30}{'sessions':>9}{'spend':>12}{'stopped':>9}")
    for row in _projects(report)[:12]:
        stopped = row["deny"] + row["ask"]
        out.append(f"    {name(row['name'])[:30]:<30}{row['sessions']:>9,}"
                   f"{_money(row['estimated_usd']):>12}{stopped:>9,}")
    out.append("")

    if share:
        out.append("  Safe to post: no paths, no hostnames, no project names, and every command")
        out.append("  reduced to its verb and flags, so nothing here can be an operand.")
    else:
        out.append("  Shareable version, with every path and name removed:  pr report --share")
    out.append("  Stop these before they run:  claude plugin install provenrail-guard")
    out.append("")
    return "\n".join(out) + "\n"


def build(root: str | Path | None = None, since: str = "", project: str = "",
          packs: list[str] | None = None) -> Report:
    """Scan a transcript tree with the rules the plugin actually ships with.

    The packs are `guard.DEFAULT_PACKS`, not a list written here, so the risk figures describe
    the guard a reader would get by installing it rather than a configuration only this report
    knows about.
    """
    from . import guard
    from .easy import load_policy

    target = Path(root) if root else DEFAULT_ROOT
    if not target.is_dir():
        raise FileNotFoundError(
            f"no transcripts at {target}. Claude Code keeps them in ~/.claude/projects; "
            f"pass the directory as an argument if yours are somewhere else.")
    policy = load_policy({"use": list(packs or guard.DEFAULT_PACKS)})
    return scan(target, policy, since=since, project=project)
