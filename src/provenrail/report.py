"""What your agents already did, read off the transcripts they left behind.

A guard is insurance. It is silent until the day it is not, and a thing that has never visibly
done anything gets uninstalled long before the day it would have paid out. Meanwhile the same
machine is carrying months of transcripts of work that already happened: on the machine this
was written on, 2,129 files and 3.5 GB of them. `ccusage` reads a strict subset of those same
files, reports cost alone, and is downloaded 332,083 times a month, which is the evidence that
people will run something over that pile. So the value here is retroactive: install, run one
command, and see what the agents did over the last months, with nothing to set up and nothing
to wait for.

So this is the front door, and four things have to be true of it or it is worse than nothing.

**Offline.** There is no network call in this module or anything it reaches, and
`tests/test_report.py` asserts it by breaking the socket. A tool that reads every transcript on
the machine and then opens a connection is a tool nobody can run at work.

**Nothing is invented.** A transcript that cannot be read is counted as unread, not as empty; a
model with no verified rate is reported as unpriced, not as free. This is the same rule
`transcript.accrue` and `spend.prior_spend` already hold, and for the same reason: a total
reported on authority is acted on, so it has to say where it stops.

Where the host left its own total on a `cost-state` line, both figures are printed side by
side over exactly the sessions that have both, rather than one being reconciled into the other.
Adopting the host's number would hide a disagreement and dropping it would hide that a second
opinion existed. On the corpus this was written against the estimates here come out about 8 per
cent BELOW what Claude Code recorded for the same sessions, never above, which is the direction
a floor is supposed to miss in.

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
     "cost": {"estimated_usd", "caveat", "model_calls", "unpriced_calls", "repeat_lines_folded",
              "host_crosscheck": {"sessions", "host_recorded_usd", "estimated_here_usd"}|null,
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
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pricing import cost_for, reliable
from .shell import command_shape, segments

# `_message_id` is private because nothing outside the spend path had a reason to ask "which
# call is this", and re-deriving the answer here would be a second copy of a rule that decides
# whether a streamed reply is charged once or eleven times. It is imported rather than copied.
# `transcript.py` is vendored verbatim into the zero-install plugin, so it is not renamed.
from .transcript import ESTIMATE_CAVEAT, _message_id

#: The token counts `pricing.cost_for` reports back. `tokens_cache_write_1h` is deliberately
#: not among them: it is the long-TTL portion of `tokens_cache_write`, so adding it would count
#: those tokens twice. Only ever used to ask whether a call reported any tokens at all.
_TOKEN_KEYS = ("tokens_in", "tokens_out", "tokens_cache_read", "tokens_cache_write",
               "tokens_reasoning")

#: Version of the `--json` document. Consumers pin on this, so a change of shape changes it.
SCHEMA = "provenrail.report/1"

#: Where Claude Code keeps its transcripts. One directory per project, one `.jsonl` per session.
DEFAULT_ROOT = Path.home() / ".claude" / "projects"

#: Lines worth handing to a JSON parser. Everything else in a transcript is host bookkeeping
#: (mode changes, titles, queue operations) that carries neither money nor a tool call, and on
#: a 3.5 GB corpus the difference between testing a substring and parsing the line is minutes.
_INTERESTING = ('"assistant"', "tool_use", "tool_result", '"cost-state"')

#: Claude Code writes its own running total for a session on a `cost-state` line. It is the one
#: figure on disk that was not produced by this code, so it is the only available check on
#: whether these estimates are plausible, and it is printed rather than reconciled: silently
#: adopting the host's number would hide a disagreement, and silently ignoring it would hide
#: that a second opinion existed. Only recent sessions carry one.
_HOST_COST = "cost-state"

#: Where a segment that did not reduce to a verb is counted: the body of a heredoc feeding a
#: shell, a line of shell control flow, a bare quoted string. It is a real and large part of
#: what agents run, so it is counted, but it is kept OUT of the ranked table below it. Left in,
#: it sat second in a table people screenshot, saying nothing.
UNRECOGNISED = "(not a recognisable command)"

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
    #: Bytes on disk of every transcript opened.
    bytes_read: int = 0
    skipped_by_since: int = 0
    seconds: float = 0.0
    estimated_usd: float = 0.0
    model_calls: int = 0
    #: Assistant lines carrying usage, counted whether or not they were a new call. It is the
    #: fallback key for a line with neither a message id nor a uuid, and it has to keep rising
    #: even when nothing was charged: reusing the count of DISTINCT calls would eventually hand
    #: two different unidentified lines the same key, and the second would vanish as a repeat.
    priced_lines: int = 0
    unpriced_calls: int = 0
    #: Repeat APPEARANCES of a call, not calls. A streamed message arrives as many lines
    #: sharing one id, and a forked session's copied history repeats the whole parent. Naming
    #: this "calls" printed a number larger than the priced-call count on the line below it,
    #: which reads as more calls deduplicated than were ever priced.
    repeat_lines_folded: int = 0
    by_model: collections.Counter[str] = field(default_factory=collections.Counter)
    model_cost: dict[str, float] = field(default_factory=dict)
    unpriced_models: set[str] = field(default_factory=set)
    by_tool: collections.Counter[str] = field(default_factory=collections.Counter)
    #: Every command a Bash call would run, reduced to its verb and flags. Kept instead of the
    #: commands because this table is printed in the shareable report, and an operand is where a
    #: secret lives. Counted per segment, not per call: `cd web && npm test` is a directory
    #: change and a test run, and shaping only the first of them reported a corpus whose most
    #: used program was `cd`, which is true of the first word and false about the work.
    bash_shapes: collections.Counter[str] = field(default_factory=collections.Counter)
    screened: int = 0
    deny: int = 0
    ask: int = 0
    by_rule: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    by_shape: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    sessions: dict[str, SessionStats] = field(default_factory=dict)
    #: session id -> the total Claude Code recorded for it itself.
    host_cost: dict[str, float] = field(default_factory=dict)

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
            try:
                # The size on disk, not the length of the decoded lines: the file is opened in
                # text mode, so counting characters would quietly under-report every transcript
                # holding anything outside ASCII.
                report.bytes_read += path.stat().st_size
            except OSError:
                pass
            for line in handle:
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

                if record.get("type") == _HOST_COST:
                    _host_cost(report, record)
                    continue

                cwd = _fold_worktree(str(record.get("cwd") or ""))
                if session is None:
                    session = _session_for(report, record, path, cwd)
                    if needle and needle not in session.project.lower():
                        # Created a moment ago to learn its project name. Leaving it behind is
                        # how a filtered report still reported every session in the corpus,
                        # with the filtered ones showing zero of everything.
                        if not session.tool_calls and not session.cost_usd:
                            report.sessions.pop(session.session_id, None)
                        session = None
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


def _host_cost(report: Report, record: dict[str, Any]) -> None:
    """Remember the host's own total for a session, keeping the largest it ever reported.

    The line is rewritten as the session grows, so an earlier one is a prefix of a later one.
    """
    session_id = record.get("sessionId")
    total = record.get("totalCostUSD")
    if isinstance(session_id, str) and isinstance(total, (int, float)):
        report.host_cost[session_id] = max(report.host_cost.get(session_id, 0.0), float(total))


def _crosscheck(report: Report) -> dict[str, Any] | None:
    """What the host said, and what this said, over exactly the sessions both have a figure for.

    Comparing a subset total against the whole-corpus total would manufacture a disagreement out
    of the sessions that simply predate the host writing the line.
    """
    shared = [sid for sid in report.host_cost if sid in report.sessions]
    if not shared:
        return None
    return {"sessions": len(shared),
            "host_recorded_usd": round(sum(report.host_cost[sid] for sid in shared), 2),
            "estimated_here_usd": round(sum(report.sessions[sid].cost_usd for sid in shared), 2)}


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
    report.priced_lines += 1
    key = _message_id(record, message, report.priced_lines)
    already = charged.get(key)
    if already is None:
        report.model_calls += 1
        report.by_model[model or "(no model reported)"] += 1
        # Unpriced is not free, and is counted and named so the total below it reads as the
        # floor it is. With one exception, measured rather than assumed: a line reporting zero
        # tokens costs zero at EVERY rate, so a missing rate tells us nothing we did not
        # already know. Claude Code writes such lines under the model name `<synthetic>` for
        # assistant text it generated locally, 223 of them in the corpus this was written
        # against, and calling them unpriced declared the total uncertain by exactly zero.
        if not reliable(priced) and any(int(priced.get(k, 0) or 0) for k in _TOKEN_KEYS):
            report.unpriced_calls += 1
            report.unpriced_models.add(model or "(no model reported)")
    else:
        report.repeat_lines_folded += 1
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
            for part in segments(command):
                shape = command_shape(part)
                # A segment that reduces to nothing is a heredoc body, a bare quoted string or
                # something this is not a shell parser for. Counted under one honest label
                # rather than dropped, or the percentages below it would be about a corpus
                # smaller than the one on disk.
                report.bash_shapes[shape or UNRECOGNISED] += 1
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
        # A session whose lines never carried a cwd still has to land somewhere with a name on
        # it. Filed under a blank it read as an unnamed row in the table and, under --share, as
        # a hash of the empty string.
        name = session.project or "(no working directory recorded)"
        row = rows.setdefault(name,
                              {"name": name, "sessions": 0, "estimated_usd": 0.0,
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
                 "repeat_lines_folded": report.repeat_lines_folded,
                 "host_crosscheck": _crosscheck(report),
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


#: The report is read in a terminal on somebody else's machine and in a screenshot, and both of
#: those break at 80 columns. Every sentence goes through `_wrap`; a path does not, because
#: breaking a path makes it uncopyable and a path is the one thing here worth copying.
_WIDTH = 80


def _wrap(text: str, indent: str = "  ") -> list[str]:
    return textwrap.wrap(text, width=_WIDTH, initial_indent=indent, subsequent_indent=indent)


def _size(byte_count: int) -> str:
    """Bytes at a unit a person can read. A small corpus printed as "0.00 GB" reads as broken."""
    for unit, scale in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if byte_count >= scale:
            return f"{byte_count / scale:.2f} {unit}"
    return f"{byte_count:,} bytes"


def _plural(count: int, word: str) -> str:
    return f"{count:,} {word}" + ("" if count == 1 else "s")


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
        lines += _wrap(f"{stopped:,} of those would have been stopped: {report.deny:,} refused, "
                       f"{report.ask:,} sent to you to approve.")
    else:
        lines += _wrap("None of them would have been stopped by the default rules.")
    return lines


def _table(rows: list[tuple[str, str]], indent: str = "    ", width: int = 38) -> list[str]:
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

    read = [_plural(report.transcripts, "transcript"), _size(report.bytes_read),
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
        out += _wrap(f"{_plural(report.unreadable_transcripts, 'transcript')} had lines that "
                     f"could not be read ({_plural(report.unreadable_lines, 'line')}). "
                     f"Everything below is a floor, not a total.")
    out.append("")

    out.append("COST")
    rows = [("estimated total", _money(report.estimated_usd)),
            ("model calls priced", f"{report.model_calls - report.unpriced_calls:,}")]
    if report.unpriced_calls:
        rows.append(("model calls with no verified rate", f"{report.unpriced_calls:,}"))
    if report.repeat_lines_folded:
        rows.append(("repeat lines folded into their call", f"{report.repeat_lines_folded:,}"))
    out += _table(rows)
    out.append("    by model")
    for model, calls in report.by_model.most_common(_TOP):
        amount = ("unpriced" if model in report.unpriced_models
                  else _money(report.model_cost.get(model, 0.0)))
        out.append(f"      {model[:38]:<38}{amount:>12}   {_plural(calls, 'call')}")
    if report.unpriced_calls:
        out += _wrap("Calls with no verified price add $0.00 to the total above, which makes "
                     "it a floor.", indent="    ")
    cross = _crosscheck(report)
    if cross:
        out += _wrap(f"Claude Code recorded its own total for {cross['sessions']:,} of these "
                     f"sessions: {_money(cross['host_recorded_usd'])}, against "
                     f"{_money(cross['estimated_here_usd'])} estimated here for the same ones.",
                     indent="    ")
    out += _wrap(f"Spend is {ESTIMATE_CAVEAT}.", indent="    ")
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
        out.append(f"      {tool[:38]:<38}{count:>12,}")
    known = collections.Counter({shape: n for shape, n in report.bash_shapes.items()
                                 if shape != UNRECOGNISED})
    if known:
        out.append("    bash commands most run (verb and flags only, operands dropped)")
        for shape, count in known.most_common(_TOP):
            out.append(f"      {shape[:38]:<38}{count:>12,}")
        unknown = report.bash_shapes.get(UNRECOGNISED, 0)
        if unknown:
            out += _wrap(f"{unknown:,} of {sum(report.bash_shapes.values()):,} commands were "
                         f"shell control flow or a heredoc body rather than a program, and are "
                         f"not in that list.", indent="      ")
    out.append("")

    out.append("RISK   your own commands, replayed offline through the shipped rules")

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
            out.append(f"    {row['title'][:38]:<38}{row['count']:>12,}")
    else:
        out.append("    Nothing in the corpus would have been stopped.")
    busiest = _busiest(report, share)
    if busiest:
        out.append(f"    busiest single session: {_plural(busiest['files'], 'distinct file')} "
                   f"touched, {_plural(busiest['tool_calls'], 'tool call')}")
        out.append(f"      in {busiest['project']}")
    out.append("")

    out.append("BY PROJECT")
    out.append(f"    {'project':<30}{'sessions':>9}{'spend':>12}{'stopped':>9}")
    for row in _projects(report)[:12]:
        stopped = row["deny"] + row["ask"]
        out.append(f"    {name(row['name'])[:30]:<30}{row['sessions']:>9,}"
                   f"{_money(row['estimated_usd']):>12}{stopped:>9,}")
    out.append("")

    if share and hide:
        out += _wrap("Safe to post: no paths, no hostnames, no project names, and every "
                     "command reduced to its verb and flags, so nothing here is an operand.")
    elif share:
        # The claim has to match what was printed. With `--project` the names are the user's
        # own word, and saying "no project names" over a page that shows one is a false claim
        # in the one place the product is asking to be trusted.
        out += _wrap("Safe to post: no paths, no hostnames, and every command reduced to its "
                     "verb and flags. The only name here is the one you asked for.")
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
