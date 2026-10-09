"""`pr brief`: what a coding agent did in this repository, for the person who has to review it.

A reviewer handed a large agent-written diff has the result and none of the history. This module
rebuilds the history from facts recorded locally while the agent worked: the working-tree
checkpoints taken before every action that can write (which see changes made by shell commands
too, on every host), and the guard's journal of what was stopped or questioned. It never reads
the agent's own account of itself, because that is the one source that cannot be checked.

The brief states facts and names what to check. It does not accuse, and it does not claim that
tests pass.
"""

from __future__ import annotations

import fnmatch
import json
import sys
import time
from pathlib import Path
from typing import Any

from . import checkpoint, guard, localstate

SCHEMA = "provenrail.brief/1"

#: How many changed paths the markdown lists before it says how many it left out. A brief that
#: lists three thousand paths is the diff again; `--json` carries every one for anything that
#: wants them all.
MAX_PATHS_LISTED = 60

#: How many shell commands and how many reverted paths are listed, for the same reason.
MAX_COMMANDS_LISTED = 30
MAX_REVERTED_LISTED = 30

#: Per-category cap on flagged paths, so one category (a vendored lockfile tree, say) cannot
#: push the other categories off the page.
MAX_FLAGGED_PER_CATEGORY = 15

#: The one place root-level files are grouped when a path has no directory part.
ROOT_GROUP = "(repository root)"

#: Seconds in a minute and an hour, for the duration line.
_MINUTE = 60
_HOUR = 3600

#: The shell tool name. The hosts module already maps every host's shell tool to this one.
SHELL_TOOL = "Bash"

#: Sensitive categories: (category, why a reviewer should look, glob patterns). A pattern with
#: no "/" matches a file name anywhere in the tree. A pattern with a "/" matches the path from
#: the repository root, or from any directory below it. Matching ignores case. A path may fall
#: in more than one category; it is listed under each, because each reason is a separate
#: question for the reviewer.
SENSITIVE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Dependency manifests and lockfiles",
     "A new or changed dependency runs with the project's permissions on every machine that "
     "installs it. Check each added package is intended and is the package it appears to be.",
     ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
      "bun.lock", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock",
      "requirements*.txt", "setup.py", "setup.cfg", "Cargo.toml", "Cargo.lock", "go.mod",
      "go.sum", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "pom.xml",
      "build.gradle", "build.gradle.kts", "Package.swift", "Package.resolved", "Podfile",
      "Podfile.lock")),
    ("Database migrations and schema",
     "Migrations change data that is hard to get back and can lock tables in production. Check "
     "ordering, reversibility, and that nothing drops or rewrites data unintentionally.",
     ("migrations/*", "migrate/*", "alembic/*", "drizzle/*", "prisma/*", "schema.prisma",
      "schema.rb", "structure.sql", "schema.sql", "*.sql")),
    ("Authentication, sessions and permissions",
     "Mistakes here are quiet: the code works and the wrong person can also use it. Read the "
     "change as an attacker would.",
     ("auth/*", "authn/*", "authz/*", "authentication/*", "authorization/*", "permissions/*",
      "sessions/*", "oauth/*", "auth.*", "auth_*", "*_auth.*", "*-auth.*", "*authn*",
      "*authz*", "*oauth*", "*session*", "*permission*", "*rbac*", "*jwt*", "*password*",
      "login.*", "*_login.*")),
    ("CI and deploy configuration",
     "This decides what runs on the build servers and what reaches production, often with "
     "secrets in scope. Check for new steps, changed triggers and widened permissions.",
     (".github/workflows/*", ".github/actions/*", ".gitlab-ci.yml", ".circleci/*",
      ".buildkite/*", "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml",
      "cloudbuild.yaml", "wrangler.toml", "wrangler.json", "wrangler.jsonc", "vercel.json",
      "netlify.toml", "fly.toml", "render.yaml", "Procfile", "app.yaml")),
    ("Infrastructure",
     "Infrastructure files change real resources and their exposure. Check ports, public "
     "access, privileged containers and anything that creates or destroys a resource.",
     ("*.tf", "*.tfvars", "terraform/*", "k8s/*", "kubernetes/*", "helm/*", "charts/*",
      "ansible/*", "Dockerfile", "Dockerfile.*", "*.dockerfile", "docker-compose*.yml",
      "docker-compose*.yaml", "compose.yml", "compose.yaml", "Pulumi.*", "cdk.json")),
    ("Secrets and environment files",
     "Credentials committed to a repository are public to everyone who ever clones it. Check "
     "that no real value is present and that none was read out of an existing file.",
     (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "id_rsa", "id_ed25519",
      "credentials*", "secrets*", "*.tfstate")),
    ("Licence files",
     "A licence change alters what other people may legally do with the code. Nobody should "
     "change it as a side effect.",
     ("LICENSE", "LICENSE.*", "LICENSE-*", "LICENCE", "LICENCE.*", "COPYING", "COPYING.*",
      "NOTICE", "NOTICE.*", "UNLICENSE")),
    ("Agent and editor configuration",
     "These files steer what the next agent session may do, including its permissions, tools "
     "and instructions. A change here outlives this session.",
     (".claude/*", ".cursor/*", ".cursorrules", ".windsurf/*", ".windsurfrules", ".codex/*",
      ".gemini/*", ".aider*", ".vscode/*", ".idea/*", ".mcp.json", "AGENTS.md", "CLAUDE.md",
      "GEMINI.md", ".github/copilot-instructions.md", ".github/workflows/*",
      ".provenrail.json")),
)

#: What counts as a test file. Directory patterns match a directory anywhere in the path.
TEST_PATTERNS: tuple[str, ...] = (
    "tests/*", "test/*", "__tests__/*", "spec/*", "e2e/*", "test_*.py", "*_test.py",
    "*_test.go", "*.test.*", "*.spec.*", "*Test.java", "*Tests.swift", "*Test.kt",
    "*_spec.rb", "*_test.rb", "conftest.py",
)

#: What the brief cannot see. Fixed and short on purpose: a reviewer should be able to rely on
#: this list being the same on every brief.
NOT_COVERED = (
    "Files that git ignores. They are not in the checkpoints, except `.env` files, which are.",
    "Anything outside this repository: other directories, services, databases, the network.",
    "Files over the size cap ({cap} MB) are recorded as skipped, not compared.",
    "Whether the tests pass. This brief does not run them and does not claim they do.",
)


# ---------------------------------------------------------------- text helpers


def _ascii(text: Any) -> str:
    """Plain printable ASCII, so the brief pastes into any PR box and renders everywhere.

    A file name can hold any character the file system allows, including newlines and
    backticks that would break out of a markdown code span. They are replaced, not dropped, so
    two different names do not collapse into one.
    """
    raw = str(text).encode("ascii", "backslashreplace").decode("ascii")
    return "".join(ch if " " <= ch <= "~" and ch != "`" else "?" for ch in raw)


def _code(text: Any) -> str:
    return f"`{_ascii(text)}`"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _clock(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp))


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= _HOUR:
        return f"{seconds // _HOUR} h {seconds % _HOUR // _MINUTE} min"
    if seconds >= _MINUTE:
        return f"{seconds // _MINUTE} min"
    return f"{seconds} s"


# ---------------------------------------------------------------- classification


def _match(path: str, pattern: str) -> bool:
    path, pattern = path.lower(), pattern.lower()
    if "/" not in pattern:
        return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pattern)
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, "*/" + pattern)


def _is_test(path: str) -> bool:
    return any(_match(path, pattern) for pattern in TEST_PATTERNS)


def sensitive_categories(path: str) -> list[str]:
    """The names of every sensitive category this path falls in."""
    return [name for name, _, patterns in SENSITIVE
            if any(_match(path, pattern) for pattern in patterns)]


def _flag(net: list[tuple[str, str]]) -> dict[str, Any]:
    """Sensitive paths by category, deleted tests, and tests edited beside source changes."""
    by_category: dict[str, list[dict[str, str]]] = {name: [] for name, _, _ in SENSITIVE}
    for status, path in net:
        for name in sensitive_categories(path):
            by_category[name].append({"status": status, "path": path})
    categories = [{"category": name, "reason": reason, "paths": by_category[name]}
                  for name, reason, _ in SENSITIVE if by_category[name]]
    deleted_tests = [p for s, p in net if s == "D" and _is_test(p)]
    # Only a MODIFIED test next to a changed non-test file is worth a line. A new test beside
    # new code is the expected shape, and listing it would bury the one that matters.
    source_touched = any(s in ("A", "M") and not _is_test(p) for s, p in net)
    edited_tests = [p for s, p in net if s == "M" and _is_test(p)] if source_touched else []
    return {"categories": categories, "deleted_tests": deleted_tests,
            "edited_tests_with_source": edited_tests}


def _normalise(status: str) -> str:
    # A type change (file to symlink or back) is a modification as far as a reviewer cares.
    return "M" if status == "T" else status


# ---------------------------------------------------------------- transcript cost


def _transcript_cost(session: str) -> dict[str, Any] | None:
    """What the host's transcript says this session cost, or None when that cannot be known.

    None means unknown and is never rendered as zero. The estimate reuses the guard's own
    transcript pricing so the figure here and the figure a spend cap acted on cannot differ.
    """
    if not session:
        return None
    from . import report, transcript
    try:
        found = sorted(Path(report.DEFAULT_ROOT).glob(f"*/{session}.jsonl"))
    except OSError:
        return None
    if not found:
        return None
    try:
        _, _, state = transcript.accrue(found[0])
    except Exception:
        return None
    if not state.known:
        return None
    return {"usd": round(state.session_usd, 2), "unpriced_calls": state.unpriced_calls,
            "caveat": transcript.ESTIMATE_CAVEAT}


# ---------------------------------------------------------------- build


def _scope(log: list[dict[str, Any]], session: str, since: int, all_sessions: bool
           ) -> tuple[list[dict[str, Any]], str]:
    """The checkpoints in scope, and the reason when there are none."""
    entries = list(log)
    if session:
        entries = [e for e in entries if str(e.get("session", "")).startswith(session)]
        if not entries:
            return [], f"no checkpoints belong to a session starting with `{_ascii(session)}`"
    elif not all_sessions and entries:
        latest = entries[-1].get("session", "")
        entries = [e for e in entries if e.get("session", "") == latest]
    if since:
        entries = [e for e in entries if e["n"] >= since]
        if not entries:
            return [], f"no checkpoint in scope has number {since} or higher"
    return entries, ""


def build(root: Any, session: str = "", since: int = 0, all_sessions: bool = False
          ) -> dict[str, Any]:
    """The brief as plain data. JSON-serialisable, and the same data `render` draws from."""
    root = Path(root)
    log = checkpoint.read_log(root)
    scope, why = _scope(log, session, since, all_sessions)
    if not scope:
        return {"schema": SCHEMA, "empty": True,
                "reason": why or "there are no checkpoints for this repository yet"}

    now_tree = checkpoint.current_tree(root)
    rows = checkpoint.describe(root, scope, now_tree)
    undos = [r for r in rows if r.get("tool") == checkpoint.UNDO_TOOL]
    actions = [r for r in rows if r.get("tool") != checkpoint.UNDO_TOOL]

    net_raw = checkpoint.changes(root, scope[0]["tree"], now_tree)
    net = sorted((_normalise(s), p) for s, p in net_raw)
    net_paths = {p for _, p in net}

    # Every path any single action changed, minus the paths that are still different now. What
    # is left was changed and then put back, which no diff of the final state can show.
    ever: set[str] = set()
    unknown_effects = 0
    for row in rows:
        if row["changed"] is None:
            unknown_effects += 1
            continue
        ever.update(p for _, p in row["changed"])
    reverted = sorted(ever - net_paths)

    commands = []
    for row in actions:
        changed = row["changed"]
        if row.get("tool") != SHELL_TOOL or not changed:
            continue
        counts = {"added": 0, "modified": 0, "deleted": 0}
        for status, _ in changed:
            counts[{"A": "added", "D": "deleted"}.get(_normalise(status), "modified")] += 1
        commands.append({"n": row["n"], "at": row.get("at"), "shape": row.get("label", ""),
                         **counts, "files": len(changed)})

    sessions = sorted({str(e.get("session", "")) for e in scope})
    first_at, last_at = scope[0].get("at", 0), scope[-1].get("at", 0)
    journal_rows = []
    for entry in guard.read_journal():
        if entry.get("verdict") not in ("deny", "ask"):
            continue
        if str(entry.get("session_id", "")) not in sessions:
            continue
        if since and entry.get("at", 0) < first_at:
            continue
        journal_rows.append({
            "at": entry.get("at"), "verdict": entry["verdict"], "rule": entry.get("rule") or "",
            "shape": entry.get("shape") or entry.get("tool") or "",
            "remote": entry.get("remote") or "",
            "supervisor": str(entry.get("rule") or "").startswith("supervisor."),
        })

    skipped = []
    for row in scope:
        for item in row.get("skipped_large") or []:
            if item not in skipped:
                skipped.append(item)

    # Cost covers a whole session's transcript, so it is only stated when the brief covers
    # exactly one whole session: a `--since` or `--all` brief would attach it to the wrong span.
    cost = _transcript_cost(sessions[0]) if len(sessions) == 1 and not since else None

    data: dict[str, Any] = {
        "schema": SCHEMA, "empty": False,
        "scope": {"sessions": sessions, "since": since, "all": bool(all_sessions),
                  "first_checkpoint": scope[0]["n"], "last_checkpoint": scope[-1]["n"]},
        "hosts": sorted({str(e.get("host", "")) for e in scope if e.get("host")}),
        "start": first_at, "end": last_at, "actions": len(actions),
        "net": [{"status": s, "path": p} for s, p in net],
        "counts": {"added": sum(1 for s, _ in net if s == "A"),
                   "modified": sum(1 for s, _ in net if s == "M"),
                   "deleted": sum(1 for s, _ in net if s == "D")},
        "reverted": reverted,
        "unknown_effects": unknown_effects,
        "flags": _flag(net),
        "commands": commands,
        "journal": journal_rows,
        "undos": [{"n": r["n"], "at": r.get("at"), "to": r.get("to")} for r in undos],
        "skipped_large": skipped,
        "max_file_mb": checkpoint.MAX_FILE_BYTES // (1024 * 1024),
    }
    if cost is not None:
        data["cost"] = cost
    return data


# ---------------------------------------------------------------- render


def _counts_phrase(counts: dict[str, int]) -> str:
    return f"{counts['added']} added, {counts['modified']} modified, {counts['deleted']} deleted"


def _header(data: dict[str, Any]) -> str:
    scope = data["scope"]
    ids = [s[:8] or "(none)" for s in scope["sessions"]]
    who = ", ".join(data["hosts"]) or "unknown host"
    session = ids[0] if len(ids) == 1 else f"{len(ids)} sessions"
    length = _duration(data["end"] - data["start"])
    span = f"{_clock(data['start'])} to {_clock(data['end'])} ({length})"
    return (f"Host {who}, session {session}, {span}, "
            f"{_plural(data['actions'], 'action')} that could write.")


def _grouped(net: list[dict[str, str]]) -> list[tuple[str, list[dict[str, str]]]]:
    groups: dict[str, list[dict[str, str]]] = {}
    for item in net:
        top = item["path"].split("/", 1)[0] if "/" in item["path"] else ROOT_GROUP
        groups.setdefault(top, []).append(item)
    return sorted(groups.items(), key=lambda kv: (kv[0] == ROOT_GROUP, kv[0]))


def _what_changed(data: dict[str, Any]) -> list[str]:
    net = data["net"]
    lines = ["## What changed", ""]
    if not net:
        lines.append("Net change from the first checkpoint to the working tree now: none.")
    else:
        lines.append(f"Net change from the first checkpoint to the working tree now: "
                     f"{_counts_phrase(data['counts'])}.")
        lines.append("")
        budget = MAX_PATHS_LISTED
        for top, items in _grouped(net):
            if budget <= 0:
                break
            label = top if top == ROOT_GROUP else top + "/"
            lines.append(f"- {_code(label) if top != ROOT_GROUP else label} "
                         f"({_plural(len(items), 'file')})")
            for item in items[:budget]:
                lines.append(f"  - {item['status']} {_code(item['path'])}")
            budget -= min(budget, len(items))
        omitted = len(net) - min(len(net), MAX_PATHS_LISTED)
        if omitted:
            lines += ["", f"{omitted} more paths not listed; `pr brief --json` lists all of them."]
    reverted = data["reverted"]
    lines += ["", "### Touched and reverted", ""]
    if reverted:
        lines.append("Changed during this scope and then put back, so they are absent from the "
                     "diff:")
        lines.append("")
        lines += [f"- {_code(p)}" for p in reverted[:MAX_REVERTED_LISTED]]
        if len(reverted) > MAX_REVERTED_LISTED:
            lines.append(f"- {len(reverted) - MAX_REVERTED_LISTED} more not listed")
    else:
        lines.append("None.")
    if data["unknown_effects"]:
        lines += ["", f"The effect of {_plural(data['unknown_effects'], 'action')} could not be "
                  "read from the checkpoint store, so this list may be incomplete."]
    return lines


def _careful(data: dict[str, Any]) -> list[str]:
    flags = data["flags"]
    lines = ["## Needs a careful look", ""]
    if not (flags["categories"] or flags["deleted_tests"] or flags["edited_tests_with_source"]):
        return lines + ["Nothing in the net change matches a sensitive category."]
    for entry in flags["categories"]:
        lines.append(f"**{entry['category']}.** {entry['reason']}")
        lines.append("")
        for item in entry["paths"][:MAX_FLAGGED_PER_CATEGORY]:
            lines.append(f"- {item['status']} {_code(item['path'])}")
        extra = len(entry["paths"]) - MAX_FLAGGED_PER_CATEGORY
        if extra > 0:
            lines.append(f"- {extra} more not listed")
        lines.append("")
    if flags["deleted_tests"]:
        lines += ["**Test files deleted.** Check each deletion is intended and its coverage "
                  "lives somewhere else.", ""]
        lines += [f"- D {_code(p)}" for p in flags["deleted_tests"][:MAX_FLAGGED_PER_CATEGORY]]
        lines.append("")
    if flags["edited_tests_with_source"]:
        lines += ["**Test files modified in the same change as non-test files.** This is "
                  "common and usually right. Check the test edits follow the new behaviour and "
                  "do not just loosen an assertion to fit it.", ""]
        lines += [f"- M {_code(p)}"
                  for p in flags["edited_tests_with_source"][:MAX_FLAGGED_PER_CATEGORY]]
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _shell(data: dict[str, Any]) -> list[str]:
    lines = ["## Shell commands that changed files", ""]
    commands = data["commands"]
    if not commands:
        return lines + ["None. No shell command changed a file in this scope."]
    lines += ["Only the command's shape is recorded (verb and flags), never its operands. "
              "These changes appear in no diff of what each command was asked to do.", ""]
    for cmd in commands[:MAX_COMMANDS_LISTED]:
        lines.append(f"- {_code(cmd['shape'] or '(unrecorded)')}: "
                     f"{_plural(cmd['files'], 'file')} ({cmd['added']} added, "
                     f"{cmd['modified']} modified, {cmd['deleted']} deleted)")
    if len(commands) > MAX_COMMANDS_LISTED:
        lines.append(f"- {len(commands) - MAX_COMMANDS_LISTED} more not listed")
    return lines


def _remote_phrase(remote: str) -> str:
    return {"approve": "approved from the phone", "deny": "denied from the phone",
            "timeout": "phone did not answer in time", "error": "phone could not be reached",
            }.get(remote, "no phone answer recorded")


def _stopped(data: dict[str, Any]) -> list[str]:
    lines = ["## Stopped or questioned", ""]
    journal, undos = data["journal"], data["undos"]
    if not journal and not undos:
        return lines + ["Nothing was denied or questioned, and no undo was performed."]
    for item in journal:
        kind = "denied" if item["verdict"] == "deny" else "asked"
        source = " (supervisor)" if item["supervisor"] else ""
        tail = f", {_remote_phrase(item['remote'])}" if item["verdict"] == "ask" else ""
        lines.append(f"- {kind}{source}: rule {_code(item['rule'] or 'unknown')}, "
                     f"{_code(item['shape'] or '(no shape)')}{tail}")
    for undo in undos:
        target = f" back to checkpoint #{undo['to']}" if isinstance(undo.get("to"), int) else ""
        lines.append(f"- undo performed{target} (safety checkpoint #{undo['n']}, "
                     f"{_clock(undo['at'])})" if undo.get("at") else
                     f"- undo performed{target} (safety checkpoint #{undo['n']})")
    return lines


def _not_covered(data: dict[str, Any]) -> list[str]:
    lines = ["## Not covered", ""]
    for text in NOT_COVERED:
        lines.append("- " + text.format(cap=data["max_file_mb"]))
    skipped = data["skipped_large"]
    if skipped:
        shown = ", ".join(_code(s if isinstance(s, str) else json.dumps(s)) for s in skipped[:10])
        more = f" and {len(skipped) - 10} more" if len(skipped) > 10 else ""
        lines.append(f"- Skipped as too large in this scope: {shown}{more}.")
    return lines


def render(data: dict[str, Any]) -> str:
    """The brief as GitHub-flavoured markdown. Plain ASCII, ready to paste into a PR."""
    if data.get("empty"):
        return (f"No brief: {_ascii(data['reason'])}. Checkpoints are taken before every agent "
                "action that can write once the hook is installed (`pr guard install`).\n")
    lines = ["# Agent review brief", "", _header(data)]
    cost = data.get("cost")
    if cost:
        floor = "at least " if cost["unpriced_calls"] else ""
        lines.append(f"Cost: {floor}${cost['usd']:.2f}, {_ascii(cost['caveat'])}.")
    for section in (_what_changed, _careful, _shell, _stopped, _not_covered):
        lines += ["", *section(data)]
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------- command line


def add_arguments(parser: Any) -> None:
    parser.add_argument("--session", default="",
                        help="brief this session id (prefix) instead of the most recent one")
    parser.add_argument("--since", type=int, default=0,
                        help="start at checkpoint number N (see `pr undo`)")
    parser.add_argument("--all", action="store_true", help="cover every session in the log")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--out", default="", help="write the brief to FILE instead of stdout")


def run(args: Any, out: Any = None) -> int:
    out = out or sys.stdout
    root = localstate.find_root()
    if root is None:
        print("pr brief: not inside a git repository. Checkpoints are per repository.",
              file=sys.stderr)
        return 2
    try:
        data = build(root, session=args.session, since=args.since, all_sessions=args.all)
    except checkpoint.CheckpointError as exc:
        print(f"pr brief: {exc}", file=sys.stderr)
        return 1
    text = (json.dumps(data, indent=2) + "\n") if args.json else render(data)
    if args.out:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"pr brief: could not write {args.out} ({exc})", file=sys.stderr)
            return 2
        out.write(f"Wrote the brief to {args.out}\n")
    else:
        out.write(text)
    return 1 if data.get("empty") else 0
