"""Verifiable AI authorship attestation over a git repository.

The question this answers is the one arriving in software contracts: *which parts of this
codebase were written by an AI agent, with what, and who reviewed it.* Every published way of
answering it today is self-asserted. A `Co-authored-by:` trailer, a git note, a spreadsheet:
all of them are written by the same party the question is being asked of, all of them are
editable afterwards, and the counterparty's lawyer knows it.

What this module adds is not better detection. It is a signature and a time.

**Precisely what an attestation proves.** That this exact set of commit hashes, with these
authorship findings, was attested by the holder of this key, and (with an anchor) that the
document existed no later than a time an independent authority signed. Git commit ids are
themselves hashes of their content and history, so the document cannot be pointed at a
different tree afterwards, and it cannot be quietly rewritten after a dispute begins.

**Precisely what it does not prove.** That the underlying evidence is complete or truthful.
A developer who strips the trailer from a commit produces a commit this module will report as
human-authored, and no signature changes that. The findings are as good as their sources, and
every finding therefore carries the source it came from so a reader can weigh it rather than
trust it. This is stated in the document itself, in `limits`, because an evidence artefact
that does not say what it fails to cover is worse than none: it invites a reliance it cannot
carry.

**The one source that is not self-asserted** is a Provenrail session record: signed at the
time by the agent's own recorder, hash-chained, and (once anchored) timestamped by a third
party. A commit whose window is covered by such records is reported at a strictly higher
evidence grade, and that grade is the reason the recorder is worth installing.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonicalize, sha256_hex

SCHEMA = "provenrail.ai-attestation/1"

#: Evidence grades, weakest to strongest. A grade is a claim about the SOURCE, never about how
#: sure we are: "asserted" means a human or a tool wrote it down and could have written
#: anything, "recorded" means a signed record was produced at the time by the recorder itself.
ASSERTED = "asserted"
RECORDED = "recorded"
GRADES = (ASSERTED, RECORDED)


@dataclass(frozen=True)
class AgentSignature:
    """One way an AI coding tool leaves its name on a commit.

    Kept as data in a single table because the alternative, a detection routine per tool, is
    how the list silently stops covering the tool everyone moved to last month.
    """

    tool: str
    #: Case-insensitive regex matched against the whole commit message (trailers included).
    message: str = ""
    #: Case-insensitive regex matched against the author and committer identity lines
    #: ("Name <email>").
    identity: str = ""


# The identities the major coding agents actually write. Anything not in here reports as
# human-authored, which is the safe direction for a document whose whole purpose is to be
# relied on: an unlisted tool understates AI involvement, and understating it is a claim the
# vendor makes against their own interest rather than one they benefit from.
AGENT_SIGNATURES: tuple[AgentSignature, ...] = (
    AgentSignature("Claude Code", message=r"co-authored-by:[^\n]*claude",
                   identity=r"noreply@anthropic\.com|claude"),
    AgentSignature("GitHub Copilot", message=r"co-authored-by:[^\n]*copilot",
                   identity=r"copilot(-swe-agent)?(\[bot\])?@|github-copilot"),
    AgentSignature("Cursor", message=r"co-authored-by:[^\n]*cursor(\s|<)",
                   identity=r"cursor(\s+agent)?\s*<|@cursor\."),
    AgentSignature("Devin", message=r"co-authored-by:[^\n]*devin",
                   identity=r"devin(-ai)?(\[bot\])?@|@cognition"),
    AgentSignature("OpenAI Codex", message=r"co-authored-by:[^\n]*codex",
                   identity=r"codex(\[bot\])?@|@openai\.com"),
    AgentSignature("Aider", message=r"(co-authored-by:[^\n]*aider|^aider:)",
                   identity=r"aider@"),
    AgentSignature("Gemini", message=r"co-authored-by:[^\n]*gemini",
                   identity=r"gemini(-cli)?(\[bot\])?@"),
    AgentSignature("Windsurf", message=r"co-authored-by:[^\n]*windsurf",
                   identity=r"windsurf(\[bot\])?@"),
    AgentSignature("Cline", message=r"co-authored-by:[^\n]*cline", identity=r"cline(\[bot\])?@"),
)

#: Generic trailers that declare AI assistance without naming a tool we know. Matched after the
#: named tools so a recognised tool keeps its name.
GENERIC_TRAILERS = (
    (r"^\s*generated-by:\s*(.+)$", "Generated-by trailer"),
    (r"^\s*assisted-by:\s*(.+)$", "Assisted-by trailer"),
    (r"^\s*ai-assisted:\s*(.+)$", "AI-Assisted trailer"),
)

# Record separator: NUL, which git forbids anywhere in commit content, so a commit author
# cannot end a record early. \x1e was used first and is author-controllable: a subject
# containing one truncated its own commit's body, taking the AI trailer with it, and the commit
# was then reported as human-authored with nothing anywhere saying so.
_RS = "\x00"
# Field separator. \x1f is likewise author-controllable, so the split below is bounded: the body
# is whatever remains after the seventh separator, which means an injected \x1f can shift a
# field's meaning but can never discard content.
_FS = "\x1f"
_FIELDS = 8
_FORMAT = _FS.join(["%H", "%P", "%an <%ae>", "%cn <%ce>", "%aI", "%cI", "%s", "%B"]) + "%x00"


class GitError(RuntimeError):
    """git could not answer. Never swallowed: an attestation built from a partial history
    would be a document that understates its own gaps."""


def _git(repo: Path, *args: str, check: bool = True) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args],
                              capture_output=True, text=True, check=False,
                              # `git blame --line-porcelain` echoes each line of the file it is
                              # blaming, so a tracked binary asset puts bytes that are not UTF-8
                              # into this stream. Strict decoding raised inside communicate(),
                              # before any handler here could see it, and `pr attest --blame`
                              # died on any repository containing an image with an error about
                              # a bundle it had never been given.
                              errors="replace")
    except FileNotFoundError as exc:
        raise GitError("git is not installed, so there is no history to attest to") from exc
    if check and proc.returncode != 0:
        raise GitError((proc.stderr or proc.stdout).strip() or
                       f"git {' '.join(args)} failed with status {proc.returncode}")
    return proc.stdout


def _is_repo(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitError:
        return False


@dataclass
class Finding:
    """Why one commit is reported as AI-assisted, and on whose word."""

    tool: str
    source: str          # what was read: "commit message trailer", "author identity", ...
    grade: str = ASSERTED
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {"tool": self.tool, "source": self.source, "grade": self.grade}
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Commit:
    sha: str
    parents: list[str]
    author: str
    committer: str
    authored_at: str
    committed_at: str
    subject: str
    body: str
    insertions: int = 0
    deletions: int = 0
    files: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def ai_assisted(self) -> bool:
        return bool(self.findings)

    @property
    def tools(self) -> list[str]:
        seen, out = set(), []
        for f in self.findings:
            if f.tool not in seen:
                seen.add(f.tool)
                out.append(f.tool)
        return out

    @property
    def grade(self) -> str:
        return RECORDED if any(f.grade == RECORDED for f in self.findings) else ASSERTED

    def to_dict(self) -> dict[str, Any]:
        """The per-commit entry. This is what a leaf hashes, so it must be exactly the facts a
        reader is being asked to rely on, with nothing derived left implicit."""
        return {
            "sha": self.sha,
            "parents": self.parents,
            "author": self.author,
            "committer": self.committer,
            "authored_at": self.authored_at,
            "committed_at": self.committed_at,
            "subject": self.subject,
            "files_changed": self.files,
            "insertions": self.insertions,
            "deletions": self.deletions,
            "ai_assisted": self.ai_assisted,
            "tools": self.tools,
            "evidence_grade": self.grade if self.ai_assisted else "none",
            "findings": [f.to_dict() for f in self.findings],
        }

    def leaf(self) -> str:
        return sha256_hex(canonicalize(self.to_dict()))


def classify(commit: Commit) -> list[Finding]:
    """Every reason to believe this commit was AI-assisted, each naming its source.

    Multiple sources for the same tool are kept rather than collapsed. "The trailer says
    Claude Code and so does the author identity" is a materially different claim from "one
    trailer says so", and a reader weighing a disputed commit needs to see which they have.
    """
    findings: list[Finding] = []
    message = commit.body or commit.subject
    identity = f"{commit.author}\n{commit.committer}"
    for sig in AGENT_SIGNATURES:
        if sig.message and re.search(sig.message, message, re.IGNORECASE | re.MULTILINE):
            findings.append(Finding(sig.tool, "commit message trailer"))
        if sig.identity and re.search(sig.identity, identity, re.IGNORECASE):
            findings.append(Finding(sig.tool, "author or committer identity"))
    if not findings:
        for pattern, label in GENERIC_TRAILERS:
            match = re.search(pattern, message, re.IGNORECASE | re.MULTILINE)
            if match:
                findings.append(Finding(match.group(1).strip()[:120] or "unnamed tool",
                                        label))
    return findings


def read_commits(repo: Path, since: str | None = None, until: str = "HEAD",
                 max_count: int | None = None) -> list[Commit]:
    """The commits in the range, oldest first, with their diffstat and findings.

    Oldest first because the order is part of what the leaves commit to, and "oldest first"
    is the order a reader reconstructs by hand from `git log --reverse`.

    `--shortstat` prints its line AFTER the format string, so it lands at the head of the next
    record rather than the tail of its own. Reading it as part of the record it appears in put
    the diffstat text inside the next commit's sha and reported every commit as zero lines
    changed, so it is deliberately attributed backwards here.
    """
    rev = f"{since}..{until}" if since else until
    args = ["log", "--reverse", "--no-merges", f"--format={_FORMAT}", "--shortstat", rev]
    if max_count is not None:
        args.insert(1, f"--max-count={max_count}")
    raw = _git(repo, *args)
    commits: list[Commit] = []
    for chunk in raw.split(_RS):
        stat, rest = _leading_stat(chunk)
        if stat is not None and commits:
            commits[-1].files, commits[-1].insertions, commits[-1].deletions = stat
        if not rest.strip():
            continue
        fields = rest.split(_FS, _FIELDS - 1)
        if len(fields) < _FIELDS:
            # A fragment, not a record. It happens when a commit field carries one of the
            # separators this format splits on, which a commit author controls. Skipping it in
            # silence is what the first version did, and it meant a subject containing \x1e
            # truncated its own commit's body, taking the AI trailer with it and reporting the
            # commit as human-authored with nothing anywhere saying so. Dropping is still the
            # right handling, because the fragment is not a commit; what is not acceptable is
            # dropping quietly, so `read_commits` cross-checks its own count against git below.
            continue
        sha, parents, author, committer, a_at, c_at, subject, body = fields[:8]
        commit = Commit(
            sha=sha.strip(),
            parents=[p for p in parents.split() if p],
            author=author.strip(), committer=committer.strip(),
            authored_at=a_at.strip(), committed_at=c_at.strip(), subject=subject,
            body=body.strip(),
        )
        commit.findings = classify(commit)
        commits.append(commit)

    if max_count is None:
        # The parse is only trustworthy if it produced exactly the commits git says are in the
        # range. This catches separator injection, a future change to git's output, and any bug
        # in the splitting above, and it turns all of them into a refusal rather than an
        # attestation that quietly covers fewer commits than it claims to.
        expected = _git(repo, "rev-list", "--count", "--no-merges", rev).strip()
        try:
            expected_n = int(expected)
        except ValueError as exc:
            raise GitError(f"git could not count the commits in {rev}: {expected!r}") from exc
        if expected_n != len(commits):
            raise GitError(
                f"parsed {len(commits)} commits from {rev} but git counts {expected_n}. "
                f"A commit field almost certainly contains one of the separators this format "
                f"splits on. Refusing to sign an attestation that would silently cover fewer "
                f"commits than it names.")
    return commits


_SHORTSTAT = re.compile(
    r"^\s*(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?"
    r"\s*$", re.MULTILINE)


def _leading_stat(chunk: str) -> tuple[tuple[int, int, int] | None, str]:
    """Split a `--shortstat` line off the front of a record. Returns (stat, remainder).

    The stat belongs to the PREVIOUS commit; the remainder is this record. A commit that
    changed nothing prints no line at all, which is why the stat is optional rather than
    positional.
    """
    match = _SHORTSTAT.search(chunk)
    if match is None or chunk[:match.start()].strip():
        return None, chunk
    stat = (int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0))
    return stat, chunk[match.end():]


def blame_tree(repo: Path, commits: list[Commit],
               paths: list[str] | None = None) -> dict[str, Any] | None:
    """How many lines of the CURRENT tree came from AI-assisted commits.

    This is the number procurement actually asks for, and it is a different question from
    "how many commits were AI-assisted": one enormous generated commit and one typo fix count
    equally as commits and not at all equally as code.

    Lines whose commit falls outside the attested range are counted as `unattributed` rather
    than as human, because this attestation has no finding about them either way and reporting
    "not AI" for a commit we never examined would be a claim the document cannot support.
    """
    tracked = paths if paths is not None else [
        line for line in _git(repo, "ls-files", "-z").split("\0") if line]
    if not tracked:
        return None
    known = {c.sha: c.ai_assisted for c in commits}
    ai_lines = human_lines = unattributed = 0
    per_tool: dict[str, int] = {}
    tool_of = {c.sha: c.tools for c in commits}
    skipped: list[str] = []
    for path in tracked:
        try:
            out = _git(repo, "blame", "--line-porcelain", "--", path)
        except GitError:
            skipped.append(path)      # binary, submodule, or unreadable: never silently zero
            continue
        for line in out.splitlines():
            if not line or line[0] not in "0123456789abcdef":
                continue
            sha = line.split(" ", 1)[0]
            if len(sha) != 40:
                continue
            if sha not in known:
                unattributed += 1
            elif known[sha]:
                ai_lines += 1
                for tool in tool_of.get(sha, ()):
                    per_tool[tool] = per_tool.get(tool, 0) + 1
            else:
                human_lines += 1
    total = ai_lines + human_lines + unattributed
    return {
        "files_examined": len(tracked) - len(skipped),
        "files_skipped": len(skipped),
        "lines_total": total,
        "lines_ai_assisted": ai_lines,
        "lines_human": human_lines,
        "lines_unattributed": unattributed,
        "percent_ai_assisted": f"{(ai_lines / total * 100):.2f}" if total else "0.00",
        "by_tool": dict(sorted(per_tool.items(), key=lambda kv: -kv[1])),
        "note": ("Lines are attributed to the commit git blame names. `unattributed` lines "
                 "come from commits outside the attested range, which this document makes no "
                 "finding about in either direction."),
    }


def summarize(commits: list[Commit]) -> dict[str, Any]:
    ai = [c for c in commits if c.ai_assisted]
    per_tool: dict[str, int] = {}
    for commit in ai:
        for tool in commit.tools:
            per_tool[tool] = per_tool.get(tool, 0) + 1
    return {
        "commits_total": len(commits),
        "commits_ai_assisted": len(ai),
        "commits_recorded_grade": sum(1 for c in ai if c.grade == RECORDED),
        "percent_commits_ai_assisted":
            f"{(len(ai) / len(commits) * 100):.2f}" if commits else "0.00",
        "insertions_total": sum(c.insertions for c in commits),
        "insertions_ai_assisted": sum(c.insertions for c in ai),
        "by_tool": dict(sorted(per_tool.items(), key=lambda kv: -kv[1])),
    }


LIMITS = [
    "The findings are read from commit metadata: trailers, author and committer identity. A "
    "commit whose author removed that metadata is reported as human-authored, and no "
    "signature on this document changes that.",
    "Detection covers the tools listed in `detectors`. A tool not on that list is not "
    "detected, so AI involvement is understated rather than overstated.",
    "'ai_assisted' means an agent was involved in producing the commit. It does not measure "
    "how much of the commit the agent wrote, and it is not a statement about the code's "
    "quality, licensing or security.",
    "A signature proves this document was produced by the holder of the named key and has "
    "not changed since. An anchor additionally proves it existed no later than the anchored "
    "time. Neither proves the findings are true.",
    "Merges are excluded, so the same change is never counted twice.",
    "The higher 'recorded' grade needs the commit to have been authored inside a recorded "
    "agent run. A commit written by the agent and committed by a person afterwards falls "
    "outside that window and is reported at the lower grade, which understates the evidence "
    "rather than inventing it.",
]


def build(repo: Path, since: str | None = None, until: str = "HEAD",
          blame: bool = False, max_count: int | None = None,
          now: datetime | None = None,
          bundle: dict[str, Any] | None = None) -> dict[str, Any]:
    """The attestation document, unsigned."""
    repo = Path(repo).resolve()
    if not _is_repo(repo):
        raise GitError(f"{repo} is not a git repository, so there is no history to attest to")
    commits = read_commits(repo, since=since, until=until, max_count=max_count)
    sessions = sessions_from_bundle(bundle) if bundle else []
    if sessions:
        attach_recorded_evidence(commits, sessions)
    if not commits:
        rng = f"{since}..{until}" if since else until
        raise GitError(f"no commits in {rng}, so there is nothing to attest to")
    head = _git(repo, "rev-parse", until).strip()
    root_commit = _git(repo, "rev-list", "--max-parents=0", head).split()
    remote = _git(repo, "config", "--get", "remote.origin.url", check=False).strip()
    stamp = (now or datetime.now(UTC)).replace(microsecond=0).isoformat()
    dirty = bool(_git(repo, "status", "--porcelain").strip())

    from . import __version__

    doc: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": stamp,
        "generator": {"name": "provenrail", "version": __version__},
        "repository": {
            "first_commit": root_commit[-1] if root_commit else "",
            "head": head,
            "remote": remote or None,
            "working_tree_clean": not dirty,
        },
        "range": {"since": since, "until": until, "commit_count": len(commits)},
        "detectors": [s.tool for s in AGENT_SIGNATURES],
        "recorded_sessions": [
            {"session_id": s["session_id"], "stream_id": s["stream_id"],
             "started": s["started"].isoformat(), "ended": s["ended"].isoformat(),
             "records": s["records"], "chains": s.get("chains", 1),
             "first_record_hash": s["first_record_hash"],
             "last_record_hash": s["last_record_hash"]}
            for s in sessions],
        "summary": summarize(commits),
        "commits": [c.to_dict() for c in commits],
        "limits": list(LIMITS),
    }
    if blame:
        doc["working_tree"] = blame_tree(repo, commits)
    doc["leaves"] = [c.leaf() for c in commits]
    doc["document_hash"] = document_hash(doc)
    return doc


def document_hash(doc: dict[str, Any]) -> str:
    """The hash a signature covers: the document with its own hash and signature removed.

    Excluding both is what makes the hash reproducible by a reader who has only the signed
    file, rather than a number they have to take our word for.
    """
    body = {k: v for k, v in doc.items() if k not in ("document_hash", "signature")}
    return sha256_hex(canonicalize(body))


def sign(doc: dict[str, Any], key: Any) -> dict[str, Any]:
    """Attach a detached Ed25519 signature over the document hash."""
    digest = document_hash(doc)
    doc = dict(doc)
    doc["document_hash"] = digest
    doc["signature"] = {
        "algorithm": "ed25519",
        "public_key": key.public_key_hex(),
        "value": key.sign(bytes.fromhex(digest)),
    }
    return doc


def stream_id(doc: dict[str, Any]) -> str:
    """The anchor stream this repository's attestations belong to.

    Derived from the repository's first commit, so every attestation of the same repo lands on
    the same stream. That is what makes the anchor service's monotonic-coverage rule bite: a
    later attestation must cover at least as many commits as the one before it, so a shorter
    history cannot be quietly substituted for a longer one that has already been anchored.
    """
    first = (doc.get("repository") or {}).get("first_commit") or ""
    return "attest-" + sha256_hex(("provenrail-attest:" + first).encode("utf-8"))[:32]


# ---------------------------------------------------------------- recorded evidence


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def sessions_from_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Recorded agent runs in a bundle: when each ran, and what it is hashed as.

    Grouped by the HOST session, not by the Provenrail session id, and the difference is the
    whole feature. A hook fires in its own process and a chain cannot span processes, so guard
    mode writes one short Provenrail session per tool call: a real overnight agent run appears
    in the bundle as hundreds of sessions a few milliseconds wide. Grouping by `session_id`
    therefore produced windows narrower than git's one-second timestamp resolution, and no
    commit ever landed inside one. `record_hook` tags every one of them with
    `meta.host_session_id`, which is the id of the run a human means, so that is the key.

    Only the fields a reader needs to check the claim themselves: the run id, its first and
    last record hash, and the window. Everything else about the session stays in the bundle,
    which is not what an attestation ships.
    """
    # Pass one: which host run does each Provenrail session belong to. The answer is in the
    # genesis record's meta, so it has to be read before any record can be filed.
    host_of: dict[str, str] = {}
    for entry in bundle.get("records") or []:
        record = entry.get("record") or {}
        meta = (record.get("payload") or {}).get("meta") or {}
        host = meta.get("host_session_id")
        session = record.get("session_id")
        if session and host:
            host_of[session] = str(host)

    by_run: dict[str, dict[str, Any]] = {}
    for entry in bundle.get("records") or []:
        record = entry.get("record") or {}
        session = record.get("session_id")
        stamp = _parse_ts(record.get("ts_utc", ""))
        if not session or stamp is None:
            continue
        run = host_of.get(session, session)
        slot = by_run.setdefault(run, {
            "session_id": run,
            "stream_id": record.get("stream_id") or bundle.get("stream_id"),
            "started": stamp, "ended": stamp,
            "first_record_hash": entry.get("server_record_hash"),
            "last_record_hash": entry.get("server_record_hash"),
            "records": 0,
            "chains": set(),
        })
        slot["records"] += 1
        slot["chains"].add(session)
        if stamp < slot["started"]:
            slot["started"], slot["first_record_hash"] = stamp, entry.get("server_record_hash")
        if stamp > slot["ended"]:
            slot["ended"], slot["last_record_hash"] = stamp, entry.get("server_record_hash")
    runs = sorted(by_run.values(), key=lambda s: s["started"])
    for run in runs:
        run["chains"] = len(run["chains"])
    return runs


def attach_recorded_evidence(commits: list[Commit],
                             sessions: list[dict[str, Any]]) -> int:
    """Raise a commit's evidence grade when a signed session covers the moment it was authored.

    This is the only source in the module that the party being asked cannot simply have typed.
    A session record was signed by the recorder at the time, hash-chained to its neighbours,
    and (once anchored) timestamped by somebody else, so a commit inside such a window has an
    agent's activity attested by a mechanism independent of the commit message.

    The claim is kept deliberately narrow, and is worded that way in the finding: an agent
    session was running when this commit was authored. It is NOT "this agent wrote this
    commit", because a recorder cannot see a developer typing in another window, and an
    evidence document that quietly widens its own claim is the failure mode this whole product
    exists to avoid.

    Returns the number of commits upgraded.
    """
    upgraded = 0
    for commit in commits:
        stamp = _parse_ts(commit.authored_at)
        if stamp is None:
            continue
        for session in sessions:
            if not (session["started"] <= stamp <= session["ended"]):
                continue
            commit.findings.append(Finding(
                tool="recorded agent session",
                source="Provenrail signed session record",
                grade=RECORDED,
                detail=(f"agent run {session['session_id']} on stream "
                        f"{session['stream_id']} was running when this commit was authored "
                        f"({session['records']} signed records across "
                        f"{session.get('chains', 1)} chains, "
                        f"{session['first_record_hash'][:12]}..{session['last_record_hash'][:12]})"),
            ))
            upgraded += 1
            break
    return upgraded
