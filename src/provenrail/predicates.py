"""Named checks a rule can add on top of its regex, for the questions a regex cannot answer.

The measurement that forced this module: run the shipped `destructive` pack over 36,929 real
Bash calls from agent sessions and the two `rm` rules account for 646 of 824 interruptions.
Almost none are dangerous. They are `rm -rf .next out` before a build, `rm -f coverage.xml`,
`rm -rf app/en` during a refactor. A guardrail that stops an agent nine times out of ten for
routine work is uninstalled the same day, and it takes the rules that were doing real work
with it.

The mistake was screening the VERB. Nobody has ever lost anything to the letters `rm -rf`;
they lost it to the target. `rm -rf .next` regenerates in twelve seconds. `rm -rf ~/` is the
end of a laptop. The two are indistinguishable to a regex because the difference is not in the
text, it is in where the text points, which needs the working directory to answer.

So a rule may name a `predicate`: a function that sees the same single command the regex
matched, plus the call's context, and gets the last word. Unknown predicate names evaluate to
True, so a rule from a newer catalogue keeps firing on an older engine rather than silently
switching itself off, and a bundle written by a newer verifier still re-checks here.

**What is deliberately NOT here.** No shell expansion, no globbing, no stat() of the target,
no symlink resolution. A predicate runs in a PreToolUse hook in front of every tool call the
agent makes; it has to be pure text and arithmetic, and it has to answer in microseconds. An
unresolvable target is classified as dangerous rather than investigated.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

#: Programs whose remaining arguments are paths about to stop existing.
_DELETERS = ("rm", "unlink", "shred", "trash")

#: Prefixes that stand in front of the real command.
_WRAPPERS = ("sudo", "env", "nohup", "time", "command", "exec", "nice", "stdbuf", "doas",
             "xargs", "then", "else", "do")

#: Directories whose contents are, by definition, reproducible. Deleting one is not a loss
#: even though it sits outside the project, and an agent clearing a broken package cache is
#: doing maintenance, not damage. Relative to the home directory.
_CACHE_DIRS = (
    "Library/Caches", ".cache", ".npm", ".yarn/cache", ".pnpm-store", "Library/pnpm-store",
    ".cargo/registry", ".gradle/caches", ".m2/repository", "Library/Developer/Xcode/DerivedData",
    ".local/share/virtualenvs", ".bun/install/cache",
)

#: Directory names that hold nothing but generated output. An agent clearing one is running a
#: build step, and it makes no difference whether the build lives in this repository or the
#: sibling checkout next to it: the contents come back from a command. Only honoured deep in
#: the tree, so a literal `/build` or `/Users/ana/dist` is still treated as the container it is.
_BUILD_DIRS = ("node_modules", "dist", "build", ".next", ".nuxt", ".turbo", ".svelte-kit",
               "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv",
               "target", "coverage", ".parcel-cache", ".gradle", "DerivedData", ".terraform")

#: Roots the operating system hands out for scratch work.
_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders",
               "/private/var/folders", "/dev/shm")

#: Variables we can resolve without running a shell. Everything else is an unknown target.
_KNOWN_VARS = ("PWD", "HOME", "TMPDIR", "TMP", "TEMP")

_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")

#: `NAME=value` at the head of a command, which is how a script names a directory before
#: deleting it. Without this, `SP=/private/tmp/x; rm -rf $SP/fixed` reads as an unset variable
#: followed by a slash, which is the shape that means `rm -rf /`, and it was 41 of the 68 denies
#: in the measured corpus. The value is right there in the same string; not reading it was the
#: guard refusing to look at evidence it already had.
_ASSIGN = re.compile(r"(?:^|[;&|\n]|\bexport\s)\s*([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|\n]*)")

#: Verdicts a target classification can carry, worst first.
CATASTROPHIC = "catastrophic"
OUTSIDE = "outside"
INSIDE = "inside"
_ORDER = (CATASTROPHIC, OUTSIDE, INSIDE)


def workspace_root(cwd: str | None = None) -> str:
    """The directory a delete is allowed to happen inside.

    The repository root, not the current directory: an agent in `apps/web` running
    `rm -rf ../api/dist` is still working inside its own project, and treating the subdirectory
    as the boundary would ask about it. Falls back to the current directory when there is no
    repository, which is the conservative answer rather than the convenient one.
    """
    start = os.path.abspath(cwd or os.getcwd())
    here = start
    while True:
        if os.path.exists(os.path.join(here, ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            return start
        here = parent


def _home() -> str:
    return os.path.abspath(os.path.expanduser("~"))


def _under(path: str, root: str) -> bool:
    """True when `path` is strictly inside `root`. Equality is NOT inside: `rm -rf .` from the
    project root deletes the project, which is exactly the case worth asking about."""
    if not root:
        return False
    root = root.rstrip("/") or "/"
    return path != root and (path + "/").startswith(root + "/")


#: Punctuation that is JSON structure rather than part of a path.
_EDGE = "\"'{}[],;`"


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        # An unbalanced quote is a string we did not understand, and those must stay screened.
        return _loose_tokens(command)


def _loose_tokens(command: str) -> list[str]:
    """Whitespace split with JSON punctuation trimmed off each token.

    Not every argument arrives as a shell string. A tool called with `{"args": {"cmd": "rm -rf
    /var/data"}}` is rendered as JSON, and `shlex` reads the quoted value as ONE token, so the
    `rm` never appears as a word and the delete looked like no delete at all. The rules have
    always matched this text; the predicate has to be able to read it too.
    """
    out = []
    for token in command.split():
        token = token.strip(_EDGE)
        if token:
            out.append(token)
    return out


def delete_targets(command: str) -> list[str] | None:
    """The paths one command is about to delete, or None when it is not a delete at all.

    An empty list is a real answer and a different one from None: `rm -rf` with no operand
    deletes nothing.
    """
    # Strict first: the deleter has to be the program the shell will run, so `echo rm` is not
    # a delete. If that finds nothing, the text may not be a shell string at all (a tool called
    # with a JSON argument object), and there the deleter can sit anywhere. The loose pass can
    # only ever find MORE targets, so it can only ever narrow an allow into a question.
    for tokens, anywhere in ((_tokens(command), False), (_loose_tokens(command), True)):
        targets = _targets_from(tokens, anywhere)
        if targets is not None:
            return targets
    return None


def _targets_from(tokens: list[str], anywhere: bool = False) -> list[str] | None:
    index = None
    for i, token in enumerate(tokens):
        base = token.rsplit("/", 1)[-1]
        if base in _DELETERS:
            index = i
            break
        if base == "find":
            return _find_targets(tokens[i + 1:])
        if (anywhere or base in _WRAPPERS or token.startswith("-")
                or ("=" in base and "/" not in base)):
            continue
        break
    if index is None:
        return None
    targets: list[str] = []
    end_of_flags = False
    for token in tokens[index + 1:]:
        if not end_of_flags and token == "--":
            end_of_flags = True
            continue
        if not end_of_flags and token.startswith("-") and token != "-":
            continue
        targets.append(token)
    return targets


def _find_targets(rest: list[str]) -> list[str] | None:
    """`find <paths> ... -delete`. Only the leading paths are targets; everything from the
    first predicate onwards describes which of them match."""
    if not any(t == "-delete" or t.startswith("-delete") for t in rest):
        return None
    targets = []
    for token in rest:
        if token.startswith("-"):
            break
        targets.append(token)
    return targets or ["."]


def local_vars(text: str) -> dict[str, str]:
    """Variables the command assigns to itself before using them."""
    out: dict[str, str] = {}
    for name, value in _ASSIGN.findall(text or ""):
        value = value.strip().strip("\"'")
        if value and "$" not in value:
            out[name] = value
    return out


def _expand(target: str, local: dict[str, str] | None = None) -> tuple[str | None, bool]:
    """(path, at_root_if_empty). None means the target cannot be resolved without a shell.

    `at_root_if_empty` is the accident that eats a machine: `rm -rf $BUILD/` with BUILD unset
    is `rm -rf /`. A bare `$BUILD` with BUILD unset deletes nothing, which is why the two are
    not classified the same way.
    """
    text = target.strip()
    if not text:
        return None, False
    if text.startswith("~"):
        return os.path.join(_home(), text[1:].lstrip("/")), False
    match = _VAR.match(text)
    if match:
        name = match.group(1)
        rest = text[match.end():]
        if local and name in local:
            text = local[name] + rest
            return (text, False) if "$" not in text else (None, False)
        if name not in _KNOWN_VARS:
            # Unknown value. If a separator follows, an empty value points at the filesystem
            # root, so the shape itself is the hazard regardless of what the variable holds.
            return None, rest.startswith("/")
        value = os.environ.get(name) or ""
        if name == "PWD" and not value:
            value = os.getcwd()
        if name == "HOME" and not value:
            value = _home()
        if not value:
            return None, rest.startswith("/")
        text = value + rest
    if "$" in text or "`" in text:
        return None, False
    return text, False


def classify_target(target: str, root: str, local: dict[str, str] | None = None) -> str:
    """Where one delete target sits: inside the workspace, outside it, or unrecoverable.

    Depth is the discriminator outside the workspace, and it is a blunt one on purpose.
    `/Volumes/T7` is a whole disk and `/Users/ana` is a whole person; `/Volumes/T7/Projects/
    site/.next` is a build directory. Two path segments or fewer under the root means the
    target is a container of unrelated things, and no build step ever needs to remove one.
    """
    path, root_if_empty = _expand(target, local)
    if root_if_empty:
        return CATASTROPHIC
    if path is None:
        return OUTSIDE
    absolute = path if path.startswith("/") else os.path.join(root, path)
    # normpath, not realpath: no filesystem access, and a symlink's own name is what the
    # command names. `..` still collapses, which is the part that matters.
    absolute = os.path.normpath(absolute)
    if absolute in ("", "."):
        absolute = root
    # Order matters, and it is the reverse of the obvious one. The exemptions below (inside the
    # workspace, under a temp root, a build directory) are asked LAST, because a home directory
    # that happens to sit under one of them is still a home directory: with HOME set to a
    # scratch path, `rm -rf ~/` read as a temp-directory clean-up and was allowed.
    home = _home()
    if absolute == home or _under(home, absolute):
        return CATASTROPHIC
    if absolute == root:
        # The project itself. Recoverable from a remote, usually, and not from anywhere if the
        # work is uncommitted, so it is a question rather than a refusal.
        return OUTSIDE
    if _under(absolute, root):
        return INSIDE
    for temp in _TEMP_ROOTS:
        if _under(absolute, temp):
            return INSIDE
    for cache in _CACHE_DIRS:
        if _under(absolute, os.path.join(home, cache)):
            return INSIDE
    if os.path.dirname(absolute) == home:
        # A folder sitting directly in the home directory is a whole category of someone's
        # life: Documents, Desktop, Projects, Downloads, or another checkout entirely. The
        # caches above are the exception and were already returned.
        return CATASTROPHIC
    parts = [p for p in PurePosixPath(absolute).parts if p != "/"]
    # A build directory ANYWHERE in the path, not only at the end: `/Volumes/T7/DerivedData/
    # Brewist-1.0.4-85-export` is Xcode output with a version in its name, and the thing that
    # makes it regenerable is the DerivedData above it. Never the first segment, so `/build`
    # and `/Users/ana/dist` stay the containers they are.
    if len(parts) >= 3 and any(part in _BUILD_DIRS for part in parts[1:]):
        return INSIDE
    if len(parts) <= 2:
        return CATASTROPHIC
    return OUTSIDE


def classify_delete(command: str, ctx: dict[str, Any]) -> str | None:
    """The worst classification among a delete command's targets, or None if it deletes nothing."""
    if re.search(r"--no-preserve-root", command):
        return CATASTROPHIC
    targets = delete_targets(command)
    if targets is None:
        return None
    if not targets:
        return None
    root = workspace_root(ctx.get("cwd") or None)
    text = ctx.get("match_text")
    local = local_vars(text if isinstance(text, str) else command)
    worst = INSIDE
    for target in targets:
        verdict = classify_target(target, root, local)
        if _ORDER.index(verdict) < _ORDER.index(worst):
            worst = verdict
    return worst


#: Flags that turn a command into a rehearsal or point it at a throwaway copy. `--dry-run`
#: prints what would happen; `wrangler d1 execute --local` runs against a SQLite file in
#: `.wrangler/`, not against the production database. Asking a human to approve either one is
#: asking them to approve nothing, and it is the fastest way to train someone to stop reading
#: the prompt. Measured: `wrangler deploy --dry-run` and `d1 execute --local` were a fifth of
#: all interruptions in the corpus.
_REHEARSAL = re.compile(r"(^|\s)(--dry[-_]?run|--local|--plan-only|--no-execute|--what-if)\b")


def _not_a_rehearsal(command: str, ctx: dict[str, Any]) -> bool:
    return not _REHEARSAL.search(command)


# ------------------------------------------------------- git working-tree loss


#: How long a git query may take before the guard stops waiting. A PreToolUse hook sits in
#: front of the agent, so it has to answer fast, and a repository that is locked or on a stalled
#: network mount must not hang the session.
_GIT_TIMEOUT_S = 2.0


def _git(cwd: str, *args: str) -> str | None:
    """One read-only git command, or None if it could not be answered."""
    try:
        proc = subprocess.run(("git", *args), cwd=cwd or None, capture_output=True, text=True,
                              timeout=_GIT_TIMEOUT_S,
                              env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def work_at_risk(cwd: str) -> bool:
    """Whether this repository is holding work that only exists here.

    Uncommitted changes, untracked files, or commits that have not reached a remote. If all
    three are clear, `git reset --hard` and `git checkout -- .` destroy nothing that cannot be
    fetched back, and asking about them is asking about nothing.

    Anything this cannot determine counts as at risk. A guard that cannot see the repository is
    not a guard that has checked it.
    """
    status = _git(cwd, "status", "--porcelain", "--untracked-files=normal")
    if status is None:
        return True
    if status.strip():
        return True
    ahead = _git(cwd, "rev-list", "--count", "@{upstream}..HEAD")
    if ahead is None:
        # No upstream, a detached HEAD, or a repository with no commits yet. In every one of
        # those the local branch is the only copy there is.
        return True
    return ahead.strip() not in ("", "0")


def _git_would_lose_work(command: str, ctx: dict[str, Any]) -> bool:
    return work_at_risk(ctx.get("cwd") or os.getcwd())


#: `git branch -D` forces the delete; `git branch -d` refuses to delete unmerged work and is
#: the safe spelling people use every day. The rule engine matches case-insensitively, which is
#: right for SQL keywords and wrong for a git flag, so the one bit of case that carries the
#: whole meaning is checked here instead.
_FORCE_DELETE_BRANCH = re.compile(r"\bbranch\s+(-[a-zA-Z]*D|--delete\s+--force"
                                  r"|--force\s+--delete)\b")


def _git_force_delete_branch(command: str, ctx: dict[str, Any]) -> bool:
    return bool(_FORCE_DELETE_BRANCH.search(command))


# ------------------------------------------------------------------ registry


def _delete_catastrophic(command: str, ctx: dict[str, Any]) -> bool:
    return classify_delete(command, ctx) == CATASTROPHIC


def _delete_outside_workspace(command: str, ctx: dict[str, Any]) -> bool:
    return classify_delete(command, ctx) in (CATASTROPHIC, OUTSIDE)


REGISTRY: dict[str, Callable[[str, dict[str, Any]], bool]] = {
    "delete.catastrophic": _delete_catastrophic,
    "delete.outside_workspace": _delete_outside_workspace,
    "command.not_a_rehearsal": _not_a_rehearsal,
    "git.would_lose_work": _git_would_lose_work,
    "git.force_delete_branch": _git_force_delete_branch,
}


def evaluate(name: str, command: str, ctx: dict[str, Any]) -> bool:
    """Run a named predicate. An unknown name, or one that raises, evaluates to True.

    Both fallbacks point the same way: a rule whose extra condition could not be checked falls
    back to what the regex already said, which is the behaviour before predicates existed. A
    predicate can therefore only ever narrow a rule, never widen one, so a bug in this file
    cannot open a hole that was previously closed.
    """
    func = REGISTRY.get(name)
    if func is None:
        return True
    try:
        return bool(func(command, ctx))
    except Exception:
        return True
