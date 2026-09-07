"""Splitting a shell command string into the commands it will actually run.

A guardrail that matches its rules against the whole string a tool was handed is not screening
commands, it is screening text, and the difference here was measured rather than argued: run
the shipped ruleset over 36,929 Bash calls from real agent sessions and it denies 295 of them,
of which almost none are dangerous. Three distinct ways it went wrong, all the same mistake:

    cat > guard.py <<'PY' ... dd of=/dev/sda ... PY     the text is FILE CONTENT being written
    git push origin main 2>&1; pkill -f "next dev"      the -f belongs to pkill, not to push
    npx wrangler d1 execute --local --command "DROP..." a local test database, not production

The first two are fixed here. A rule should see those as two separate commands, and should not
see the body of a heredoc at all, because a heredoc body is data on its way to a file.

**The exception that keeps this honest.** A heredoc body IS commands when the thing reading it
is a shell, so `bash <<'EOF' ... EOF` keeps its body. Anything else, `cat`, `python3`, `tee`,
`sqlite3`, is reading data, and treating that data as commands produced most of the false
positives above.

**What this does not do.** It is not a shell parser and does not try to be. Quoted strings are
kept as written, because `bash -c "rm -rf /"` is a real command and stripping quotes to dodge a
false positive would create a real hole. Command substitution is split out rather than dropped,
so `$(...)` is still screened. When anything is ambiguous the whole original string is kept as
a segment too, so this can only ever give a rule MORE places to match, never fewer.
"""

from __future__ import annotations

import re

#: Programs that execute what arrives on stdin. A heredoc feeding one of these carries commands.
_SHELLS = ("bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "eval", "source")

#: Wrappers that stand in front of the program actually being run.
_WRAPPERS = ("env", "sudo", "nohup", "time", "xargs", "command", "exec", "nice", "stdbuf")

#: `<<` or `<<-`, optional whitespace, then the delimiter, quoted or not.
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

#: Operators that end one command and begin the next. Longest first so `&&` is not read as `&`,
#: and a lone `&` only counts when it is not part of a redirection: splitting `2>&1` produced a
#: segment ending `2>` and another reading `1`, which is not a command anybody ran.
_SPLIT = re.compile(r"\|\||&&|;;|;|\||(?<![>&\d])&(?![>&\d])|\n")

#: The same operators, used to find split points while scanning with quote state.
_OPERATOR = re.compile(r"\|\||&&|;;|;|\||(?<![>&\d])&(?![>&\d])|\n")


def split_commands(text: str) -> list[str]:
    """Split on shell operators, ignoring any that sit inside quotes.

    A newline inside a quoted argument is not an operator, and treating it as one is how
    `wrangler d1 execute --local --command "DELETE FROM licenses\n WHERE ..."` became two
    commands: one carrying the `--local` flag that made it harmless, and one carrying a bare
    unbounded DELETE. The rule then denied a local test database five separate times in the
    measured corpus, having thrown away the word that said it was local.

    Backslash escapes are honoured, and an unterminated quote means the rest of the string is
    one piece, which is the reading that keeps the most text in front of the rules.
    """
    parts: list[str] = []
    start = 0
    i = 0
    quote = ""
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        match = _OPERATOR.match(text, i)
        if match:
            parts.append(text[start:i])
            i = match.end()
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _feeds_a_shell(line: str, heredoc_start: int) -> bool:
    """Whether the command opening this heredoc will execute its body."""
    prefix = line[:heredoc_start]
    # The last command on the line before the redirection is the one reading stdin.
    last = _SPLIT.split(prefix)[-1].strip()
    for word in last.split():
        base = word.rsplit("/", 1)[-1]
        if base in _SHELLS:
            return True
        if base in _WRAPPERS or base.startswith("-") or ("=" in base and "/" not in base):
            continue        # a wrapper, a flag, or a VAR=value prefix: keep looking
        return False
    return False


def strip_heredocs(command: str) -> str:
    """The command with heredoc bodies that are data, rather than commands, removed.

    A body feeding a shell is kept, and so is every line that opened one. An unterminated
    heredoc is a string this did not understand, and a shape we do not understand must fail
    towards being READ, so its body is kept too.
    """
    if "<<" not in command:
        return command
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        match = _HEREDOC.search(line)
        if not match:
            i += 1
            continue
        delimiter = match.group(2)
        executed = _feeds_a_shell(line, match.start())
        i += 1
        body: list[str] = []
        closed = False
        while i < len(lines):
            if lines[i].strip() == delimiter:
                closed = True
                i += 1
                break
            body.append(lines[i])
            i += 1
        if executed or not closed:
            out.extend(body)
    return "\n".join(out)


def segments(command: str) -> list[str]:
    """The individual commands a shell string will run.

    The whole original string is deliberately NOT one of them. Keeping it would be the safer
    looking choice and would defeat the entire purpose: `git push origin main 2>&1; pkill -f x`
    matches the force-push rule as one string and matches nothing as two commands, and it is
    the two-command reading that is true. Every rule in the catalogue is written against a
    single command, so nothing is lost; a rule that needs to span an operator would report
    itself as matching nothing under `pr rules --check`, which is the visible failure rather
    than the silent one.

    A string this cannot make sense of falls back to itself, so an unparseable input is still
    screened rather than waved through.
    """
    if not isinstance(command, str):
        return []
    if not command.strip():
        return [command]
    stripped = strip_heredocs(command)
    parts: list[str] = []
    seen: set[str] = set()

    def _add(text: str) -> None:
        text = text.strip()
        if text and text not in seen:
            seen.add(text)
            parts.append(text)

    for chunk in split_commands(stripped):
        _add(chunk)
        # Command substitution runs its contents, so screen them in their own right rather than
        # only as part of the line that happens to contain them.
        for outer, inner in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", chunk):
            for piece in split_commands(outer or inner):
                _add(piece)
    return parts or [command]


#: A word that reads as a subcommand: letters, digits and hyphens, nothing else. `delete-db-
#: instance` and `migrate` qualify; `myapp_production`, `s3://bucket`, `./script.sh` and
#: `"DROP` do not. Everything a secret can hide in fails this on the first character class.
_SUBCOMMAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,23}$")

#: `NAME=value` in front of the command it runs.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def command_shape(command: str, limit: int = 6) -> str:
    """The verb and its flags, with every operand dropped.

    `git reset --hard origin/main` becomes `git reset --hard`, and an environment assignment
    carrying an API key becomes `export`. This is what a journal line is allowed to remember
    about a command, and what a shareable summary is allowed to print. The rule is deliberately
    crude in the safe direction: a secret always arrives as an operand, so no operand is kept.
    A truncation or a redaction pass would have to be right every time; dropping the whole
    category has to be right once.
    """
    if not isinstance(command, str):
        return ""
    parts = segments(command)
    if not parts:
        return ""
    out: list[str] = []
    words = 0
    after_flag = False
    for token in parts[0].split():
        if len(out) >= limit:
            break
        if not out and _ASSIGNMENT.match(token):
            # `SC=/private/tmp/.../scratchpad cmd ...`: an environment prefix, whose value is
            # an operand. Skip it and keep looking for the verb.
            continue
        if token.startswith("-"):
            out.append(token)
            # `--db-instance-identifier prod` and `-m "fix login"`: the next word belongs to
            # the flag, and a flag's value is an operand like any other.
            after_flag = token != "--" and not token.startswith("--no-")
            continue
        if after_flag:
            break
        if not out and "/" in token:
            # An absolute or relative path to the program. The directories are the operand
            # part; the program's own name is the verb.
            token = token.rsplit("/", 1)[-1]
        # Four bare words is `npx wrangler d1 delete`, and past that a bare word is an operand.
        if words >= 4 or not _SUBCOMMAND.match(token):
            break
        out.append(token)
        words += 1
    return " ".join(out)
