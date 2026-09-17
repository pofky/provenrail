"""One policy, five coding agents: the per-host hook contracts, in one place.

`guard.decide()` never needed to know which agent it was protecting. It takes a tool name, a
tool input, a working directory and a session id, and every agent with a pre-tool hook hands
over exactly those four things. Only two pieces were ever Claude Code specific: the field names
on the way in, and the JSON envelope on the way out. This module is those two pieces, for every
host, and nothing else.

Why it is one module and not one per host: the table below is the kind of list that drifts the
moment there are two copies of it. A field name that is right in the parser and wrong in the
installer produces a guard that reports itself armed and screens an empty object, which is the
worst failure this product has, and it has shipped twice.

What is verified, and what is not
---------------------------------
Every contract below was read from the vendor's own documentation on the date in its
`checked` field, and the URL is in `doc` so the next person can re-check it rather than trust
this comment. NONE of these hosts has had a real payload captured into this repository, Claude
Code included: `CAPTURED_PAYLOAD` is empty and `tests/test_hosts.py` fails if any host claims
otherwise or if any module under `src/` describes an uncaptured host as verified, driven or
tested. Documentation is evidence about the vendor's intent. It is not evidence that our
adapter parses what the vendor actually sends, and the difference between those two is a guard
that silently stops guarding.

Effects are never flattened
---------------------------
Two of these hosts have no way to ask a human. The policy effect `require_oversight` still
travels into the journal and the signed record AS `require_oversight`, with the verdict the
host was actually given in `extra`. Recording "deny" because the host could only express deny
would mean the record answers a question about the host when it was asked a question about the
policy.
"""

from __future__ import annotations

import json
from typing import Any

#: The host this project was built on and the default everywhere a host is not named.
DEFAULT_HOST = "claude-code"

#: Hosts for which a REAL payload, emitted by the vendor's own CLI, is checked in under
#: `tests/fixtures/hosts/`. Claude Code was captured on 2026-09-17 from a live `claude -p`
#: session. The other four are still synthetic, hand-written from each vendor's published hook
#: reference, and say so in the file: Codex CLI's stored token is expired and the rest are not
#: installed here. Documentation is evidence about a vendor's intent, not evidence that our
#: adapter parses what the vendor actually sends, and the gap between those two is a guard that
#: silently stops guarding. Nothing in `src/` may call a host outside this tuple verified,
#: driven or tested.
CAPTURED_PAYLOAD: tuple[str, ...] = ("claude-code",)


class UnknownHost(ValueError):
    """A host nobody here has a contract for. Never treated as "allow"; see `guard.run_hook`."""


class PayloadShapeError(ValueError):
    """The payload did not have the shape this host's documented contract describes.

    Raised rather than shrugged off, because on a host whose payload we have never actually
    seen, a shape we do not recognise most likely means our adapter is wrong. An adapter that
    is wrong and quiet is a guard that reports itself armed while screening nothing.
    """


# ---------------------------------------------------------------- tool names

# The rules' `tool` and `not_tool` globs are written in Claude Code's names (`Bash`, `Read`,
# `Write`, `Edit`, `Glob`, `Grep`, ...), because that is the host the catalogue grew up on.
# Rather than write every rule five times, each host's documented tool names are translated
# into those here.
#
# Only names the vendor's own documentation shows are listed. An unlisted name passes through
# unchanged, which is the safe direction: an unknown name matches no `not_tool` exclusion, so
# the call is screened as if it were a command instead of skipped as if it were a file read.
# The cost is a false positive; the alternative cost is a missed `rm -rf`.
_TOOL_NAMES: dict[str, dict[str, str]] = {
    # https://learn.chatgpt.com/docs/hooks (checked 2026-09-16): "For file edits through
    # apply_patch, matcher values can use apply_patch, Edit, or Write; hook input still reports
    # tool_name: 'apply_patch'." Shell calls already arrive as "Bash".
    "codex": {"apply_patch": "Edit"},
    # https://geminicli.com/docs/hooks/reference/ (checked 2026-09-16): the four built-in tool
    # names the hooks reference itself names. Its "Tools Reference" lists more; they are not
    # copied here because that page was not read, and a guessed tool name is a guessed rule.
    "gemini": {
        "run_shell_command": "Bash",
        "read_file": "Read",
        "write_file": "Write",
        "replace": "Edit",
    },
    # https://docs.github.com/en/copilot/reference/hooks-reference (checked 2026-09-16): the
    # complete documented `toolName` list is ask_user, bash, create, edit, glob, grep,
    # powershell, task, view, web_fetch.
    "copilot": {
        "ask_user": "AskUserQuestion",
        "bash": "Bash",
        "create": "Write",
        "edit": "Edit",
        "glob": "Glob",
        "grep": "Grep",
        "powershell": "Bash",
        "task": "Task",
        "view": "Read",
        "web_fetch": "WebFetch",
    },
    # Cursor's shell event carries no tool name at all; the event IS the tool name, and the
    # parser below supplies "Bash". Its MCP event carries the server's own tool names, which
    # are the server author's, not Cursor's, so there is nothing to translate.
    "cursor": {},
    "claude-code": {},
}


def canonical_tool(host: str, name: str) -> str:
    """The Claude Code tool name that `host`'s `name` stands for, or `name` unchanged."""
    table = _TOOL_NAMES.get(host)
    if table is None:
        raise UnknownHost(host)
    return table.get(name, name)


# ---------------------------------------------------------------- payload shapes


def coerce_tool_input(value: Any) -> Any:
    """Whatever the host sent, in a shape the content rules can actually read.

    A dict passes through. A string is the command itself and is the single most important
    thing to screen, so it is wrapped rather than discarded. A list or any other shape is kept
    too: an unrecognised payload must fail towards being READ, never towards being ignored,
    because the alternative is a guard that reports itself armed while matching every rule
    against an empty object.
    """
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str):
        return {"command": value}
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        # An argv array IS a command line, and the content rules are written against command
        # lines. Serialised as JSON it reads `["rm", "-rf", "/"]`, where the comma between the
        # program and its flags defeats every `\brm\s+-rf` pattern, so it is joined back into
        # the string it stands for.
        return {"command": " ".join(value)}
    return {"input": value}


def _blank(host: str, event: str) -> dict[str, Any]:
    return {"host": host, "event": event, "tool": "", "host_tool": "", "input": {},
            "response": None, "session_id": "", "cwd": "", "transcript_path": ""}


def _phase(raw_event: str, default_event: str) -> str:
    event = (raw_event or "").strip().lower()
    if event.startswith("posttool") or event.startswith("aftertool"):
        return "post"
    if event.startswith("pretool") or event.startswith("beforetool"):
        return "pre"
    # Hook name absent or renamed upstream: fall back to the phase the installed command
    # declares, rather than guessing "pre" and gating a call that already ran.
    return default_event


def _parse_claude_code(data: dict[str, Any], default_event: str) -> dict[str, Any]:
    """Claude Code `PreToolUse` / `PostToolUse`.

    https://code.claude.com/docs/en/hooks (checked 2026-09-16).

    Everything is read with `.get()` and a missing field degrades to "record it anyway". That
    tolerance is deliberate here and NOT extended to the other hosts: this payload has been
    driven through this code thousands of times, so an unfamiliar shape here is most likely the
    vendor renaming a field, while an unfamiliar shape on a host nobody has driven is most
    likely us being wrong about the contract.
    """
    out = _blank("claude-code", _phase(data.get("hook_event_name") or "", default_event))
    out["host_tool"] = data.get("tool_name") or ""
    out["tool"] = out["host_tool"]
    # A non-dict tool_input used to become `{}`, which every content rule then matched against
    # the two characters "{}" and let through. For the Bash tool that is the ENTIRE protection.
    out["input"] = coerce_tool_input(data.get("tool_input"))
    out["response"] = data.get("tool_response")
    out["session_id"] = data.get("session_id") or ""
    out["cwd"] = data.get("cwd") or ""
    # The only thing in a tool-hook payload that knows what the model has cost. Without it a
    # budget in hook mode caps nothing, because no model call passes through a tool hook.
    out["transcript_path"] = data.get("transcript_path") or ""
    return out


def _parse_codex(data: dict[str, Any], default_event: str) -> dict[str, Any]:
    """Codex CLI `PreToolUse`.

    https://learn.chatgpt.com/docs/hooks (checked 2026-09-16). Documented input fields:
    `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, `permission_mode`,
    `turn_id`, `tool_name`, `tool_use_id`, `tool_input`. Nearly identical to Claude Code's,
    which is why this function is nearly identical and still written out: the moment one of
    them adds a field, sharing the parser would hide it.
    """
    if not isinstance(data.get("tool_name"), str) or not data["tool_name"]:
        raise PayloadShapeError(
            "Codex PreToolUse payload has no string 'tool_name' "
            "(https://learn.chatgpt.com/docs/hooks)")
    out = _blank("codex", _phase(data.get("hook_event_name") or "", default_event))
    out["host_tool"] = data["tool_name"]
    out["tool"] = canonical_tool("codex", out["host_tool"])
    out["input"] = coerce_tool_input(data.get("tool_input"))
    out["response"] = data.get("tool_response")
    out["session_id"] = data.get("session_id") or ""
    out["cwd"] = data.get("cwd") or ""
    out["transcript_path"] = data.get("transcript_path") or ""
    return out


def _parse_gemini(data: dict[str, Any], default_event: str) -> dict[str, Any]:
    """Gemini CLI `BeforeTool`.

    https://geminicli.com/docs/hooks/reference/ (checked 2026-09-16). Documented input fields:
    `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`, `tool_name`,
    `tool_input`, optional `mcp_context`, `original_request_name`.
    """
    if not isinstance(data.get("tool_name"), str) or not data["tool_name"]:
        raise PayloadShapeError(
            "Gemini BeforeTool payload has no string 'tool_name' "
            "(https://geminicli.com/docs/hooks/reference/)")
    out = _blank("gemini", _phase(data.get("hook_event_name") or "", default_event))
    out["host_tool"] = data["tool_name"]
    out["tool"] = canonical_tool("gemini", out["host_tool"])
    out["input"] = coerce_tool_input(data.get("tool_input"))
    out["session_id"] = data.get("session_id") or ""
    out["cwd"] = data.get("cwd") or ""
    out["transcript_path"] = data.get("transcript_path") or ""
    return out


def _parse_copilot(data: dict[str, Any], default_event: str) -> dict[str, Any]:
    """GitHub Copilot CLI `preToolUse`.

    https://docs.github.com/en/copilot/reference/hooks-reference (checked 2026-09-16).
    Documented input fields, camelCase: `sessionId`, `timestamp`, `cwd`, `toolName`, `toolArgs`.
    There is no transcript path in this payload, so a spend cap cannot bind on this host and
    `guard.decide` is given no transcript rather than a guessed one.
    """
    if not isinstance(data.get("toolName"), str) or not data["toolName"]:
        raise PayloadShapeError(
            "Copilot preToolUse payload has no string 'toolName' "
            "(https://docs.github.com/en/copilot/reference/hooks-reference)")
    out = _blank("copilot", default_event)
    out["host_tool"] = data["toolName"]
    out["tool"] = canonical_tool("copilot", out["host_tool"])
    out["input"] = coerce_tool_input(data.get("toolArgs"))
    out["session_id"] = data.get("sessionId") or ""
    out["cwd"] = data.get("cwd") or ""
    return out


def _parse_cursor(data: dict[str, Any], default_event: str) -> dict[str, Any]:
    """Cursor `beforeShellExecution` and `beforeMCPExecution`.

    https://cursor.com/docs/agent/hooks (checked 2026-09-16). `beforeShellExecution` carries
    `command`, `cwd` and `sandbox`; `beforeMCPExecution` carries `tool_name`, `tool_input` (the
    parameters as a JSON *string*), `mcp_server_name` and the server's `url` or `command`. Both
    carry the base fields, of which `conversation_id` and `transcript_path` are used here.

    The shell event has no tool name, so "Bash" is supplied: the event IS the tool, and every
    command rule in the catalogue is written against that name.
    """
    event = (data.get("hook_event_name") or "").strip().lower()
    is_mcp = event == "beforemcpexecution" or (
        not event and "command" not in data and "tool_name" in data)
    out = _blank("cursor", default_event if default_event == "post" else "pre")
    out["session_id"] = data.get("conversation_id") or ""
    out["cwd"] = data.get("cwd") or ""
    out["transcript_path"] = data.get("transcript_path") or ""
    if is_mcp:
        if not isinstance(data.get("tool_name"), str) or not data["tool_name"]:
            raise PayloadShapeError(
                "Cursor beforeMCPExecution payload has no string 'tool_name' "
                "(https://cursor.com/docs/agent/hooks)")
        server = data.get("mcp_server_name") or ""
        out["host_tool"] = data["tool_name"]
        # Composed into Claude Code's MCP spelling so the catalogue's `mcp__*__[dD]elete*`
        # rules, which are the only rules that can screen an MCP call at all, keep matching.
        out["tool"] = f"mcp__{server}__{data['tool_name']}" if server else data["tool_name"]
        raw = data.get("tool_input")
        if isinstance(raw, str):
            # Documented as "JSON parameters as string". Parsed when it parses, so a rule reads
            # the parameters; kept as text when it does not, so nothing is silently dropped.
            try:
                raw = json.loads(raw)
            except ValueError:
                pass
        out["input"] = coerce_tool_input(raw)
        return out
    if not isinstance(data.get("command"), str):
        raise PayloadShapeError(
            "Cursor beforeShellExecution payload has no string 'command' "
            "(https://cursor.com/docs/agent/hooks)")
    out["host_tool"] = "beforeShellExecution"
    out["tool"] = "Bash"
    out["input"] = {"command": data["command"]}
    return out


# ---------------------------------------------------------------- output envelopes


def _render_claude_shape(verdict: str, reason: str) -> str:
    """The envelope Claude Code and Codex CLI both document, to the byte.

    https://code.claude.com/docs/en/hooks and https://learn.chatgpt.com/docs/hooks, both
    checked 2026-09-16. Codex's documented deny example is this object with these three keys
    and `hookEventName: "PreToolUse"`.
    """
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict,
        "permissionDecisionReason": reason,
    }})


def _render_gemini(verdict: str, reason: str) -> str:
    """https://geminicli.com/docs/hooks/reference/ (checked 2026-09-16): `{"decision": "deny",
    "reason": string}`. There is no allow envelope and no ask, so an allow renders NOTHING.

    That page also warns: "Your script must not print any plain text to stdout other than the
    final JSON." Everything this project prints that is not a verdict goes to stderr, which is
    why `run_hook` returns stdout and stderr separately instead of printing as it goes.
    """
    return json.dumps({"decision": verdict, "reason": reason})


def _render_copilot(verdict: str, reason: str) -> str:
    """https://docs.github.com/en/copilot/reference/hooks-reference (checked 2026-09-16):
    `{"permissionDecision": "deny", "permissionDecisionReason": string}`, with allow, deny and
    ask. Documented caveat, repeated in the docs we ship: under the Copilot cloud agent "a
    decision of 'ask' is treated as 'deny' because no user is available to answer", so an
    oversight rule stops the work there instead of prompting.
    """
    return json.dumps({"permissionDecision": verdict, "permissionDecisionReason": reason})


def _render_cursor(verdict: str, reason: str) -> str:
    """https://cursor.com/docs/agent/hooks (checked 2026-09-16): `{"permission": "allow" |
    "deny" | "ask", "user_message": ..., "agent_message": ...}`.

    Cursor is the one host that needs an explicit ALLOW on stdout. Its documentation says
    "Invalid JSON or schema mismatches block the action", so printing nothing for an allowed
    command risks blocking every ordinary command in the session, which is how a guard gets
    uninstalled by lunchtime.
    """
    out: dict[str, Any] = {"permission": verdict}
    if reason:
        out["user_message"] = reason
        out["agent_message"] = reason
    return json.dumps(out)


# ---------------------------------------------------------------- the table

#: Everything host-shaped, once. `parse` and `render` are the two things that were Claude Code
#: specific; `ask` says whether the host can put the decision to a human; `install` is the
#: config file that wires the hook up, per the vendor page in `doc`.
HOSTS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "label": "Claude Code",
        "doc": "https://code.claude.com/docs/en/hooks",
        "checked": "2026-09-16",
        "events": ("PreToolUse", "PostToolUse"),
        "ask": True,
        "parse": _parse_claude_code,
        "render": _render_claude_shape,
        "config": ".claude/settings.json",
    },
    "codex": {
        "label": "Codex CLI",
        "doc": "https://learn.chatgpt.com/docs/hooks",
        "checked": "2026-09-16",
        "events": ("PreToolUse",),
        # Codex documents `permissionDecision` on PreToolUse; whether it honours "ask" there,
        # and how its `PermissionRequest` event behaves, has not been driven, so oversight is
        # enforced as a block and the record keeps `require_oversight`.
        "ask": False,
        "parse": _parse_codex,
        "render": _render_claude_shape,
        "config": ".codex/hooks.json",
    },
    "gemini": {
        "label": "Gemini CLI",
        "doc": "https://geminicli.com/docs/hooks/reference/",
        "checked": "2026-09-16",
        "events": ("BeforeTool",),
        "ask": False,
        "parse": _parse_gemini,
        "render": _render_gemini,
        "config": ".gemini/settings.json",
    },
    "copilot": {
        "label": "GitHub Copilot CLI",
        "doc": "https://docs.github.com/en/copilot/reference/hooks-reference",
        "checked": "2026-09-16",
        "events": ("preToolUse",),
        "ask": True,
        "parse": _parse_copilot,
        "render": _render_copilot,
        "config": ".github/hooks/provenrail.json",
    },
    "cursor": {
        "label": "Cursor",
        "doc": "https://cursor.com/docs/agent/hooks",
        "checked": "2026-09-16",
        "events": ("beforeShellExecution", "beforeMCPExecution"),
        "ask": True,
        "parse": _parse_cursor,
        "render": _render_cursor,
        "config": ".cursor/hooks.json",
    },
}

#: Stable order for help text, argparse choices and docs.
HOST_NAMES: tuple[str, ...] = tuple(HOSTS)


def spec(host: str) -> dict[str, Any]:
    try:
        return HOSTS[host]
    except KeyError:
        raise UnknownHost(
            f"unknown host {host!r}; known hosts: {', '.join(HOST_NAMES)}") from None


def label(host: str) -> str:
    return spec(host)["label"]


def supports_ask(host: str) -> bool:
    return bool(spec(host)["ask"])


def parse(host: str, data: dict[str, Any], default_event: str = "pre") -> dict[str, Any]:
    """Normalise one host's hook payload into the fields the policy engine needs.

    Returns `host`, `event`, `tool` (already translated to the catalogue's names), `host_tool`,
    `input`, `response`, `session_id`, `cwd`, `transcript_path`.
    """
    if not isinstance(data, dict):
        raise PayloadShapeError("hook payload was not a JSON object")
    return spec(host)["parse"](data, default_event)


#: Appended when the policy asked for a human and the host has no way to ask one. It names the
#: downgrade out loud, because an agent told only "blocked" will retry a different spelling,
#: and the person reading the transcript deserves to know a human WOULD have been asked here.
NO_ASK_NOTE = (" This host cannot put a decision to a human, so an oversight rule is enforced "
               "as a block; it is recorded as require_oversight, not as a denial.")

#: Appended on a host that can ask. Identical wording in both engines, on purpose.
ASK_NOTE = " (approve here and the approval is recorded as human oversight)"


def host_verdict(host: str, verdict: str) -> str:
    """The verdict this host can actually express, given what the policy decided.

    `ask` becomes `deny` where there is nobody to ask. What the POLICY decided is never
    rewritten by this function; only what the host is told is.
    """
    if verdict == "ask" and not supports_ask(host):
        return "deny"
    return verdict


def render(host: str, verdict: str, reason: str) -> str:
    """The exact stdout this host expects for `verdict`, or "" when it expects nothing.

    `verdict` is the POLICY verdict ("allow", "deny" or "ask"). The reason is extended, not
    replaced, when the host cannot express what the policy asked for.
    """
    entry = spec(host)
    actual = host_verdict(host, verdict)
    if verdict == "ask":
        reason += ASK_NOTE if entry["ask"] else NO_ASK_NOTE
    if actual == "allow":
        # Every host except Cursor reads silence as "this hook has no opinion". Cursor reads a
        # missing envelope as a schema mismatch and blocks, so it gets an explicit allow.
        if host != "cursor":
            return ""
        return entry["render"]("allow", "")
    return entry["render"](actual, reason)


# ---------------------------------------------------------------- install

#: How each host wires a command to its pre-tool event. `top` is merged into the file only
#: where the key is absent, so a file the user already owns keeps its own values. `entry` is a
#: callable so the command string appears once per host rather than once per event.
#:
#: The matchers are regular expressions on every host that has one except Claude Code, whose
#: matcher is a glob; `.*` and `*` are the same intent spelled two ways, and getting this
#: backwards would install a guard that matches one tool called ".*".
_INSTALL: dict[str, dict[str, Any]] = {
    "codex": {
        "path": (".codex", "hooks.json"),
        "top": {},
        "events": lambda cmd, t: {"PreToolUse": [
            {"matcher": ".*", "hooks": [{"type": "command", "command": cmd, "timeout": t}]}]},
    },
    "gemini": {
        "path": (".gemini", "settings.json"),
        "top": {},
        "events": lambda cmd, t: {"BeforeTool": [
            {"matcher": ".*", "hooks": [{"type": "command", "command": cmd,
                                         "name": "provenrail-guard", "timeout": t}]}]},
    },
    "copilot": {
        # Its own file under `.github/hooks/`, which the vendor documents as a directory of
        # `*.json`. A separate file is additive by construction: nothing of the user's is in it.
        "path": (".github", "hooks", "provenrail.json"),
        "top": {"version": 1},
        "events": lambda cmd, t: {"preToolUse": [
            {"type": "command", "bash": cmd, "timeoutSec": t}]},
    },
    "cursor": {
        "path": (".cursor", "hooks.json"),
        "top": {"version": 1},
        "events": lambda cmd, t: {
            "beforeShellExecution": [{"command": cmd, "timeout": t}],
            # failClosed is left at Cursor's default (false) deliberately: a hook that breaks
            # must not brick the session, and that trade is stated in the README rather than
            # decided quietly here.
            "beforeMCPExecution": [{"command": cmd, "timeout": t}],
        },
    },
}


def install_plan(host: str, command: str, timeout: int) -> dict[str, Any]:
    """What `guard.install_hooks` must write for `host`: path parts, top-level defaults, entries.

    Claude Code is not here because it has had its own installer since before this module
    existed, including an uninstaller and a PostToolUse entry, and rewriting a working
    installer to prove a point is how the working one breaks.
    """
    plan = _INSTALL.get(host)
    if plan is None:
        spec(host)  # raises UnknownHost for a host nobody has a contract for
        raise UnknownHost(
            f"{host} has no per-host installer; use `pr guard install` for {label(host)}")
    return {"path": plan["path"], "top": dict(plan["top"]),
            "entries": plan["events"](command, timeout)}
