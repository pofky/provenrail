"""Guardrails for coding agents, at the tool boundary, with a signed receipt.

`pr guard` wires Provenrail's existing policy engine into a coding agent's own hook
mechanism, so a destructive tool call is stopped *before* it runs and the decision is
written into the same signed, hash-chained record stream as everything else.

The order of operations is the point:

1. **Decide offline.** The verdict comes from the policy in `.provenrail.json`, evaluated
   in this process with no network call. A sink that is down, slow, or unreachable can
   therefore never turn a deny into an allow.
2. **Then record.** The decision is pushed to the sink as evidence. If that fails, the
   decision is appended to a local journal (`.provenrail-guard.jsonl`) and `pr guard status`
   reports the backlog. A journalled decision is honestly reported as *unsigned and pending*,
   never as proof.

Supported host today: **Claude Code** (`PreToolUse` / `PostToolUse` hooks). Other agents are
not claimed until their hook contract has been read and tested; a guardrail that silently
does nothing is worse than no guardrail.

Effect mapping, which is where this is better than a shell script: the policy's three effects
map onto Claude Code's three permission decisions rather than being flattened into "block".

| Policy effect                        | Claude Code decision | Meaning                          |
|--------------------------------------|----------------------|----------------------------------|
| `deny`                               | `deny`               | stopped, agent is told why       |
| `require_oversight` (none recorded)  | `ask`                | the human decides, in the UI     |
| `limit` over cap                     | `deny`               | blast-radius cap reached         |
| allow                                | (silent)             | nothing added to the agent's path|

`require_oversight` becoming `ask` matters: the human's approval in the Claude Code prompt IS
the oversight the rule wanted, so the rule stays useful instead of blocking legitimate work
and being switched off within a day.

Spend caps bind here too, and for a long time they did not. No model call passes through a tool
hook, so a budget in `.provenrail.json` used to sit in the policy, print itself as armed in
`pr guard status`, and cap nothing at all in the install this product recommends. The hook
payload does carry `transcript_path`, and the transcript carries `message.model` and
`message.usage`, so the spend is priced from it (`transcript.py`), added to the local ledger,
and the NEXT tool call is refused once the cap is over. That is a turn late by construction,
because the host writes the transcript asynchronously, so nothing here claims to stop the agent
at the exact dollar. Every figure is an estimate at API list price and is notional on Pro and
Max, where there is no per-token charge to cap, and every string that shows one says so.

`limit` rules need one more thing. Every hook invocation is a separate process, so a count held
only in memory resets on every call and a "3 deletions per session" cap caps nothing, while
`pr guard status` still reports it as armed. The counts are therefore carried across processes
in `.provenrail-guard-counts.json`. That file is local and editable, so it is a convenience,
not evidence, and the rules that do the real protecting (`deny`, `require_oversight`) never
read it: editing or deleting it cannot unblock anything.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

JOURNAL_FILENAME = ".provenrail-guard.jsonl"
CLAUDE_SETTINGS = Path(".claude") / "settings.json"
HOOK_COMMAND = "pr guard hook"
HOOK_TIMEOUT_S = 15

# What `pr guard install` arms when the project has no policy yet. Chosen for a coding agent
# working in a repo: the things that destroy work, leak credentials, or hand out access.
#
# `access` is included because two of its rules (world-writable chmod, disabling MFA) match on
# command text a coding agent really does produce, and both are advertised as blocked. Its other
# two match tool-name patterns Claude Code never emits, so they cost nothing. Money, exfiltration
# and blast-radius are still opt-in: they fire on tool names a coding agent does not use, so
# arming them by default would add noise without adding protection.
#
# Anything named in the marketing copy has to be in this list. `tests/test_guard.py` asserts it
# command by command, because "we say it blocks X" and "it blocks X" drifting apart is the one
# bug a guardrail cannot survive.
# The packs a fresh install arms. `git-worktree` is first because it is the incident class
# people actually report: uncommitted work destroyed by `git reset --hard` or `git checkout --`,
# not by anything containing `rm`.
DEFAULT_PACKS = ["git-worktree", "destructive", "database", "cloud", "secrets", "production",
                 "access"]

# Every tool. A named list looks careful and was a hole: it covered the built-in tools and
# nothing else, so an MCP server's `deleteVolume` (the exact shape of the PocketOS incident this
# product's own copy cites) and a `Read` of `~/.ssh/id_ed25519` were never seen by any rule,
# while the catalogue advertised rules for both. Scope belongs in the rules, where it is
# declared per rule and visible in `pr guard rules`, not in a matcher nobody reads. Rules that
# do not apply to a tool now say so with `not_tool`.
_DEFAULT_MATCHER = "*"


class GuardError(RuntimeError):
    """A guard operation failed in a way the user must see (bad settings file, no config)."""


# ---------------------------------------------------------------- hook payload


def _coerce_tool_input(value: Any) -> Any:
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


def parse_hook_input(data: dict[str, Any], default_event: str = "pre") -> dict[str, Any]:
    """Normalize a Claude Code hook payload into the fields the policy engine needs.

    Claude Code sends `tool_name` plus a `tool_input` object (for Bash: `{"command": ...}`),
    and on PostToolUse a `tool_response`. Everything is read with `.get()`: an unknown or
    renamed field must degrade to "record it anyway", never to a crash inside the agent's
    critical path.
    """
    event = (data.get("hook_event_name") or "").strip().lower()
    if event.startswith("posttool"):
        phase = "post"
    elif event.startswith("pretool"):
        phase = "pre"
    else:
        # Hook name absent or renamed upstream: fall back to the phase the installed command
        # declares, rather than guessing "pre" and gating a call that already ran.
        phase = default_event
    return {
        "event": phase,
        "tool": data.get("tool_name") or "",
        # A non-dict tool_input used to become `{}`, which every content rule then matched
        # against the two characters "{}" and let through. For the Bash tool that is the ENTIRE
        # protection, because the tool name alone cannot tell `ls` from `rm -rf /`, so one
        # payload with tool_input as a string silently disarmed the guard. Anything that is not
        # a dict is now kept and screened as text: a string command is exactly the thing that
        # most needs reading, and a shape we do not recognise must never mean "allow".
        "input": _coerce_tool_input(data.get("tool_input")),
        "response": data.get("tool_response"),
        "session_id": data.get("session_id") or "",
        "cwd": data.get("cwd") or "",
        # The only thing in a tool-hook payload that knows what the model has cost. Without it
        # a budget in hook mode caps nothing, because no model call passes through a tool hook.
        "transcript_path": data.get("transcript_path") or "",
    }


def match_text(tool_input: Any) -> str:
    """The bounded text view a content rule (`arg_contains`) matches against.

    Computed in-process and never sent to the sink, so a content gate stays local: the
    recorded payload still stores a hash of the arguments unless the user opts into content
    capture.
    """
    from .sdk import _match_text
    return _match_text(tool_input)


# ---------------------------------------------------------------- decision


def _rule_effect(policy: Any, rule_id: str | None) -> str:
    if not rule_id or policy is None:
        return ""
    from .policy import REQUIRE_OVERSIGHT, UNSCREENABLE

    if rule_id == UNSCREENABLE:
        # The engine could not read the argument, which is not the same as a rule saying no.
        # A human decides: hard-blocking here would refuse a legitimate multi-megabyte file
        # write, and allowing would restore the padding bypass this exists to close.
        return REQUIRE_OVERSIGHT
    for rule in getattr(policy, "rules", []):
        if rule.id == rule_id:
            return rule.effect
    return ""


def _seed_prior_spend(policy: Any, state: Any) -> None:
    """Load recorded spend into the state a hook process rebuilds from scratch.

    A hook fires in a fresh process every time, so a `SessionState` built here starts at zero
    spend and a budget evaluated against it can never bind: it would report as armed while
    capping nothing. Seeding from the local ledger is what makes a budget honest in hook mode.
    Model calls do not pass through a tool hook, so this is for reporting and for future
    tool-side budget gates; it is deliberately skipped when no cross-session budget exists.
    """
    from .policy import SESSION

    try:
        budgets = policy.effective_budgets()
    except AttributeError:
        return
    if not any(b.scope != SESSION for b in budgets):
        return
    from . import spend as spend_ledger
    day, total, known = spend_ledger.prior_spend(spend_agent_id())
    state.prior_day_usd, state.prior_total_usd, state.prior_known = day, total, known


#: Said on stderr, at most once a day, when budgets are configured but the spend they are
#: supposed to cap cannot be counted. A guard that cannot bind and does not say so is worse than
#: no guard: `pr guard status` would keep printing the cap while nothing enforced it.
CANNOT_BIND = "provenrail: spend cap cannot bind: "


def _apply_transcript_spend(policy: Any, state: Any, transcript_path: str | None,
                            session_id: str | None) -> str:
    """Price the agent's transcript since the last tool call and put the total into `state`.

    Returns a stderr notice, or "". The notice is the important half: every path here that
    cannot produce a number says which one it took, because the failure mode this feature has
    is invisible by construction. A cap that silently stops counting looks exactly like a cap
    with nothing to count.
    """
    from . import spend as spend_ledger
    from . import transcript as transcript_mod
    from .policy import SESSION

    budgets = policy.effective_budgets()
    if not budgets:
        # No budget, no transcript I/O. This is why the check is first: reading and pricing a
        # multi-megabyte transcript on every tool call of every project that has never set a
        # cap would be a tax paid by everyone for a feature almost nobody has turned on.
        return ""
    if not transcript_path:
        return _once_a_day("spend-no-transcript", CANNOT_BIND + (
            "this hook payload carried no transcript_path, so no model spend can be seen from "
            "here. The cap in the policy is not enforcing anything.\n"))
    if not session_id:
        # The read cursor is keyed on the transcript and survives this, but a `session`-scope
        # figure has nowhere to live without a session key, and answering a session cap from a
        # total that restarts at zero every tool call would report a cap as binding while it
        # never fired. Not counting is the honest answer, and the notice says so.
        return _once_a_day("spend-no-session", CANNOT_BIND + (
            "this hook payload carried no session_id, so this session's own spend total cannot "
            "be kept between tool calls and spend is not being counted.\n"))

    st = load_spend_state(session_id, transcript_path)
    resumed_known = st.known
    new_cost, _unpriced, st = transcript_mod.accrue(transcript_path, st)
    save_spend_state(session_id, transcript_path, st)
    if new_cost > 0:
        spend_ledger.add_spend(new_cost, spend_agent_id())

    day, total, ledger_known = spend_ledger.prior_spend(spend_agent_id())
    # The ledger already contains this session's spend, because it was just added to it. A
    # `session` budget still needs the session figure on its own, so the session total is held
    # in `spend_usd` and subtracted out of the cross-session figures rather than counted twice.
    session_usd = st.session_usd
    state.spend_usd = session_usd
    state.prior_day_usd = max(0.0, day - session_usd)
    state.prior_total_usd = max(0.0, total - session_usd)
    state.prior_known = ledger_known and st.known and resumed_known
    state.unpriced_calls = st.unpriced_calls

    if not st.known or not resumed_known:
        return _once_a_day("spend-unreadable", CANNOT_BIND + (
            "transcript unreadable. Part of this session's model spend could not be priced, so "
            f"the figures below are a floor, not a total ({transcript_path}).\n"))
    if not ledger_known and any(b.scope != SESSION for b in budgets):
        return _once_a_day("spend-ledger", CANNOT_BIND + (
            "the local spend ledger could not be read, so spend from earlier sessions is not "
            "counted and a day or total cap sees only this session.\n"))
    return ""


def policy_spec(config: dict[str, Any] | None) -> Any:
    """The policy the hook will actually evaluate, given the contents of `.provenrail.json`.

    One function because two readers of the same file must not reach different answers: the hook
    decides with it and `pr guard status` prints what is armed, and a status line that says "0
    rules armed" while the hook arms forty-four is the same lie as a guard that silently does
    nothing.

    A policy block that says nothing about RULES is not a decision to run without any.
    `pr guard budget 25` in a fresh project writes exactly such a block, and reading it as "the
    user chose no rules" meant that arming a spend cap silently switched every destructive rule
    off. Turning one control on must never turn another one off. An explicit `use` (including an
    empty one) or an explicit `rules` list is still a decision, and still wins completely.
    """
    spec = (config or {}).get("policy")
    if isinstance(spec, dict) and "use" not in spec and "rules" not in spec:
        return {**spec, "use": list(DEFAULT_PACKS)}
    return spec


def spend_agent_id() -> str:
    """Ledger key for guard mode: the configured stream, else a shared default."""
    from .easy import _load_config_file
    try:
        cfg = _load_config_file()
    except Exception:
        return "default"
    return str(cfg.get("stream_id") or cfg.get("agent_id") or "default")


def budget_status(policy: Any) -> list[dict[str, Any]]:
    """Budget headroom for `pr guard status`, read from the local ledger."""
    from .policy import SessionState
    from .policy import budget_status as _status

    if policy is None:
        return []
    state = SessionState()
    _seed_prior_spend(policy, state)
    return _status(policy, state)


def decide(policy: Any, tool: str, tool_input: Any,
           session_id: str | None = None, cwd: str | None = None,
           transcript_path: str | None = None) -> dict[str, Any]:
    """Evaluate the policy for one attempted tool call. Offline, no network.

    Returns a dict with `verdict` ("allow" | "deny" | "ask"), the firing rule and reason.

    `transcript_path` is what makes a spend cap real here. The model call that cost the money
    never reaches a tool hook, so a budget used to sit in the policy binding nothing; given the
    transcript the host already names in its payload, the spend is priced, added to the ledger,
    and the next tool call is refused once the cap is over. That is a turn late by construction,
    which is why nothing here ever claims to stop the agent at the exact dollar.

    Each hook invocation is its own process, so `limit` rules (blast-radius caps such as "at
    most 3 file deletions per session") would reset on every call and cap nothing. When a
    `session_id` is supplied the running counts are carried across processes in a small local
    state file, so a cap actually caps. That file is a convenience, not evidence: anything that
    can write the working directory can reset it, exactly like the journal. `deny` and
    `require_oversight` rules never consult it and are unaffected.
    """
    from .policy import ALLOW, DENY, REQUIRE_OVERSIGHT, SessionState

    if policy is None:
        return {"verdict": "allow", "rule": None, "reason": "no policy configured",
                "effect": ALLOW}
    # `cwd` is what lets a rule tell `rm -rf .next` from `rm -rf ~`: the difference is not in
    # the text, it is in where the text points. Claude Code sends it with every hook call.
    ctx = {"tool": tool, "match_text": match_text(tool_input), "cwd": cwd or ""}
    state = SessionState(counts=load_counts(session_id) if session_id else {})
    _seed_prior_spend(policy, state)
    notice = _apply_transcript_spend(policy, state, transcript_path, session_id)

    # Before the rule loop, because a blown cap is not a question about this particular command:
    # once the money is gone, the next tool call is the one that has to stop, whatever it is.
    spent = policy.spent_verdict(state)
    if spent is not None and spent.effect == DENY:
        return {"verdict": "deny", "rule": spent.rule_id, "reason": spent.reason,
                "effect": DENY, "shape": _matched_shape(policy, spent.rule_id, ctx),
                "warning": None, "notice": notice}
    budget_warning = spent.warning if spent is not None else None

    before = dict(state.counts)
    decision = policy.decide("tool_call", ctx, state)
    if session_id and state.counts != before:
        save_counts(session_id, state.counts)
    effect = _rule_effect(policy, decision.rule_id)
    if decision.effect == ALLOW:
        verdict = "allow"
    elif effect == REQUIRE_OVERSIGHT:
        # The human answering the Claude Code permission prompt IS the oversight this rule
        # asked for, so hand them the decision instead of hard-blocking work they would have
        # approved. Recorded either way.
        verdict = "ask"
    else:
        verdict = "deny"
    return {"verdict": verdict, "rule": decision.rule_id, "reason": decision.reason,
            "effect": effect or (DENY if verdict == "deny" else ALLOW),
            "shape": _matched_shape(policy, decision.rule_id, ctx) if verdict != "allow" else "",
            "warning": budget_warning, "notice": notice}


def _matched_shape(policy: Any, rule_id: str | None, ctx: dict[str, Any]) -> str:
    """The verb and flags of the single command that fired the rule, with operands dropped.

    This is what makes a block worth showing anyone. "destructive.recursive-force-remove" says
    nothing; "rm -rf, outside the project" is a sentence. It is not the command: every operand
    is dropped, because operands are where a path, a hostname and an API key live, and a block
    is only shareable if what it records cannot be a secret.
    """
    from .shell import command_shape, segments

    text = ctx.get("match_text", "")
    if not isinstance(text, str) or not text:
        return ""
    rule = next((r for r in getattr(policy, "rules", []) if r.id == rule_id), None)
    if rule is None or not getattr(rule, "arg_contains", ""):
        return command_shape(text)
    import re as _re
    pattern = _re.compile(rule.arg_contains, _re.IGNORECASE | _re.DOTALL)
    for part in segments(text):
        if pattern.search(part):
            return command_shape(part)
    return command_shape(text)


# ---------------------------------------------------------------- recording


def _journal_path() -> Path:
    """Where the journal and the sibling state files live.

    Anchored to the directory holding `.provenrail.json`, not to the current directory, so an
    agent launched from a subdirectory keeps writing to the same place the policy came from.
    Otherwise a session run from `apps/web` would start a second, invisible journal and its
    blast-radius counters would restart from zero.
    """
    override = os.environ.get("PROVENRAIL_GUARD_JOURNAL")
    if override:
        return Path(override)
    from .easy import find_config_file
    config = find_config_file()
    return (config.parent / JOURNAL_FILENAME) if config else Path(JOURNAL_FILENAME)


def journal(entry: dict[str, Any]) -> None:
    """Append a decision that could not be recorded off-box, so it is not simply lost.

    A journal line is NOT evidence: it is unsigned, local, and editable by anything that can
    write the file. It exists so `pr guard status` can tell you the receipt chain has a gap
    and why, which is the honest alternative to silently dropping the record.
    """
    try:
        with _journal_path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        pass  # never fail the agent's tool call because a log line could not be written


def read_journal() -> list[dict[str, Any]]:
    path = _journal_path()
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def card() -> str:
    """A paste-ready summary of what the guard has stopped in this project.

    The only visible moment a guardrail has is the moment it says no, and until now that moment
    left nothing behind but a rule id in a terminal that scrolls away. Every public thread about
    a coding agent destroying someone's work is a post-mortem written afterwards; this is the
    same story told before the loss, which is the version worth reading.

    Nothing identifying goes in. Not the project name, not a path, not an operand: the directory
    becomes a truncated hash so two cards from the same project match without naming it, and
    each command is reduced by `shell.command_shape` to its verb and flags. That is what makes
    it something a person can paste in public without reading it line by line first.
    """
    import hashlib
    import time

    entries = [e for e in read_journal() if e.get("verdict") in ("deny", "ask")]
    digest = hashlib.sha256(str(_journal_path().parent).encode("utf-8")).hexdigest()[:8]
    if not entries:
        return ("Provenrail guard has not had to stop anything here yet.\n\n"
                "  Armed and watching. `pr guard status` shows what is armed.\n")

    denies = sum(1 for e in entries if e["verdict"] == "deny")
    plural = "" if len(entries) == 1 else "s"
    lines = [
        f"Provenrail guard stopped {len(entries)} command{plural} in this repo "
        f"({denies} refused, {len(entries) - denies} sent to me to approve).",
        "",
    ]
    for entry in entries[-10:]:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("at", 0)))
        shape = entry.get("shape") or entry.get("tool") or "?"
        lines.append(f"  {stamp}  {entry.get('verdict', '?'):<8} {shape}")
        lines.append(f"  {' ' * len(stamp)}  {entry.get('rule') or ''}")
    lines += [
        "",
        f"  repo {digest} (hashed, not the name). Commands are shown as verb and flags only;",
        "  every operand is dropped, so nothing here can be a path or a key.",
        "",
        "  Signed and verifiable version:  pr guard receipt && pr verify guard-receipt.json",
    ]
    return "\n".join(lines) + "\n"


PENDING_FILENAME = ".provenrail-guard-pending.json"


def _pending_path() -> Path:
    return _journal_path().with_name(PENDING_FILENAME)


def mark_ask(session_id: str, tool: str, rule: str) -> None:
    """Remember that a call was escalated to the human, so the outcome can be recorded.

    Hook invocations are separate processes, so the PostToolUse hook cannot otherwise know
    that PreToolUse asked. Without this the record would show an oversight-gated tool call
    executing with no oversight, and an offline verifier would rightly report that the
    committed policy was not enforced.
    """
    try:
        path = _pending_path()
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        if not isinstance(data, dict):
            data = {}
        data[f"{session_id}|{tool}"] = rule
        path.write_text(json.dumps(data), encoding="utf-8")
    except (OSError, ValueError):
        pass


def take_ask(session_id: str, tool: str) -> str | None:
    """Pop the pending escalation for this call, if there was one."""
    try:
        path = _pending_path()
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        rule = data.pop(f"{session_id}|{tool}", None)
        if rule is not None:
            path.write_text(json.dumps(data), encoding="utf-8")
        return rule
    except (OSError, ValueError):
        return None


COUNTS_FILENAME = ".provenrail-guard-counts.json"
# How long a session's counters survive. Claude Code reuses a session id across a working
# day, so this has to outlive a lunch break; it must not outlive the machine, or a cap set
# weeks ago would deny the first matching call of a fresh session.
COUNTS_TTL_S = 7 * 24 * 3600
_COUNTS_MAX_SESSIONS = 200


def _counts_path() -> Path:
    return _journal_path().with_name(COUNTS_FILENAME)


def _write_json_atomic(path: Path, data: Any) -> None:
    """Replace the file in one step so a concurrent reader never sees a half-written file."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def _read_counts_file() -> dict[str, Any]:
    try:
        path = _counts_path()
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_counts(session_id: str) -> dict[str, int]:
    """Per-rule match counts carried over from earlier hook processes in this session."""
    entry = _read_counts_file().get(session_id)
    if not isinstance(entry, dict):
        return {}
    counts = entry.get("counts")
    if not isinstance(counts, dict):
        return {}
    return {str(k): int(v) for k, v in counts.items() if isinstance(v, (int, float))}


def _save_session_entry(session_id: str, **fields: Any) -> None:
    """Merge fields into this session's entry, pruning stale sessions.

    Merge, not replace: the entry now carries two independent things, the blast-radius counters
    and the transcript spend cursor. Writing one by assigning a whole new entry dropped the
    other, and dropping the spend cursor resets the read offset to zero, which charges the
    entire transcript to the ledger again on the next tool call.

    Best effort by design: failing to write must never fail the user's tool call, and the
    deny/oversight rules that do the real protecting never read this file.
    """
    import time

    now = int(time.time())
    try:
        data = _read_counts_file()
        entry = data.get(session_id)
        entry = dict(entry) if isinstance(entry, dict) else {}
        entry.update(fields)
        entry["updated"] = now
        data[session_id] = entry
        fresh = {k: v for k, v in data.items()
                 if isinstance(v, dict) and now - int(v.get("updated", 0) or 0) < COUNTS_TTL_S}
        if len(fresh) > _COUNTS_MAX_SESSIONS:
            keep = sorted(fresh.items(), key=lambda kv: -int(kv[1].get("updated", 0) or 0))
            fresh = dict(keep[:_COUNTS_MAX_SESSIONS])
            fresh.setdefault(session_id, entry)
        _write_json_atomic(_counts_path(), fresh)
    except (OSError, ValueError):
        pass


def save_counts(session_id: str, counts: dict[str, int]) -> None:
    """Persist this session's blast-radius counters."""
    _save_session_entry(session_id, counts=dict(counts))


def load_spend_state(session_id: str, transcript_path: str) -> Any:
    """The transcript cursor, plus this session's own total. Keyed as `transcript.find_state`
    describes: the cursor on the transcript, the session figure on the session."""
    from . import transcript
    return transcript.find_state(_read_counts_file(), transcript.state_key(transcript_path),
                                 session_id)


def save_spend_state(session_id: str, transcript_path: str, state: Any) -> None:
    from . import transcript
    _save_session_entry(transcript.state_key(transcript_path), spend=state.cursor_dict())
    _save_session_entry(session_id, spend=state.session_dict())


def reset_counts(session_id: str | None = None) -> None:
    """Clear blast-radius counters, for one session or all of them."""
    try:
        if session_id is None:
            _counts_path().unlink(missing_ok=True)
            return
        data = _read_counts_file()
        if data.pop(session_id, None) is not None:
            _write_json_atomic(_counts_path(), data)
    except OSError:
        pass


def record_hook(hook: dict[str, Any], decision: dict[str, Any] | None) -> bool:
    """Best-effort: write this hook's evidence into the signed chain. Returns success.

    One short session per hook process, tagged with the host session id, because hook
    invocations are separate processes and a chain cannot span them. The verifier is
    session-aware, so many one-event sessions on one stream verify exactly like one long
    session, each rooted in its own genesis record.
    """
    from .chain import POLICY_DECISION
    from .easy import make_recorder

    try:
        recorder = make_recorder("claude-code")
    except Exception:
        return False
    # We have already decided, offline, whether this call is allowed. The recorder must not
    # decide again and raise: its job here is evidence, not enforcement.
    recorder.enforce = False
    try:
        meta = {"agent": "claude-code", "host": "claude-code", "hook": hook["event"],
                "host_session_id": hook.get("session_id", "")}
        with recorder.session(meta):
            if decision is not None and decision.get("rule"):
                # The recorded effect is the verdict that was actually applied. An escalation
                # is NOT a denial: flattening "the human was asked" into "blocked" would
                # overstate the evidence, and every downstream reader (pr risk, the alert
                # engine, the verifier's replay) counts denials for real.
                effect = {"allow": "allow", "deny": "deny",
                          "ask": "require_oversight"}[decision["verdict"]]
                recorder.record(POLICY_DECISION, {
                    "effect": effect,
                    "rule": decision["rule"],
                    "reason": decision["reason"],
                    "event_type": "tool_call",
                    "target": hook.get("tool", ""),
                    "enforced": True,
                    "extra": {"verdict": decision["verdict"], "host": "claude-code"},
                })
            if hook["event"] == "post":
                # The call ran, so if it had been escalated the human approved it in the
                # permission prompt. Record that approval as the oversight it is.
                approved = take_ask(hook.get("session_id", ""), hook.get("tool", ""))
                if approved:
                    recorder.record_human_oversight(
                        "approved in the Claude Code permission prompt",
                        rule=approved, tool=hook.get("tool", ""), host="claude-code")
                response = hook.get("response")
                outcome = "failure" if _looks_failed(response) else "success"
                recorder.record_tool_call(hook.get("tool", ""), hook.get("input"), response,
                                          outcome=outcome, _skip_policy=True,
                                          host="claude-code")
        return True
    except Exception:
        return False


def _looks_failed(response: Any) -> bool:
    if isinstance(response, dict):
        for key in ("error", "is_error", "isError"):
            if response.get(key):
                return True
    return False


NOTICE_FILENAME = ".provenrail-guard-notice"
_NOTICE_INTERVAL_S = 24 * 3600


def _once_a_day(name: str, message: str) -> str:
    """Return `message` at most once a day, keyed by `name`. Silence in between.

    The zero-install engine has the same function for the same reason: a warning printed on
    every tool call is noise, noise gets the plugin uninstalled, and silence about a guard that
    cannot do its job is the one thing that is worse than noise.
    """
    import time

    try:
        path = _journal_path().with_name(NOTICE_FILENAME + "-" + name)
        now = time.time()
        if path.is_file() and now - path.stat().st_mtime < _NOTICE_INTERVAL_S:
            return ""
        path.write_text(str(int(now)), encoding="utf-8")
    except OSError:
        return ""  # cannot track it, so do not risk warning on every single call
    return message


def _no_policy_notice() -> str:
    """Warn, at most once a day, that hooks are installed but no guardrails are armed.

    Once a day rather than every tool call: a warning on every call is noise, and noise gets
    the plugin uninstalled. Silence, though, is worse than noise here, because the failure is
    invisible by construction.
    """
    import time

    try:
        path = _journal_path().with_name(NOTICE_FILENAME)
        now = time.time()
        if path.is_file() and now - path.stat().st_mtime < _NOTICE_INTERVAL_S:
            return ""
        path.write_text(str(int(now)), encoding="utf-8")
    except OSError:
        return ""  # cannot track it, so do not risk warning on every single call
    return ("provenrail: hooks are installed but NO guardrails are armed, so nothing is being "
            "blocked or recorded. Run `pr guard install` in this project, or `pr guard status` "
            "to see what is (and is not) in force.\n")


def _first_run_notice(policy: Any, config_exists: bool) -> str:
    """The same first-run notice the zero-install plugin prints, from the same module.

    Rendered only when the defaults armed themselves, and only once a day, on the same stamp
    file the plugin uses so switching engines does not re-announce.
    """
    import time

    from . import rulesets, welcome

    try:
        path = _journal_path().with_name(".provenrail-guard-notice-armed")
        now = time.time()
        if path.is_file() and now - path.stat().st_mtime < _NOTICE_INTERVAL_S:
            return ""
        path.write_text(str(int(now)), encoding="utf-8")
    except OSError:
        return ""
    armed = [{"id": r.id, "effect": r.effect} for r in getattr(policy, "rules", [])]
    packs = {name: {"title": spec["title"]} for name, spec in rulesets.CATALOG.items()}
    return welcome.first_run_notice(armed, packs, ".provenrail.json", signed=True,
                                    config_exists=config_exists)


# ---------------------------------------------------------------- the hook itself


def run_hook(raw: str, default_event: str = "pre",
             use: list[str] | None = None) -> tuple[int, str, str]:
    """Handle one hook invocation. Returns (exit_code, stdout, stderr).

    Never raises into the agent: any internal failure degrades to "allow, unrecorded" rather
    than breaking the user's session. The one thing that is never skipped is the offline
    verdict, which is computed before anything that can touch the network.
    """
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return 0, "", "provenrail: hook input was not JSON; allowing and not recording\n"
    if not isinstance(data, dict):
        return 0, "", "provenrail: unexpected hook input; allowing and not recording\n"

    hook = parse_hook_input(data, default_event=default_event)
    armed_defaults = False
    # The notice says WHY the defaults armed, so the branch that knows records which of the two
    # reasons is true rather than leaving the notice to assume one of them.
    config_exists = False
    try:
        from .easy import _load_config_file, find_config_file, load_policy
        # `--use` on the hook arms those packs for this invocation, without a config file. It
        # used to be accepted and then ignored, so `pr guard hook --use destructive` in a folder
        # with no `.provenrail.json` allowed everything while its help text said the packs were
        # armed: the worst shape a guardrail failure can take.
        if use:
            policy = load_policy({"use": list(use)})
        else:
            config = _load_config_file() if find_config_file() else None
            if config is None:
                # No config file at all. The zero-install plugin arms the default packs here,
                # and this path did not, so installing the CLI on top of a working plugin
                # SILENTLY DISARMED it: the hook script prefers `pr` when it finds one, `pr`
                # found no policy, and every tool call proceeded unguarded. An upgrade that
                # turns the guard off is the worst shape this failure can take, because the
                # user did the thing the docs told them to do.
                #
                # A config file, once present, still wins completely, including an explicit
                # empty `use` that arms nothing: whoever wrote it outranks our defaults.
                policy = load_policy({"use": list(DEFAULT_PACKS)})
                armed_defaults = True
            else:
                config_exists = True
                spec = policy_spec(config)
                armed_defaults = spec is not config.get("policy")
                policy = load_policy(spec)
    except Exception as exc:  # a broken policy config must be loud, not silently permissive
        return 0, "", f"provenrail: could not load the policy ({exc}); NOT enforcing\n"

    # A budget with no rules IS an armed policy. Testing only for rules meant a config whose
    # whole purpose was a spend cap fell into the "nothing is armed" path and was never
    # evaluated, which is the same silent disarming this branch exists to warn about.
    has_budgets = bool(getattr(policy, "effective_budgets", lambda: [])())
    if policy is None or not (getattr(policy, "rules", []) or has_budgets):
        # Hooks are wired but nothing is armed. Staying silent here is how a user ends up
        # believing they are guarded for weeks while nothing is being checked, so say it,
        # rarely enough not to become noise the user tunes out.
        return 0, "", _no_policy_notice()

    # Installing the CLI used to make the plugin's first-run notice disappear, because the CLI
    # answers the hook and had no notice of its own. So the user who followed the upgrade path
    # got LESS explanation than the user who did nothing.
    notice = _first_run_notice(policy, config_exists) if armed_defaults else ""

    decision = (decide(policy, hook["tool"], hook["input"], hook.get("session_id") or None,
                       hook.get("cwd") or None, hook.get("transcript_path") or None)
                if hook["event"] == "pre" else None)
    # A guard that cannot enforce a cap it advertises has to say so where the user will see it.
    notice += (decision or {}).get("notice") or ""
    if decision is not None and decision["verdict"] == "ask":
        mark_ask(hook.get("session_id", ""), hook.get("tool", ""), decision["rule"] or "")

    recorded = record_hook(hook, decision)
    verdict = (decision or {}).get("verdict", "allow")
    # Journalled whenever the guard had an opinion, not only when the sink was unreachable.
    # Otherwise the local history, and everything built on it, is empty on exactly the installs
    # where recording works, and `pr guard card` would have nothing to show on a healthy setup
    # while the zero-install plugin showed the full list.
    budget_warning = (decision or {}).get("warning")
    if not recorded or verdict != "allow" or budget_warning:
        import time as _time
        entry = {"at": int(_time.time()),
                 "event": hook["event"], "tool": hook["tool"],
                 "session_id": hook.get("session_id", ""),
                 "verdict": verdict,
                 "rule": (decision or {}).get("rule"),
                 "shape": (decision or {}).get("shape", ""),
                 "recorded": bool(recorded),
                 "reason": (decision or {}).get("reason", "")}
        if budget_warning:
            # Journalled on an ALLOW, which nothing else here is. A cap that only appears in the
            # history at the moment it blocks the work leaves the user no warning they could
            # have acted on, which is the difference between a control and a post-mortem.
            entry["warning"] = budget_warning
        journal(entry)
    if budget_warning:
        # Once a day on stderr as well as in the journal, because the person who set the cap is
        # the one who can act on "you are at 90% of it", and nobody reads a journal file until
        # after something has gone wrong.
        notice += _once_a_day("spend-warn", f"provenrail: {budget_warning}\n")

    if decision is None or decision["verdict"] == "allow":
        return 0, "", notice

    reason = f"Provenrail guardrail {decision['rule']}: {decision['reason']}"
    if decision["verdict"] == "ask":
        reason += " (approve here and the approval is recorded as human oversight)"
    elif not recorded:
        reason += " [blocked; receipt journalled locally, sink unreachable]"
    out = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision["verdict"],
        "permissionDecisionReason": reason,
    }}
    return 0, json.dumps(out), notice


# ---------------------------------------------------------------- install


def _load_settings(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise GuardError(
            f"{path} is not valid JSON ({exc}). Fix or move it, then rerun.") from exc
    if not isinstance(data, dict):
        raise GuardError(f"{path} does not contain a JSON object.")
    return data


def _entry_is_ours(entry: dict[str, Any]) -> bool:
    return any(HOOK_COMMAND in str(h.get("command", ""))
               for h in entry.get("hooks", []) if isinstance(h, dict))


def install_claude_hooks(root: Path | None = None, matcher: str = _DEFAULT_MATCHER) -> Path:
    """Merge Provenrail's PreToolUse/PostToolUse hooks into `.claude/settings.json`.

    Idempotent, and additive: any hook the user already configured is preserved. We only ever
    add or replace entries whose command is ours.
    """
    root = Path(root or Path.cwd())
    path = root / CLAUDE_SETTINGS
    settings = _load_settings(path)
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise GuardError(f'{path}: "hooks" is not an object.')

    for event, arg in (("PreToolUse", "pre"), ("PostToolUse", "post")):
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise GuardError(f'{path}: hooks.{event} is not a list.')
        ours = {"matcher": matcher if event == "PreToolUse" else "*",
                "hooks": [{"type": "command",
                           "command": f"{HOOK_COMMAND} --event {arg}",
                           "timeout": HOOK_TIMEOUT_S}]}
        entries[:] = [e for e in entries if not (isinstance(e, dict) and _entry_is_ours(e))]
        entries.append(ours)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return path


def uninstall_claude_hooks(root: Path | None = None) -> tuple[Path, int]:
    """Remove only our hook entries. Returns (path, number removed)."""
    root = Path(root or Path.cwd())
    path = root / CLAUDE_SETTINGS
    if not path.is_file():
        return path, 0
    settings = _load_settings(path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return path, 0
    removed = 0
    for event in ("PreToolUse", "PostToolUse"):
        entries = hooks.get(event)
        if not isinstance(entries, list):
            continue
        keep = [e for e in entries if not (isinstance(e, dict) and _entry_is_ours(e))]
        removed += len(entries) - len(keep)
        if keep:
            hooks[event] = keep
        else:
            hooks.pop(event, None)
    if not hooks:
        settings.pop("hooks", None)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return path, removed


def hooks_installed(root: Path | None = None) -> bool:
    path = Path(root or Path.cwd()) / CLAUDE_SETTINGS
    if not path.is_file():
        return False
    try:
        hooks = _load_settings(path).get("hooks", {})
    except GuardError:
        return False
    entries = hooks.get("PreToolUse", []) if isinstance(hooks, dict) else []
    return any(isinstance(e, dict) and _entry_is_ours(e) for e in entries)


def config_path() -> Path:
    """The `.provenrail.json` the SDK will actually read (cwd wins, then home, then cwd)."""
    from .easy import CONFIG_FILENAME
    for path in (Path.cwd() / CONFIG_FILENAME, Path.home() / CONFIG_FILENAME):
        if path.is_file():
            return path
    return Path.cwd() / CONFIG_FILENAME


def arm_default_policy(packs: list[str] | None = None) -> list[str]:
    """Write a default `policy.use` into `.provenrail.json` if none is configured.

    Returns the packs now armed. An existing policy is never overwritten: whoever configured
    guardrails deliberately outranks our defaults.
    """
    from .easy import _load_config_file

    cfg = _load_config_file() or {}
    existing = cfg.get("policy")
    if existing:
        from .easy import load_policy
        loaded = load_policy(existing)
        if loaded is not None and loaded.rules:
            use = existing.get("use") if isinstance(existing, dict) else None
            return list(use) if use else ["(custom rules)"]
    packs = list(packs or DEFAULT_PACKS)
    cfg["policy"] = {"use": packs}
    config_path().write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return packs
