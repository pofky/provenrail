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
# working in a repo: the things that destroy work or leak credentials. Money, access,
# exfiltration and blast-radius packs exist and are one word away in `.provenrail.json`, but
# they fire on tool-name patterns a coding agent does not use, so arming them by default would
# add noise without adding protection.
DEFAULT_PACKS = ["destructive", "secrets", "production"]

# Claude Code tools whose input can carry a destructive payload. Everything else (Read, Glob,
# Grep, TodoWrite...) is still recorded on PostToolUse but is not worth a pre-dispatch gate.
_DEFAULT_MATCHER = "Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch|Task"


class GuardError(RuntimeError):
    """A guard operation failed in a way the user must see (bad settings file, no config)."""


# ---------------------------------------------------------------- hook payload


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
        "input": data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {},
        "response": data.get("tool_response"),
        "session_id": data.get("session_id") or "",
        "cwd": data.get("cwd") or "",
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
    for rule in getattr(policy, "rules", []):
        if rule.id == rule_id:
            return rule.effect
    return ""


def decide(policy: Any, tool: str, tool_input: Any) -> dict[str, Any]:
    """Evaluate the policy for one attempted tool call. Pure, offline, no I/O.

    Returns a dict with `verdict` ("allow" | "deny" | "ask"), the firing rule and reason.
    A fresh SessionState is used per hook process because each hook invocation is its own
    process: per-session counters (`limit` rules) therefore cannot be enforced across a whole
    Claude Code session, and `pr guard status` says so rather than implying coverage.
    """
    from .policy import ALLOW, DENY, REQUIRE_OVERSIGHT, SessionState

    if policy is None:
        return {"verdict": "allow", "rule": None, "reason": "no policy configured",
                "effect": ALLOW}
    ctx = {"tool": tool, "match_text": match_text(tool_input)}
    decision = policy.decide("tool_call", ctx, SessionState())
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
            "effect": effect or (DENY if verdict == "deny" else ALLOW)}


# ---------------------------------------------------------------- recording


def _journal_path() -> Path:
    return Path(os.environ.get("PROVENRAIL_GUARD_JOURNAL") or JOURNAL_FILENAME)


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


# ---------------------------------------------------------------- the hook itself


def run_hook(raw: str, default_event: str = "pre") -> tuple[int, str, str]:
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
    try:
        from .easy import _load_config_file, load_policy
        policy = load_policy((_load_config_file() or {}).get("policy"))
    except Exception as exc:  # a broken policy config must be loud, not silently permissive
        return 0, "", f"provenrail: could not load the policy ({exc}); NOT enforcing\n"

    decision = decide(policy, hook["tool"], hook["input"]) if hook["event"] == "pre" else None
    if decision is not None and decision["verdict"] == "ask":
        mark_ask(hook.get("session_id", ""), hook.get("tool", ""), decision["rule"] or "")

    recorded = record_hook(hook, decision)
    if not recorded:
        journal({"event": hook["event"], "tool": hook["tool"],
                 "session_id": hook.get("session_id", ""),
                 "verdict": (decision or {}).get("verdict", "allow"),
                 "rule": (decision or {}).get("rule"),
                 "reason": (decision or {}).get("reason", "")})

    if decision is None or decision["verdict"] == "allow":
        return 0, "", ""

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
    return 0, json.dumps(out), ""


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
