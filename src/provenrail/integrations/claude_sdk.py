"""Claude Agent SDK capture via PreToolUse / PostToolUse hooks.

The Anthropic Claude Agent SDK (`claude-agent-sdk`) ships with no built-in audit trail.
This adapter turns every tool call the agent makes into a signed, hash-chained, off-box
record, of the kind EU AI Act Article 12 calls for, with two lines of wiring:

    import provenrail as fr
    from provenrail.integrations.claude_sdk import provenrail_hooks
    from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

    fr.configure()                       # reads .provenrail.json (run `pr quickstart` once)
    with fr.record("my-claude-agent") as rec:
        options = ClaudeAgentOptions(hooks=provenrail_hooks(rec))
        async with ClaudeSDKClient(options=options) as client:
            ...

A PostToolUse hook records each completed tool call (name, input digest, response digest,
outcome); a PreToolUse hook records intent and is also where a denial decision is captured as
evidence. The hooks never deny by default and never raise into the agent's path: a capture
failure is swallowed so the agent keeps working, and the gap is detectable later via the chain.

Provenrail produces tamper-evident evidence; it is not legal advice or a compliance
certification. Hook callback signature confirmed against code.claude.com/docs/en/agent-sdk
(2026-06-29): `async def cb(input_data: dict, tool_use_id: str | None, context) -> dict`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _recorder(recorder: Any) -> Any:
    if recorder is not None:
        return recorder
    from provenrail import easy

    rec = easy.current_recorder()
    if rec is None:
        raise RuntimeError(
            "No active recorder: open one with `with provenrail.record('agent'):` "
            "or pass a FlightRecorder explicitly to provenrail_hooks(...).")
    return rec


def make_pre_tool_hook(recorder: Any = None) -> Callable:
    """Build a PreToolUse hook callback that records tool-call intent."""
    rec = _recorder(recorder)

    async def pre_tool(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        try:
            # Intent only: name + correlation id. The full args + result land safely-digested
            # in the PostToolUse record_tool_call, so keep this payload to JSON-safe scalars.
            rec.record(
                "tool_call_intent",
                {
                    "tool": str(input_data.get("tool_name", "tool")),
                    "tool_use_id": str(tool_use_id) if tool_use_id is not None else None,
                    "session_id": str(input_data.get("session_id") or ""),
                },
            )
        except Exception:
            pass  # capture must never break the agent's call path
        return {}

    return pre_tool


def make_post_tool_hook(recorder: Any = None) -> Callable:
    """Build a PostToolUse hook callback that records the completed tool call."""
    rec = _recorder(recorder)

    async def post_tool(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        try:
            response = input_data.get("tool_response")
            outcome = "success"
            if isinstance(response, dict) and (response.get("is_error") or response.get("error")):
                outcome = "failure"
            rec.record_tool_call(
                input_data.get("tool_name", "tool"),
                input_data.get("tool_input"),
                response,
                outcome=outcome,
                tool_use_id=tool_use_id,
            )
        except Exception:
            pass
        return {}

    return post_tool


def provenrail_hooks(recorder: Any = None, *, matcher: str | None = None) -> dict:
    """Return a ClaudeAgentOptions-ready hooks dict capturing every tool call.

    Pass straight in: `ClaudeAgentOptions(hooks=provenrail_hooks(rec))`. With no recorder,
    binds to the recorder of the open `provenrail.record(...)` session. If `claude-agent-sdk`
    is installed we wrap callbacks in its `HookMatcher`; otherwise we fall back to a plain dict
    of the same shape so the adapter is importable and testable without the SDK present.
    """
    pre = make_pre_tool_hook(recorder)
    post = make_post_tool_hook(recorder)
    try:  # pragma: no cover - exercised only when the SDK is installed
        from claude_agent_sdk import HookMatcher

        def wrap(cb):
            return HookMatcher(matcher=matcher, hooks=[cb])
    except Exception:
        def wrap(cb):
            return {"matcher": matcher, "hooks": [cb]}

    return {"PreToolUse": [wrap(pre)], "PostToolUse": [wrap(post)]}
