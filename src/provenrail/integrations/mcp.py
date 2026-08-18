"""Capture Model Context Protocol (MCP) tool calls.

Agents increasingly reach external tools through MCP rather than direct SDK calls. An MCP
tool invocation is exactly the local dispatch boundary Provenrail cares about: it is
where the agent decides to act on the world. Wrapping the MCP client session records every
`call_tool` as an `mcp_call` event (tool name, hashed arguments, hashed result, outcome),
off-box and signed, with no change to the agent's logic.

Duck-typed: there is no hard dependency on any MCP package. Pass any object exposing an
async `call_tool(name, arguments=...)` returning a result (the official `mcp` ClientSession
shape, where a truthy `isError` marks a failed tool call).
"""

from __future__ import annotations

import functools
from typing import Any

from ..chain import MCP_CALL
from ._common import jsonable, recorder_or_raise

_MARK = "_provenrail_mcp_instrumented"


def _record(recorder: Any, name: str, arguments: Any, result: Any, outcome: str) -> None:
    try:
        recorder.record_tool_call(name, jsonable(arguments), jsonable(result),
                                  outcome=outcome, kind=MCP_CALL, transport="mcp")
    except Exception:
        pass  # capture must never break the agent's tool call


def instrument_mcp(session: Any, recorder: Any) -> Any:
    """Wrap an MCP client session's async `call_tool` so each call is recorded. Idempotent."""
    recorder_or_raise(recorder)
    if getattr(session, _MARK, False):
        return session
    original = getattr(session, "call_tool", None)
    if original is None or not callable(original):
        return session

    @functools.wraps(original)
    async def wrapped(name, arguments=None, *args, **kwargs):
        try:
            result = await original(name, arguments, *args, **kwargs)
        except Exception as e:
            _record(recorder, name, arguments, {"error": str(e)}, "failure")
            raise
        outcome = "failure" if getattr(result, "isError", False) else "success"
        _record(recorder, name, arguments, result, outcome)
        return result

    session.call_tool = wrapped
    setattr(session, _MARK, True)
    return session
