"""Agno capture via agent-level tool hooks.

Agno ships tracing but no tamper-evident audit trail: the trace lives in infrastructure
the agent (or whoever operates it) can edit. This adapter turns every tool call an Agno
agent makes into an Ed25519-signed, hash-chained, off-box record that an auditor can
verify without trusting the agent, the sink, or us. Two lines of wiring:

    import provenrail as fr
    from provenrail.integrations.agno import provenrail_tool_hook

    fr.configure()                       # reads .provenrail.json (run `pr quickstart` once)
    with fr.record("my-agno-agent") as rec:
        agent = Agent(model=..., tools=[...], tool_hooks=[provenrail_tool_hook(rec)])
        agent.print_response("...")

This answers agno-agi/agno#7518, the open request for cryptographic receipts on agent
audit trails ("proving each tool call's content and signer identity with Ed25519, so the
audit trail is tamper-evident without relying on infrastructure trust").

An Agno tool hook is middleware: it receives the function name, the callable, and the
arguments, and must invoke `function_call(**arguments)` to let execution proceed. Agno
resolves hook parameters *by name*, so the signature below deliberately uses the names
Agno supports (`function_name`, `function_call`, `arguments`). Verified against
docs.agno.com/tools/hooks (2026-07-30).

The hook records the tool name, arguments, result, outcome, and wall-clock duration. A
raising tool is recorded as a `failure` and the exception is re-raised unchanged, so
Agno's own error handling is untouched. Capture never breaks the agent: a recording
failure is swallowed, and the resulting gap stays detectable in the chain rather than
being silently papered over.

Provenrail produces tamper-evident evidence; it is not legal advice or a compliance
certification, and it never claims completeness.
"""

from __future__ import annotations

import time
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
            "or pass a FlightRecorder explicitly to provenrail_tool_hook(...).")
    return rec


def _record(rec: Any, name: str, arguments: Any, result: Any, outcome: str,
            started: float) -> None:
    try:
        rec.record_tool_call(
            name,
            arguments,
            result,
            outcome=outcome,
            framework="agno",
            # Integer milliseconds: the canonical record format bans floats so that two
            # independent verifier implementations hash the same bytes.
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception:
        pass  # capture must never break the agent's call path


def provenrail_tool_hook(recorder: Any = None) -> Callable:
    """Build an Agno tool hook that records every tool call as signed evidence.

    Pass the result in `Agent(tool_hooks=[...])` (or `Team(tool_hooks=[...])`). With no
    argument it binds to the recorder opened by `with provenrail.record(...)`.
    """
    rec = _recorder(recorder)

    def provenrail_hook(function_name: str, function_call: Callable,
                        arguments: dict[str, Any]):
        args = arguments if isinstance(arguments, dict) else {}
        started = time.monotonic()
        try:
            result = function_call(**args)
        except Exception as exc:
            _record(rec, function_name, args,
                    {"error": type(exc).__name__, "message": str(exc)}, "failure", started)
            raise
        _record(rec, function_name, args, result, "success", started)
        return result

    return provenrail_hook


def async_provenrail_tool_hook(recorder: Any = None) -> Callable:
    """Async counterpart of `provenrail_tool_hook`, for agents with async tools."""
    rec = _recorder(recorder)

    async def provenrail_hook(function_name: str, function_call: Callable,
                              arguments: dict[str, Any]):
        args = arguments if isinstance(arguments, dict) else {}
        started = time.monotonic()
        try:
            result = function_call(**args)
            if hasattr(result, "__await__"):
                result = await result
        except Exception as exc:
            _record(rec, function_name, args,
                    {"error": type(exc).__name__, "message": str(exc)}, "failure", started)
            raise
        _record(rec, function_name, args, result, "success", started)
        return result

    return provenrail_hook


def instrument_agno(agent: Any, recorder: Any = None) -> Any:
    """Attach the Provenrail hook to an existing Agno agent or team, in place.

        agent = Agent(model=..., tools=[...])
        instrument_agno(agent, rec)

    Idempotent: instrumenting the same agent twice does not double-record. Returns the
    agent so the call can be chained.
    """
    rec = _recorder(recorder)
    hooks = list(getattr(agent, "tool_hooks", None) or [])
    if any(getattr(h, "__name__", "") == "provenrail_hook" for h in hooks):
        return agent
    hooks.append(provenrail_tool_hook(rec))
    agent.tool_hooks = hooks
    return agent
