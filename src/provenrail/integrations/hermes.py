"""Hermes Agent capture via observer plugin hooks.

Hermes exposes a read-only observer contract (`hermes.observer.v1`) that fires on every
tool dispatch across the CLI, gateway, cron, and subagents. This adapter turns those
firings into Ed25519-signed, hash-chained, off-box records that a third party can verify
without trusting the agent, the operator, or us.

Register it from a Hermes plugin:

    # ~/.hermes/plugins/provenrail/__init__.py
    from provenrail.integrations.hermes import register_provenrail

    def register(ctx):
        register_provenrail(ctx, agent_name="my-hermes-agent")

Why the off-box chain matters here specifically. NousResearch/hermes-agent#487 proposed an
in-tree hash-chained audit log and was closed as not planned, on the grounds that a hash
chain verified only against itself proves nothing against an operator with write access:
they can fork the chain, rewrite every entry after the fork, and internal verification
still passes. Provenrail's answer is that the chain is not verified against itself. Records
are signed by a key the sink never holds, re-chained independently on arrival by the sink,
and anchored to an RFC 3161 trusted timestamp and an RFC 6962 transparency log with
independent witness cosignatures. A rewrite has to defeat all of those at once.

Hooks used (payload fields per `docs/observability/README.md`, `hermes.observer.v1`):
- `pre_tool_call`   -> records intent (tool_name, session_id, task_id, tool_call_id)
- `post_tool_call`  -> records the completed call (args, result, status, duration_ms)
- `on_session_start` / `on_session_end` -> opens and seals the signed session

Hermes observer hooks are fail-open: it catches callback exceptions, logs a warning, and
keeps the agent loop running. This adapter matches that contract and never raises, so a
sink outage cannot stall an agent. It also never returns a value from `pre_tool_call`, so
it can never block a tool: this is a recorder, not a policy engine.

Honest scope: this proves that whatever was recorded has not been altered. It cannot prove
completeness, because an agent that never dispatches through the hook is never seen by it.
Provenrail is evidence tooling, not legal advice or a compliance certification.
"""

from __future__ import annotations

import json
from typing import Any


def _recorder(recorder: Any) -> Any:
    if recorder is not None:
        return recorder
    from provenrail import easy

    rec = easy.current_recorder()
    if rec is None:
        raise RuntimeError(
            "No active recorder: open one with `with provenrail.record('agent'):` "
            "or pass a FlightRecorder explicitly to register_provenrail(...).")
    return rec


def _coerce_result(result: Any) -> Any:
    """Hermes passes tool results as a string that is often JSON. Prefer the parsed
    form so the record carries structure, but never fail on a plain string."""
    if isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return result
    return result


# Hermes' documented observer-grade status vocabulary, mapped to our outcome field.
# "blocked" and "cancelled" are deliberately NOT folded into "failure": a policy denial
# and a cancellation are not tool failures, and recording them as such would misstate
# what the evidence shows. The raw Hermes status is preserved in extra either way.
_STATUS_TO_OUTCOME = {
    "ok": "success",
    "success": "success",
    "succeeded": "success",
    "error": "failure",
    "failure": "failure",
    "blocked": "blocked",
    "cancelled": "cancelled",
    "canceled": "cancelled",
}


def _outcome(kwargs: dict[str, Any]) -> str:
    status = kwargs.get("status")
    if isinstance(status, str) and status:
        # An unrecognised status is reported verbatim rather than guessed at.
        return _STATUS_TO_OUTCOME.get(status.lower(), status.lower())
    if kwargs.get("error") or kwargs.get("error_type") or kwargs.get("error_message"):
        return "failure"
    return "success"


def make_pre_tool_call(recorder: Any = None):
    """Build a `pre_tool_call` observer callback that records tool-call intent."""
    rec = _recorder(recorder)

    def on_pre_tool_call(**kwargs: Any) -> None:
        try:
            # Intent only. The full args and result land in the post_tool_call record,
            # so keep this payload to JSON-safe scalars.
            rec.record(
                "tool_call_intent",
                {
                    "tool": str(kwargs.get("tool_name") or "tool"),
                    "session_id": str(kwargs.get("session_id") or ""),
                    "task_id": str(kwargs.get("task_id") or ""),
                    "tool_call_id": str(kwargs.get("tool_call_id") or ""),
                },
            )
        except Exception:
            pass  # observer hooks are fail-open; capture must never break the agent
        # Returns None deliberately: a dict here would block the tool. This is a
        # recorder, not a policy engine.

    return on_pre_tool_call


def make_post_tool_call(recorder: Any = None):
    """Build a `post_tool_call` observer callback that records the completed call."""
    rec = _recorder(recorder)

    def on_post_tool_call(**kwargs: Any) -> None:
        try:
            duration = kwargs.get("duration_ms")
            extra: dict[str, Any] = {
                "framework": "hermes",
                "session_id": str(kwargs.get("session_id") or ""),
                "task_id": str(kwargs.get("task_id") or ""),
                "tool_call_id": str(kwargs.get("tool_call_id") or ""),
            }
            # Keep Hermes' own status verbatim alongside our normalised outcome, so an
            # auditor can see exactly what the framework reported.
            if kwargs.get("status"):
                extra["hermes_status"] = str(kwargs["status"])
            for field in ("error_type", "error_message"):
                if kwargs.get(field):
                    extra[field] = str(kwargs[field])[:500]
            if duration is not None:
                # The canonical record format bans floats so that two independent
                # verifier implementations hash identical bytes.
                try:
                    extra["duration_ms"] = int(duration)
                except (TypeError, ValueError):
                    pass
            rec.record_tool_call(
                str(kwargs.get("tool_name") or "tool"),
                kwargs.get("args"),
                _coerce_result(kwargs.get("result")),
                outcome=_outcome(kwargs),
                **extra,
            )
        except Exception:
            pass  # observer hooks are fail-open

    return on_post_tool_call


def register_provenrail(ctx: Any, recorder: Any = None, agent_name: str = "hermes-agent",
                        capture_intent: bool = True) -> Any:
    """Register Provenrail capture on a Hermes plugin context.

        def register(ctx):
            register_provenrail(ctx, agent_name="my-hermes-agent")

    With no recorder it binds to the one opened by `with provenrail.record(...)`, or
    opens one lazily from `.provenrail.json` (written by `pr quickstart`). Returns the
    recorder so a caller can seal it explicitly.
    """
    rec = recorder
    if rec is None:
        from provenrail import easy

        rec = easy.current_recorder()
        if rec is None:
            # A Hermes plugin's register() runs outside any `with record(...)` block,
            # so build the recorder directly from .provenrail.json.
            rec = easy.make_recorder(agent_name)

    if capture_intent:
        ctx.register_hook("pre_tool_call", make_pre_tool_call(rec))
    ctx.register_hook("post_tool_call", make_post_tool_call(rec))
    return rec
