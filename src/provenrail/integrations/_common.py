"""Shared helpers for SDK instrumentation."""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any

_log = logging.getLogger(__name__)


def _capture(recorder, provider: str, op: str, kwargs: dict, response: Any) -> None:
    try:
        model = kwargs.get("model", "unknown")
        request = {k: jsonable(v) for k, v in kwargs.items() if k != "model"}
        if kwargs.get("stream"):
            # we must not consume the caller's stream; record the request and mark it
            recorder.record_model_call(provider, model, request, {"streaming": True},
                                       usage={}, op=op, streaming=True)
        else:
            recorder.record_model_call(provider, model, request, jsonable(response),
                                       usage=extract_usage(response), op=op)
    except Exception as exc:
        # Capture must never break the agent's call path. But silence here is how someone ends
        # up believing they have an audit trail and having none: the call succeeds, the agent
        # behaves normally, and nothing is recorded. Warn once per process per reason, loudly
        # enough to be seen in a log, without turning a hot loop into a wall of text.
        _warn_capture_failed(provider, op, exc)


_warned: set[str] = set()


def _warn_capture_failed(provider: str, op: str, exc: Exception) -> None:
    key = f"{provider}.{op}.{type(exc).__name__}"
    if key in _warned:
        return
    _warned.add(key)
    _log.warning(
        "provenrail: a %s %s call completed but was NOT recorded (%s: %s). The agent is running "
        "unrecorded. The usual cause is passing the wrong object as the recorder: it must be the "
        "object with .record_model_call, not the provenrail module or a FlightRecorder you have "
        "not opened a session on. Further identical warnings are suppressed.",
        provider, op, type(exc).__name__, exc)


def recorder_or_raise(recorder: Any) -> Any:
    """Reject a recorder that cannot record, at the moment it is wired rather than at the moment
    it is needed.

    Passing the wrong object here used to be invisible: instrumentation succeeded, every model
    call succeeded, and the capture failed silently inside the call path. Published examples had
    this exact bug, which is the argument for failing here instead."""
    if not hasattr(recorder, "record_model_call"):
        raise TypeError(
            f"provenrail: {type(recorder).__name__} cannot record. Pass the recorder object "
            f"(the one with .record_model_call), not a module or a class. With the context "
            f"manager that is the value it yields: `with fr.session(): instrument_...(client, fr)`."
        )
    return recorder


def make_wrapper(method, recorder, provider: str, op: str):
    """Wrap a sync or async SDK method so each call is captured after it returns."""
    if inspect.iscoroutinefunction(method):
        @functools.wraps(method)
        async def awrapper(*args, **kwargs):
            response = await method(*args, **kwargs)
            _capture(recorder, provider, op, kwargs, response)
            return response
        return awrapper

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        response = method(*args, **kwargs)
        _capture(recorder, provider, op, kwargs, response)
        return response
    return wrapper


def jsonable(value: Any, _depth: int = 0) -> Any:
    """Best-effort conversion of an SDK object into a canonicalizable structure.

    Used to build a stable request/response digest. Falls back to str() for opaque
    objects so the recorder can still hash a deterministic-within-run descriptor.
    """
    if _depth > 6:
        return str(value)
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= (2**53 - 1) else str(value)
    if isinstance(value, float):
        return str(value)  # floats are not allowed raw in canonical records
    if isinstance(value, dict):
        return {str(k): jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v, _depth + 1) for v in value]
    # pydantic / SDK models
    for attr in ("model_dump", "to_dict", "dict"):
        fn = getattr(value, attr, None)
        if callable(fn):
            try:
                return jsonable(fn(), _depth + 1)
            except Exception:
                pass
    if hasattr(value, "__dict__"):
        try:
            return {k: jsonable(v, _depth + 1) for k, v in vars(value).items()
                    if not k.startswith("_")}
        except Exception:
            pass
    return str(value)


def extract_usage(response: Any) -> dict[str, str]:
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return {}
    d = jsonable(usage)
    if not isinstance(d, dict):
        return {}
    # stringify numeric token counts (records forbid raw ints beyond safe range; keep simple)
    return {str(k): str(v) for k, v in d.items() if isinstance(v, (int, str))}
