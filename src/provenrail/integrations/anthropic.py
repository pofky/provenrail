"""Instrument an Anthropic client instance to auto-capture model calls."""

from __future__ import annotations

from typing import Any

from ._common import make_wrapper, recorder_or_raise

_MARK = "_provenrail_instrumented"


def instrument_anthropic(client: Any, recorder: Any) -> Any:
    """Patch a client's messages.create and beta.messages.create (sync or async)."""
    recorder_or_raise(recorder)
    if getattr(client, _MARK, False):
        return client
    targets = []
    messages = getattr(client, "messages", None)
    if messages is not None and hasattr(messages, "create"):
        targets.append((messages, "create", "messages"))
    beta_msgs = getattr(getattr(client, "beta", None), "messages", None)
    if beta_msgs is not None and hasattr(beta_msgs, "create"):
        targets.append((beta_msgs, "create", "beta.messages"))
    for obj, name, op in targets:
        setattr(obj, name, make_wrapper(getattr(obj, name), recorder, "anthropic", op))
    setattr(client, _MARK, True)
    return client
