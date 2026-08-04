"""Instrument an OpenAI client instance to auto-capture model calls."""

from __future__ import annotations

from typing import Any

from ._common import make_wrapper

_MARK = "_provenrail_instrumented"


def instrument_openai(client: Any, recorder: Any) -> Any:
    """Patch a client's chat.completions.create and responses.create (sync or async)."""
    if getattr(client, _MARK, False):
        return client
    targets = []
    chat = getattr(getattr(client, "chat", None), "completions", None)
    if chat is not None and hasattr(chat, "create"):
        targets.append((chat, "create", "chat.completions"))
    responses = getattr(client, "responses", None)
    if responses is not None and hasattr(responses, "create"):
        targets.append((responses, "create", "responses"))
    for obj, name, op in targets:
        setattr(obj, name, make_wrapper(getattr(obj, name), recorder, "openai", op))
    setattr(client, _MARK, True)
    return client
