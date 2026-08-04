"""LangChain / LangGraph capture via a callback handler.

Two lines to a tamper-evident, independently verifiable record of every model and tool
call your chain or agent makes, of the kind EU AI Act Article 12 calls for:

    import provenrail as fr
    from provenrail.integrations.langchain import ComplianceCallbackHandler

    fr.configure()                       # reads .provenrail.json (run `pr quickstart` once)
    with fr.record("my-agent") as rec:   # auto-provisions, signs, seals off-box
        chain.invoke(x, config={"callbacks": [ComplianceCallbackHandler(rec)]})

`ComplianceCallbackHandler` is the public name (it answers langchain-ai/langchain#35691,
the community RFC for a callback handler that emits cryptographically signed audit logs for
Article 12). It records each LLM call and tool call into Provenrail's dual hash chain, so the
record is independently verifiable by an auditor who trusts neither the agent nor the sink.
Provenrail produces the evidence; it is not legal advice or a compliance certification.

Works with LangGraph too (pass the handler in the run config). If langchain is installed
the handler subclasses BaseCallbackHandler; otherwise it is a duck-typed object with the
same method surface, so it can be tested and used without a hard dependency.
"""

from __future__ import annotations

from typing import Any

try:  # pragma: no cover - exercised only when langchain is installed
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except Exception:  # pragma: no cover
    try:
        from langchain.callbacks.base import BaseCallbackHandler as _Base
    except Exception:
        _Base = object


def _model_name(serialized: dict | None, kwargs: dict) -> str:
    inv = kwargs.get("invocation_params") or {}
    return inv.get("model") or inv.get("model_name") or (
        (serialized or {}).get("name") if serialized else None) or "unknown"


def _llm_result_to_dict(response: Any) -> Any:
    texts = []
    try:
        for gen_list in getattr(response, "generations", []) or []:
            for gen in gen_list:
                texts.append(getattr(gen, "text", None) or str(gen))
    except Exception:
        return str(response)
    out: dict[str, Any] = {"generations": texts}
    info = getattr(response, "llm_output", None)
    if isinstance(info, dict):
        out["llm_output"] = info
    return out


class FlightRecorderCallbackHandler(_Base):
    def __init__(self, recorder: Any):
        try:
            super().__init__()
        except Exception:
            pass
        self.recorder = recorder
        self._llm: dict[Any, dict] = {}
        self._tool: dict[Any, dict] = {}

    def on_llm_start(self, serialized, prompts, *, run_id=None, **kwargs):
        self._llm[run_id] = {"prompts": list(prompts) if prompts else [],
                             "model": _model_name(serialized, kwargs)}

    def on_chat_model_start(self, serialized, messages, *, run_id=None, **kwargs):
        self._llm[run_id] = {"prompts": [[str(m) for m in batch] for batch in (messages or [])],
                             "model": _model_name(serialized, kwargs)}

    def on_llm_end(self, response, *, run_id=None, **kwargs):
        ctx = self._llm.pop(run_id, {})
        self.recorder.record_model_call(
            provider="langchain", model=ctx.get("model", "unknown"),
            request={"prompts": ctx.get("prompts", [])},
            response=_llm_result_to_dict(response),
        )

    def on_tool_start(self, serialized, input_str, *, run_id=None, **kwargs):
        self._tool[run_id] = {"name": (serialized or {}).get("name", "tool"), "input": input_str}

    def on_tool_end(self, output, *, run_id=None, **kwargs):
        ctx = self._tool.pop(run_id, {})
        self.recorder.record_tool_call(ctx.get("name", "tool"), ctx.get("input"), str(output))

    def on_tool_error(self, error, *, run_id=None, **kwargs):
        ctx = self._tool.pop(run_id, {})
        self.recorder.record_tool_call(ctx.get("name", "tool"), ctx.get("input"),
                                       {"error": str(error)}, outcome="failure")


# Canonical public name. EU AI Act Article 12 framing; answers langchain-ai/langchain#35691.
# Same capture surface as FlightRecorderCallbackHandler, kept as the recommended import.
class ComplianceCallbackHandler(FlightRecorderCallbackHandler):
    """A LangChain callback handler that emits a signed, hash-chained, off-box record of
    every model and tool call, suitable as Article 12 record-keeping evidence."""


def provenrail_callback(recorder: Any = None) -> ComplianceCallbackHandler:
    """Build a handler. With no recorder, use the process-wide recorder configured via
    `provenrail.configure()` / opened with `provenrail.record(...)`, for the 2-line story."""
    if recorder is None:
        from provenrail import easy

        recorder = easy.current_recorder()
        if recorder is None:
            raise RuntimeError(
                "No active recorder: open one with `with provenrail.record('agent'):` "
                "or pass a FlightRecorder explicitly to ComplianceCallbackHandler.")
    return ComplianceCallbackHandler(recorder)


# Back-compat alias.
compliance_handler = provenrail_callback
