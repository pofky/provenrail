"""LangChain callback handler capture (duck-typed, no langchain dependency)."""
import types

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations.langchain import provenrail_callback
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _fr():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    return fr, c, prov


def _llm_result(text):
    gen = types.SimpleNamespace(text=text)
    return types.SimpleNamespace(generations=[[gen]], llm_output={"token_usage": {"total": 5}})


def test_langchain_handler_captures_llm_and_tool():
    fr, c, prov = _fr()
    h = provenrail_callback(fr)
    with fr.session():
        h.on_llm_start({"name": "ChatOpenAI"}, ["hello"], run_id="r1",
                       invocation_params={"model": "gpt-4o"})
        h.on_llm_end(_llm_result("hi there"), run_id="r1")
        h.on_tool_start({"name": "search"}, "query", run_id="t1")
        h.on_tool_end("result", run_id="t1")
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    actions = [r["record"]["action_type"] for r in exp["records"]]
    assert "model_call" in actions and "tool_call" in actions
    mc = next(r["record"] for r in exp["records"] if r["record"]["action_type"] == "model_call")
    assert mc["payload"]["provider"] == "langchain" and mc["payload"]["model"] == "gpt-4o"


def test_langchain_tool_error_recorded_as_failure():
    fr, c, prov = _fr()
    h = provenrail_callback(fr)
    with fr.session():
        h.on_tool_start({"name": "db"}, "select", run_id="t9")
        h.on_tool_error(RuntimeError("boom"), run_id="t9")
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    tc = next(r["record"] for r in exp["records"] if r["record"]["action_type"] == "tool_call")
    assert tc["payload"]["outcome"] == "failure"


def test_compliance_handler_is_the_public_name():
    from provenrail.integrations import ComplianceCallbackHandler
    from provenrail.integrations.langchain import ComplianceCallbackHandler as H2
    assert ComplianceCallbackHandler is H2
    fr, c, prov = _fr()
    h = ComplianceCallbackHandler(fr)
    with fr.session():
        h.on_llm_start({"name": "ChatAnthropic"}, ["hi"], run_id="r2",
                       invocation_params={"model": "claude"})
        h.on_llm_end(_llm_result("yo"), run_id="r2")
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert any(r["record"]["action_type"] == "model_call" for r in exp["records"])


def test_no_arg_handler_uses_active_recorder():
    import provenrail as fr_pkg
    from provenrail import easy
    from provenrail.integrations.langchain import compliance_handler

    fr, c, prov = _fr()
    # No active session: building with no recorder must fail loudly, not silently no-op.
    with pytest.raises(RuntimeError):
        compliance_handler()
    # Inside an active record() session the handler binds to the current recorder.
    token = easy._ACTIVE.set(fr)
    try:
        assert fr_pkg.current_recorder() is fr
        h = compliance_handler()
        assert h.recorder is fr
    finally:
        easy._ACTIVE.reset(token)
