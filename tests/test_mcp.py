"""MCP capture: async call_tool wrapping, idempotency, success/failure outcomes."""
import asyncio
import types

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations import instrument_mcp
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _fr():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    return app, c, prov, fr


def _bundle(c, prov):
    return c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


class FakeSession:
    def __init__(self, result=None, raise_exc=None):
        self._result = result
        self._raise = raise_exc
        self.calls = 0

    async def call_tool(self, name, arguments=None):
        self.calls += 1
        if self._raise:
            raise self._raise
        return self._result


def test_mcp_call_is_captured():
    _, c, prov, fr = _fr()
    sess = FakeSession(result=types.SimpleNamespace(content=[{"text": "ok"}], isError=False))
    instrument_mcp(sess, fr)
    with fr.session():
        out = asyncio.run(sess.call_tool("filesystem.read", {"path": "/etc/hosts"}))
    assert out is not None
    rec = next(r["record"] for r in _bundle(c, prov)["records"]
               if r["record"]["action_type"] == "mcp_call")
    assert rec["payload"]["tool"] == "filesystem.read"
    assert rec["payload"]["outcome"] == "success"
    assert rec["payload"]["extra"]["transport"] == "mcp"


def test_mcp_error_result_marked_failure():
    _, c, prov, fr = _fr()
    sess = FakeSession(result=types.SimpleNamespace(content=[], isError=True))
    instrument_mcp(sess, fr)
    with fr.session():
        asyncio.run(sess.call_tool("db.write", {"q": "drop"}))
    rec = next(r["record"] for r in _bundle(c, prov)["records"]
               if r["record"]["action_type"] == "mcp_call")
    assert rec["payload"]["outcome"] == "failure"


def test_mcp_exception_records_failure_and_reraises():
    _, c, prov, fr = _fr()
    sess = FakeSession(raise_exc=RuntimeError("boom"))
    instrument_mcp(sess, fr)
    with fr.session():
        with pytest.raises(RuntimeError):
            asyncio.run(sess.call_tool("flaky", {}))
    rec = next(r["record"] for r in _bundle(c, prov)["records"]
               if r["record"]["action_type"] == "mcp_call")
    assert rec["payload"]["outcome"] == "failure"


def test_mcp_instrument_is_idempotent():
    _, _, _, fr = _fr()
    sess = FakeSession(result=types.SimpleNamespace(isError=False))
    instrument_mcp(sess, fr)
    first = sess.call_tool
    instrument_mcp(sess, fr)
    assert sess.call_tool is first  # not double-wrapped


def test_mcp_no_call_tool_is_safe():
    _, _, _, fr = _fr()
    obj = types.SimpleNamespace()  # no call_tool
    assert instrument_mcp(obj, fr) is obj  # no crash
