"""Agno tool-hook capture (duck-typed, no agno dependency).

Agno resolves hook parameters by name and calls the hook as middleware, so these tests
drive the hook exactly the way Agno does: positionally and by keyword, with the callable
and its arguments handed over for the hook to invoke.
"""
import asyncio
import inspect

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations.agno import (
    async_provenrail_tool_hook,
    instrument_agno,
    provenrail_tool_hook,
)
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _fr():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    return fr, c, prov


def _records(c, prov):
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    return [r["record"] for r in exp["records"]]


def _tool_calls(c, prov):
    return [r for r in _records(c, prov) if r["action_type"] == "tool_call"]


def test_hook_records_tool_call_and_returns_result():
    fr, c, prov = _fr()
    hook = provenrail_tool_hook(fr)

    def get_weather(city: str) -> str:
        return f"sunny in {city}"

    with fr.session():
        out = hook("get_weather", get_weather, {"city": "Vilnius"})

    assert out == "sunny in Vilnius"  # the hook must not alter the tool's return value
    calls = _tool_calls(c, prov)
    assert len(calls) == 1
    payload = calls[0]["payload"]
    assert payload["tool"] == "get_weather"
    assert payload["outcome"] == "success"
    assert payload["extra"]["framework"] == "agno"
    assert payload["extra"]["duration_ms"] >= 0
    # Integers only: the canonical format bans floats so both verifiers hash equal bytes.
    assert isinstance(payload["extra"]["duration_ms"], int)


def test_hook_signature_uses_the_parameter_names_agno_resolves():
    # Agno injects hook parameters by name, so these exact names are load-bearing.
    fr, _, _ = _fr()
    params = list(inspect.signature(provenrail_tool_hook(fr)).parameters)
    assert params == ["function_name", "function_call", "arguments"]


def test_hook_accepts_keyword_invocation():
    fr, c, prov = _fr()
    hook = provenrail_tool_hook(fr)
    with fr.session():
        out = hook(function_name="echo", function_call=lambda v: v, arguments={"v": 7})
    assert out == 7
    assert _tool_calls(c, prov)[0]["payload"]["tool"] == "echo"


def test_failing_tool_is_recorded_as_failure_and_reraises():
    fr, c, prov = _fr()
    hook = provenrail_tool_hook(fr)

    def broken():
        raise ValueError("boom")

    with fr.session():
        with pytest.raises(ValueError, match="boom"):
            hook("broken", broken, {})

    payload = _tool_calls(c, prov)[0]["payload"]
    assert payload["outcome"] == "failure"
    assert payload["tool"] == "broken"


def test_capture_failure_never_breaks_the_agent():
    fr, _, _ = _fr()

    class Exploding:
        def record_tool_call(self, *a, **k):
            raise RuntimeError("sink down")

    hook = provenrail_tool_hook(Exploding())
    assert hook("ok", lambda: "value", {}) == "value"  # tool result still reaches the agent


def test_non_dict_arguments_are_tolerated():
    fr, c, prov = _fr()
    hook = provenrail_tool_hook(fr)
    with fr.session():
        assert hook("noargs", lambda: "done", None) == "done"
    assert _tool_calls(c, prov)[0]["payload"]["tool"] == "noargs"


def test_async_hook_awaits_and_records():
    fr, c, prov = _fr()
    hook = async_provenrail_tool_hook(fr)

    async def fetch(url: str) -> str:
        return f"body of {url}"

    with fr.session():
        out = asyncio.run(hook("fetch", fetch, {"url": "https://x.test"}))

    assert out == "body of https://x.test"
    assert _tool_calls(c, prov)[0]["payload"]["outcome"] == "success"


def test_async_hook_records_failure_and_reraises():
    fr, c, prov = _fr()
    hook = async_provenrail_tool_hook(fr)

    async def broken():
        raise KeyError("missing")

    with fr.session():
        with pytest.raises(KeyError):
            asyncio.run(hook("broken", broken, {}))

    assert _tool_calls(c, prov)[0]["payload"]["outcome"] == "failure"


def test_instrument_agno_attaches_hook_and_is_idempotent():
    fr, c, prov = _fr()

    class FakeAgent:
        tool_hooks: list = []

    agent = FakeAgent()
    assert instrument_agno(agent, fr) is agent
    instrument_agno(agent, fr)  # second call must not double-record
    assert len(agent.tool_hooks) == 1

    with fr.session():
        agent.tool_hooks[0]("t", lambda: "r", {})
    assert len(_tool_calls(c, prov)) == 1


def test_instrument_agno_preserves_existing_hooks():
    fr, _, _ = _fr()
    seen = []

    def other_hook(function_name, function_call, arguments):
        seen.append(function_name)
        return function_call(**arguments)

    class FakeAgent:
        tool_hooks = [other_hook]

    agent = instrument_agno(FakeAgent(), fr)
    assert agent.tool_hooks[0] is other_hook
    assert len(agent.tool_hooks) == 2


def test_no_arg_hook_requires_active_recorder():
    with pytest.raises(RuntimeError, match="No active recorder"):
        provenrail_tool_hook()


# --- Against the real Agno package, when it is installed -----------------------------
# The duck-typed tests above pin our contract; these pin Agno's. Agno resolves hook
# parameters by name and invokes hooks keyword-only, so a rename on either side breaks
# capture silently. Verified against agno 2.8.5.

def test_real_agno_executes_our_hook_and_the_record_verifies():
    pytest.importorskip("agno")
    from agno.tools.function import Function, FunctionCall

    fr, c, prov = _fr()
    hook = provenrail_tool_hook(fr)

    def transfer_funds(account: str, amount: int) -> str:
        return f"moved {amount} to {account}"

    def failing_tool(x: int) -> str:
        raise RuntimeError("downstream refused")

    with fr.session():
        f = Function.from_callable(transfer_funds)
        f.tool_hooks = [hook]
        ok = FunctionCall(function=f, arguments={"account": "LT12", "amount": 500}).execute()

        f2 = Function.from_callable(failing_tool)
        f2.tool_hooks = [hook]
        bad = FunctionCall(function=f2, arguments={"x": 1}).execute()

    assert ok.status == "success"
    assert bad.status == "failure"  # the hook re-raises, so Agno still sees the failure

    calls = _tool_calls(c, prov)
    assert [p["payload"]["tool"] for p in calls] == ["transfer_funds", "failing_tool"]
    assert [p["payload"]["outcome"] for p in calls] == ["success", "failure"]


def test_real_agno_resolves_every_parameter_name_we_declare():
    pytest.importorskip("agno")
    from agno.tools.function import Function, FunctionCall

    fr, _, _ = _fr()
    fc = FunctionCall(function=Function.from_callable(lambda: "x"), arguments={})
    built = fc._build_hook_args(provenrail_tool_hook(fr), "tool_name", lambda: None, {"a": 1})
    # If Agno stops supplying any of these, capture would silently lose that field.
    assert set(built) == {"function_name", "function_call", "arguments"}
