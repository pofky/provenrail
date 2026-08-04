"""Claude Agent SDK hook capture (duck-typed, no claude-agent-sdk dependency)."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations.claude_sdk import (
    make_post_tool_hook,
    make_pre_tool_hook,
    provenrail_hooks,
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


def test_pre_and_post_hooks_capture_tool_call():
    fr, c, prov = _fr()
    pre = make_pre_tool_hook(fr)
    post = make_post_tool_hook(fr)
    pre_in = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "session_id": "s1",
              "hook_event_name": "PreToolUse"}
    post_in = {"tool_name": "Bash", "tool_input": {"command": "ls"},
               "tool_response": "file.txt", "hook_event_name": "PostToolUse"}
    with fr.session():
        asyncio.run(pre(pre_in, "tu_1", None))
        asyncio.run(post(post_in, "tu_1", None))
    recs = _records(c, prov)
    actions = [r["action_type"] for r in recs]
    assert "tool_call_intent" in actions
    assert "tool_call" in actions
    tc = next(r for r in recs if r["action_type"] == "tool_call")
    assert tc["payload"]["tool"] == "Bash" and tc["payload"]["outcome"] == "success"


def test_post_hook_marks_error_response_as_failure():
    fr, c, prov = _fr()
    post = make_post_tool_hook(fr)
    post_in = {"tool_name": "Write", "tool_input": {"file_path": "/x"},
               "tool_response": {"is_error": True, "error": "denied"}}
    with fr.session():
        asyncio.run(post(post_in, "tu_2", None))
    tc = next(r for r in _records(c, prov) if r["action_type"] == "tool_call")
    assert tc["payload"]["outcome"] == "failure"


def test_hooks_are_pass_through_and_never_raise():
    fr, c, prov = _fr()
    pre = make_pre_tool_hook(fr)
    # Malformed input must not raise into the agent's path; hook returns a pass-through dict.
    with fr.session():
        out = asyncio.run(pre({}, None, None))
    assert out == {}


def test_provenrail_hooks_shape_without_sdk():
    fr, c, prov = _fr()
    hooks = provenrail_hooks(fr)
    assert set(hooks) == {"PreToolUse", "PostToolUse"}
    # Fallback shape (no claude-agent-sdk installed): list of {matcher, hooks} dicts.
    entry = hooks["PreToolUse"][0]
    if isinstance(entry, dict):
        assert "hooks" in entry and callable(entry["hooks"][0])
    else:  # HookMatcher present
        assert callable(entry.hooks[0])


def test_no_arg_hook_requires_active_recorder():
    with pytest.raises(RuntimeError):
        make_pre_tool_hook()
