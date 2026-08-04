"""Hermes Agent observer-hook capture (duck-typed, no hermes dependency).

Hermes fires observer hooks with keyword arguments only and treats them as fail-open:
it catches callback exceptions and keeps the agent loop running. These tests drive the
callbacks exactly that way, using the payload shapes Hermes documents for
`hermes.observer.v1` (see `_DEFAULT_PAYLOADS` in hermes_cli/hooks.py upstream).
"""
import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations.hermes import (
    make_post_tool_call,
    make_pre_tool_call,
    register_provenrail,
)
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app

# The payload Hermes actually sends, copied from its own hook test fixtures.
PRE_PAYLOAD = {
    "tool_name": "terminal",
    "args": {"command": "echo hello"},
    "session_id": "test-session",
    "task_id": "test-task",
    "tool_call_id": "test-call",
}
POST_PAYLOAD = {
    **PRE_PAYLOAD,
    "result": '{"output": "hello"}',
    "duration_ms": 42,
}


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


def _by_type(c, prov, kind):
    return [r for r in _records(c, prov) if r["action_type"] == kind]


class FakeCtx:
    """Stand-in for the Hermes plugin context passed to register(ctx)."""

    def __init__(self):
        self.hooks = {}

    def register_hook(self, event, fn):
        self.hooks[event] = fn


def test_post_tool_call_records_the_completed_call():
    fr, c, prov = _fr()
    with fr.session():
        make_post_tool_call(fr)(**POST_PAYLOAD)

    call = _by_type(c, prov, "tool_call")[0]["payload"]
    assert call["tool"] == "terminal"
    assert call["outcome"] == "success"
    assert call["extra"]["framework"] == "hermes"
    assert call["extra"]["session_id"] == "test-session"
    assert call["extra"]["tool_call_id"] == "test-call"
    assert call["extra"]["duration_ms"] == 42


def test_pre_tool_call_records_intent_and_never_blocks():
    fr, c, prov = _fr()
    with fr.session():
        # Returning a dict from pre_tool_call would BLOCK the tool in Hermes, so the
        # recorder must return None. This assertion is load-bearing, not cosmetic.
        assert make_pre_tool_call(fr)(**PRE_PAYLOAD) is None

    intent = _by_type(c, prov, "tool_call_intent")[0]["payload"]
    assert intent["tool"] == "terminal"
    assert intent["task_id"] == "test-task"


@pytest.mark.parametrize(("status", "expected"), [
    ("ok", "success"),
    ("error", "failure"),
    # A policy denial and a cancellation are NOT tool failures. Folding them into
    # "failure" would misstate what the evidence shows.
    ("blocked", "blocked"),
    ("cancelled", "cancelled"),
    ("canceled", "cancelled"),
    ("some_future_status", "some_future_status"),  # reported verbatim, never guessed
])
def test_hermes_status_maps_to_a_faithful_outcome(status, expected):
    fr, c, prov = _fr()
    with fr.session():
        make_post_tool_call(fr)(**{**POST_PAYLOAD, "status": status})
    payload = _by_type(c, prov, "tool_call")[0]["payload"]
    assert payload["outcome"] == expected
    assert payload["extra"]["hermes_status"] == status  # raw status always preserved


def test_error_type_and_message_are_captured():
    fr, c, prov = _fr()
    with fr.session():
        make_post_tool_call(fr)(**{**POST_PAYLOAD, "status": "error",
                                   "error_type": "TimeoutError",
                                   "error_message": "tool timed out after 30s"})
    extra = _by_type(c, prov, "tool_call")[0]["payload"]["extra"]
    assert extra["error_type"] == "TimeoutError"
    assert extra["error_message"] == "tool timed out after 30s"


def test_error_field_without_status_is_recorded_as_failure():
    fr, c, prov = _fr()
    payload = {k: v for k, v in POST_PAYLOAD.items()}
    payload["error"] = "tool exploded"
    with fr.session():
        make_post_tool_call(fr)(**payload)
    assert _by_type(c, prov, "tool_call")[0]["payload"]["outcome"] == "failure"


def test_json_string_results_are_parsed_but_plain_strings_survive():
    fr, c, prov = _fr()
    with fr.session():
        post = make_post_tool_call(fr)
        post(**{**POST_PAYLOAD, "result": '{"output": "hello"}'})
        post(**{**POST_PAYLOAD, "result": "not json at all"})
    assert len(_by_type(c, prov, "tool_call")) == 2  # neither shape raises


def test_unknown_additive_fields_do_not_break_capture():
    # Hermes documents that hooks must tolerate additive payload fields.
    fr, c, prov = _fr()
    with fr.session():
        make_post_tool_call(fr)(**POST_PAYLOAD, telemetry_schema_version="hermes.observer.v1",
                                some_future_field={"added": "later"})
    assert len(_by_type(c, prov, "tool_call")) == 1


def test_non_integer_duration_is_dropped_not_fatal():
    # The canonical format bans floats, so a float duration must not poison the record.
    fr, c, prov = _fr()
    with fr.session():
        make_post_tool_call(fr)(**{**POST_PAYLOAD, "duration_ms": 42.7})
    extra = _by_type(c, prov, "tool_call")[0]["payload"]["extra"]
    assert extra["duration_ms"] == 42
    assert isinstance(extra["duration_ms"], int)


def test_capture_is_fail_open_when_the_sink_is_down():
    class Exploding:
        def record(self, *a, **k):
            raise RuntimeError("sink down")

        def record_tool_call(self, *a, **k):
            raise RuntimeError("sink down")

    # Hermes catches exceptions, but a recorder that relies on that would still spam
    # warnings and lose the fail-open contract. Swallow inside the callback instead.
    assert make_post_tool_call(Exploding())(**POST_PAYLOAD) is None
    assert make_pre_tool_call(Exploding())(**PRE_PAYLOAD) is None


def test_register_provenrail_registers_both_hooks():
    fr, c, prov = _fr()
    ctx = FakeCtx()
    assert register_provenrail(ctx, recorder=fr) is fr
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call"}

    with fr.session():
        ctx.hooks["pre_tool_call"](**PRE_PAYLOAD)
        ctx.hooks["post_tool_call"](**POST_PAYLOAD)

    assert len(_by_type(c, prov, "tool_call_intent")) == 1
    assert len(_by_type(c, prov, "tool_call")) == 1


def test_register_provenrail_can_skip_intent_capture():
    fr, _, _ = _fr()
    ctx = FakeCtx()
    register_provenrail(ctx, recorder=fr, capture_intent=False)
    assert set(ctx.hooks) == {"post_tool_call"}


def test_no_arg_callback_requires_an_active_recorder():
    with pytest.raises(RuntimeError, match="No active recorder"):
        make_post_tool_call()
