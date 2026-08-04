"""The out-of-process capture sidecar: a recording reverse proxy in front of a model API.

These tests stand up a fake provider, put the sidecar in front of it, and drive it as an agent
would (the agent code never touches Provenrail). They assert the call is forwarded
faithfully AND recorded off-box from a separate process, with the recorded response hash
committing to the exact upstream bytes (so tampering with the transcript later is detectable).
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.canonical import hash_value
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.sidecar import create_sidecar_app, infer_provider, is_model_call

# ---- a fake upstream model provider ----

def _fake_upstream() -> FastAPI:
    up = FastAPI()

    @up.post("/v1/chat/completions")
    async def chat(payload: dict):
        return {"id": "cmpl-1", "model": payload.get("model"),
                "choices": [{"message": {"role": "assistant", "content": "hi there"}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 5}}

    @up.get("/v1/models")
    async def models():
        return {"data": [{"id": "gpt-4o"}]}

    @up.post("/v1/stream")
    async def stream(payload: dict):
        async def gen():
            yield b'data: {"delta":"hi"}\n\n'
            yield b'data: {"usage":{"prompt_tokens":7,"completion_tokens":3}}\n\n'
            yield b"data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")

    return up


def _sink_and_recorder(**rec_kw):
    sink = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    sc = TestClient(sink)
    prov = provision_stream("http://sink", http=sc)
    rec = FlightRecorder("http://sink", prov["write_token"], prov["stream_id"], http=sc,
                         flush_mode="async", **rec_kw)
    return sink, sc, prov, rec


def _fwd_client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=_fake_upstream()),
                             base_url="http://up")


def _model_calls(sink, stream_id):
    bundle = sink.state.store  # read straight from storage
    recs = bundle.get_records(stream_id)
    out = []
    for r in recs:
        rec = r["client_record"] if isinstance(r, dict) and "client_record" in r else r
        import json
        body = json.loads(rec) if isinstance(rec, str) else rec
        action = body.get("action_type") or body.get("record", {}).get("action_type")
        payload = body.get("payload") or body.get("record", {}).get("payload", {})
        if action == "model_call":
            out.append(payload)
    return out


# ---- unit ----

def test_provider_inference():
    assert infer_provider("https://api.openai.com") == "openai"
    assert infer_provider("https://api.anthropic.com/v1") == "anthropic"


def test_is_model_call_detection():
    import json
    assert is_model_call("POST", json.dumps({"model": "x", "messages": []}).encode())
    assert not is_model_call("GET", b"")
    assert not is_model_call("POST", json.dumps({"hello": 1}).encode())


# ---- integration ----

def test_forwards_and_records_chat_completion():
    sink, sc, prov, rec = _sink_and_recorder()
    side = create_sidecar_app(rec, "https://api.openai.com", client=_fwd_client())
    with TestClient(side) as agent:
        # The "agent" only knows the sidecar URL. It never imports Provenrail.
        resp = agent.post("/v1/chat/completions",
                          json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
        assert resp.status_code == 200
        upstream_json = resp.json()
        assert upstream_json["choices"][0]["message"]["content"] == "hi there"
        rec.flush()  # drain the async recorder before inspecting the sink

        calls = _model_calls(sink, prov["stream_id"])
        assert len(calls) == 1
        call = calls[0]
        assert call["provider"] == "openai"
        assert call["model"] == "gpt-4o"
        assert call["usage"] == {"input": "11", "output": "5"}
        # The recorded response hash commits to the EXACT upstream response bytes.
        assert call["response"]["hash"] == hash_value(upstream_json)


def test_streaming_is_passed_through_and_recorded():
    sink, sc, prov, rec = _sink_and_recorder()
    side = create_sidecar_app(rec, "https://api.openai.com", client=_fwd_client())
    with TestClient(side) as agent:
        resp = agent.post("/v1/stream", json={"model": "gpt-4o", "messages": [{"role": "user"}]})
        assert resp.status_code == 200
        assert b"[DONE]" in resp.content  # the stream reached the agent intact
        rec.flush()
        calls = _model_calls(sink, prov["stream_id"])
        assert len(calls) == 1
        # usage was recovered from the SSE stream
        assert calls[0]["usage"] == {"input": "7", "output": "3"}


def test_non_model_requests_pass_through_unrecorded():
    sink, sc, prov, rec = _sink_and_recorder()
    side = create_sidecar_app(rec, "https://api.openai.com", client=_fwd_client())
    with TestClient(side) as agent:
        resp = agent.get("/v1/models")
        assert resp.status_code == 200
        assert resp.json()["data"][0]["id"] == "gpt-4o"
        rec.flush()
        assert _model_calls(sink, prov["stream_id"]) == []


def test_fail_closed_refuses_when_recording_fails():
    sink, sc, prov, rec = _sink_and_recorder()

    def _boom(*a, **k):
        raise RuntimeError("sink down")

    rec.record_model_call = _boom  # simulate an unrecordable call
    side = create_sidecar_app(rec, "https://api.openai.com", client=_fwd_client(),
                              fail_closed=True)
    with TestClient(side) as agent:
        resp = agent.post("/v1/chat/completions",
                          json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
        assert resp.status_code == 502
        assert "could not be recorded" in resp.text
