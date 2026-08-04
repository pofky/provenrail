"""Async (non-blocking) transport and async/streaming capture."""
import asyncio
import types

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations import instrument_openai
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _setup():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     ingest_per_min=0)  # 0 disables limit
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    return app, c, prov


def _export(c, prov):
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


def test_async_transport_flushes_and_verifies():
    app, c, prov = _setup()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        flush_mode="async", flush_interval=0.05)
    with fr.session():
        for i in range(20):
            fr.record_decision(f"step {i}")
    # session() blocks on close() -> all 22 records (genesis + 20 + seal) are off-box
    bundle = _export(c, prov)
    assert len(bundle["records"]) == 22
    assert verify_bundle(bundle).ok


def test_async_preserves_emission_order():
    app, c, prov = _setup()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        flush_mode="async", flush_interval=0.02, flush_batch=5)
    with fr.session():
        for i in range(30):
            fr.record_decision(f"s{i}")
    bundle = _export(c, prov)
    seqs = [r["record"]["seq"] for r in bundle["records"]]
    assert seqs == sorted(seqs) == list(range(len(seqs)))
    assert verify_bundle(bundle).ok


def test_async_openai_capture():
    app, c, prov = _setup()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)

    resp = types.SimpleNamespace(usage=types.SimpleNamespace(input_tokens=3, output_tokens=1))

    async def acreate(**kw):
        return resp

    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=acreate)))
    instrument_openai(client, fr)

    async def run():
        with fr.session():
            await client.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": "hi"}])

    asyncio.run(run())
    bundle = _export(c, prov)
    mc = [r["record"] for r in bundle["records"] if r["record"]["action_type"] == "model_call"]
    assert len(mc) == 1 and mc[0]["payload"]["model"] == "gpt-x"


def test_streaming_records_request_only():
    app, c, prov = _setup()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)

    def stream_iter():
        yield "a"
        yield "b"

    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(
            create=lambda **kw: stream_iter())))
    instrument_openai(client, fr)
    with fr.session():
        gen = client.chat.completions.create(model="gpt-x", stream=True,
                                             messages=[{"role": "user", "content": "hi"}])
        assert list(gen) == ["a", "b"]  # caller's stream is untouched
    bundle = _export(c, prov)
    mc = next(r["record"] for r in bundle["records"] if r["record"]["action_type"] == "model_call")
    assert mc["payload"]["extra"]["streaming"] is True
