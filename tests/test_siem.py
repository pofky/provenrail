"""SIEM NDJSON export: flattening, hash linkage, and the account-scoped endpoint."""
import json

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.server.siem import bundle_to_ndjson


def _seed():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)

    @fr.tool("search")
    def search(q):
        return {"hits": 1}

    with fr.session({"agent": "demo"}):
        fr.record_model_call("openai", "gpt-4o", {"p": "hi"}, {"t": "ok"},
                             usage={"input": "10", "output": "5"})
        search("x")
        fr.record_data_access("phi_db", "read")
    return c, prov, c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


def test_ndjson_one_line_per_record_and_parses():
    _, _, bundle = _seed()
    nd = bundle_to_ndjson(bundle)
    lines = [ln for ln in nd.splitlines() if ln]
    assert len(lines) == len(bundle["records"])
    for ln in lines:
        obj = json.loads(ln)  # every line is valid JSON
        assert "action" in obj and "record_hash" in obj and obj["stream_id"]


def test_ndjson_promotes_indexable_fields():
    _, _, bundle = _seed()
    rows = [json.loads(ln) for ln in bundle_to_ndjson(bundle).splitlines() if ln]
    mc = next(r for r in rows if r["action"] == "model_call")
    assert mc["provider"] == "openai" and mc["model"] == "gpt-4o" and mc["usage"]["input"] == "10"
    da = next(r for r in rows if r["action"] == "data_access")
    assert da["resource"] == "phi_db" and da["op"] == "read"
    tc = next(r for r in rows if r["action"] == "tool_call")
    assert tc["tool"] == "search" and tc["outcome"] == "success"


def test_ndjson_links_back_to_bundle_hashes():
    _, _, bundle = _seed()
    rows = [json.loads(ln) for ln in bundle_to_ndjson(bundle).splitlines() if ln]
    bundle_hashes = {sr["record"]["record_hash"] for sr in bundle["records"]}
    assert {r["record_hash"] for r in rows} == bundle_hashes


def test_ndjson_endpoint():
    c, prov, _ = _seed()
    r = c.get(f"/v1/streams/{prov['stream_id']}/export.ndjson")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in r.headers["content-disposition"]
    assert all(json.loads(ln)["stream_id"] == prov["stream_id"]
               for ln in r.text.splitlines() if ln)


def test_ndjson_endpoint_account_scoped():
    app = create_app(":memory:", require_account=True)
    c = TestClient(app)
    a = c.post("/v1/accounts", json={}).json()
    b = c.post("/v1/accounts", json={}).json()
    sa = c.post("/v1/streams", json={}, headers={"Authorization": f"Bearer {a['api_key']}"}).json()
    r = c.get(f"/v1/streams/{sa['stream_id']}/export.ndjson",
              headers={"Authorization": f"Bearer {b['api_key']}"})
    assert r.status_code == 403
