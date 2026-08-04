"""Cross-language compatibility: records signed by the JavaScript SDK must verify under the
Python verifier AND the JavaScript verifier.

This is the load-bearing guarantee for the TS/JS SDK: a TypeScript agent's run is real, portable
evidence, not a second-class format. The JS SDK signs records (Ed25519 over canonical JSON), the
Python sink re-chains and anchors them exactly as it does Python-produced records, and the standalone
verifier recomputes every hash and signature from scratch. If the canonicalization or signing
disagreed across languages by a single byte, the client-chain signature check would fail.
"""

import json
import pathlib
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle

HERE = pathlib.Path(__file__).parent
SDK_EMIT = HERE / "js" / "sdk_emit.mjs"
CONFORMANCE = HERE / "js" / "conformance.mjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _emit_with_js_sdk(stream_id: str) -> list[dict]:
    result = subprocess.run(["node", str(SDK_EMIT), stream_id],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"JS SDK emit failed:\n{result.stdout}\n{result.stderr}"
    return json.loads(result.stdout)


def test_js_sdk_records_verify_in_python_and_js(tmp_path):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    stream_id, write_token = prov["stream_id"], prov["write_token"]

    # 1. The JavaScript SDK signs a full session for THIS stream.
    records = _emit_with_js_sdk(stream_id)
    assert records[0]["action_type"] == "lifecycle.session_start"
    assert records[-1]["action_type"] == "lifecycle.session_end"
    # Every record was signed by the same JS device key, with a real Ed25519 signature.
    assert all(len(r["record_sig"]) == 128 for r in records)
    assert len({r["pubkey"] for r in records}) == 1

    # 2. The Python sink ingests them exactly as if they came from the Python SDK.
    resp = c.post("/v1/ingest", json={"records": records},
                  headers={"Authorization": f"Bearer {write_token}"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == len(records)

    c.post(f"/v1/streams/{stream_id}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{stream_id}/bundle").json()

    # 3. The Python verifier accepts the JS-signed run: no client-chain failure of any kind.
    rep = verify_bundle(bundle)
    fails = {f.code for f in rep.findings if f.severity == "fail"}
    assert not fails, f"Python verifier rejected JS-signed records: {fails}"
    assert rep.ok

    # 4. The JavaScript verifier accepts the same bundle (full two-implementation lockstep on
    #    JS-PRODUCED data, not only Python-produced data).
    (tmp_path / "js_bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    manifest = [{"name": "js_sdk_run", "bundle": "js_bundle.json", "expect_ok": True}]
    (tmp_path / "m.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(["node", str(CONFORMANCE), str(tmp_path / "m.json")],
                            capture_output=True, text=True)
    assert result.returncode == 0, \
        f"JS verifier rejected JS-signed records:\n{result.stdout}\n{result.stderr}"
    assert "PASS js_sdk_run " in result.stdout


def test_js_sdk_tamper_is_detected(tmp_path):
    """A payload altered after the JS SDK signed it must be caught by the Python verifier, proving
    the signature really binds the content across languages."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    stream_id = prov["stream_id"]
    records = _emit_with_js_sdk(stream_id)

    # Tamper with a model-call payload after signing.
    for r in records:
        if r["action_type"] == "model_call":
            r["payload"]["model"] = "evil-model"
            break

    c.post("/v1/ingest", json={"records": records},
           headers={"Authorization": f"Bearer {prov['write_token']}"})
    c.post(f"/v1/streams/{stream_id}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{stream_id}/bundle").json()

    rep = verify_bundle(bundle)
    codes = {f.code for f in rep.findings}
    assert not rep.ok
    assert "client_hash_mismatch" in codes or "client_bad_signature" in codes
