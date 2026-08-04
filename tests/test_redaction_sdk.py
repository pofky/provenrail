"""SDK integration: redactable fields become commitments at the sink; openings stay operator-side."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

import provenrail as fr
from provenrail import redaction as rd
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _sink():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    return app, c, prov


def test_front_door_exports_redactable():
    assert fr.redactable("x").value == "x"


def test_sink_never_sees_cleartext_but_record_commits_to_it():
    app, c, prov = _sink()
    rec = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                         capture_content=True)  # even with content capture on, redacted stays hidden
    secret = "patient SSN 078-05-1120"
    with rec.session({"agent": "phi"}):
        rec.record_model_call("openai", "gpt-4o",
                              request={"prompt": fr.redactable(secret), "model": "gpt-4o"},
                              response="ok")

    bundle = c.get(f"/v1/streams/{prov['stream_id']}/export",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    blob = json.dumps(bundle)
    assert secret not in blob                      # the sink never received the cleartext
    assert rd.MARKER in blob                        # but a commitment to it is in the record
    # exactly one opening, held operator-side
    assert len(rec.openings()) == 1
    # and the immutable record still verifies (commitments are opaque signed content)
    assert verify_bundle(bundle).ok


def test_disclose_from_bundle_with_operator_openings():
    app, c, prov = _sink()
    rec = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                         capture_content=True)
    with rec.session({"agent": "phi"}):
        rec.record_tool_call("lookup", {"q": fr.redactable("classified query")}, {"ok": True})
    openings = rec.openings()

    bundle = c.get(f"/v1/streams/{prov['stream_id']}/export",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    # find the tool_call record and disclose its args using the operator keystore
    tool = next(sr["record"] for sr in bundle["records"]
                if sr["record"]["action_type"] == "tool_call")
    disclosed = rd.disclose(tool["payload"], openings)
    assert disclosed["args"]["content"]["q"] == "classified query"

    # erasure: with the keystore destroyed, the value cannot be recovered, record still verifies
    erased = rd.disclose(tool["payload"], {})
    assert "__withheld__" in erased["args"]["content"]["q"]
    assert verify_bundle(bundle).ok


def test_openings_written_to_disclosure_path(tmp_path):
    app, c, prov = _sink()
    path = tmp_path / "openings.json"
    rec = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                         disclosure_path=str(path))
    with rec.session({"agent": "phi"}):
        rec.record_decision("note", detail=fr.redactable("sensitive rationale"))
    assert path.is_file()
    saved = json.loads(path.read_text())
    assert saved["format"] == "flightrecorder.openings/1"
    assert len(saved["openings"]) == 1
