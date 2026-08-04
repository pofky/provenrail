"""Verifier side of selective disclosure: count commitments, validate openings, catch forgeries."""

from __future__ import annotations

from fastapi.testclient import TestClient

import provenrail as fr
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import load_openings, verify_bundle


def _bundle_with_redaction():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    rec = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with rec.session({"agent": "phi"}):
        rec.record_model_call("openai", "gpt-4o",
                              request={"prompt": fr.redactable("SSN 078-05-1120")}, response="ok")
        rec.record_decision("done", note=fr.redactable("internal rationale"))
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/export",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    return bundle, rec.openings()


def _findings(rep):
    return {f.code: f for f in rep.findings}


def test_base_verify_ok_and_counts_redacted_without_openings():
    bundle, _ = _bundle_with_redaction()
    rep = verify_bundle(bundle)  # no openings supplied: everything withheld
    assert rep.ok
    summary = _findings(rep)["redaction_summary"]
    assert "2 redactable field(s)" in summary.detail
    assert "0 disclosed" in summary.detail
    assert "2 withheld or erased" in summary.detail


def test_disclosed_openings_verify_clean():
    bundle, openings = _bundle_with_redaction()
    rep = verify_bundle(bundle, disclosure_openings=openings)
    assert rep.ok
    assert "2 disclosed and verified" in _findings(rep)["redaction_summary"].detail


def test_forged_disclosure_is_a_hard_fail():
    bundle, openings = _bundle_with_redaction()
    # the operator (or a tamperer) lies about a value while keeping the original salt
    c0 = next(iter(openings))
    forged = dict(openings)
    forged[c0] = {"alg": "sha256", "salt": openings[c0]["salt"], "value": "A DIFFERENT VALUE"}
    rep = verify_bundle(bundle, disclosure_openings=forged)
    assert not rep.ok
    assert "redaction_disclosure_invalid" in _findings(rep)


def test_partial_disclosure_one_field():
    bundle, openings = _bundle_with_redaction()
    # disclose only the first commitment, withhold the rest (minimum-necessary disclosure)
    first = dict(list(openings.items())[:1])
    rep = verify_bundle(bundle, disclosure_openings=first)
    assert rep.ok
    detail = _findings(rep)["redaction_summary"].detail
    assert "1 disclosed and verified" in detail and "1 withheld" in detail


def test_load_openings_accepts_both_shapes():
    raw = {"abc": {"salt": "00", "value": 1}}
    assert load_openings(raw) == raw
    assert load_openings({"format": "flightrecorder.openings/1", "openings": raw}) == raw
    assert load_openings(None) == {}
