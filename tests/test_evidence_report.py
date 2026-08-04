"""The auditor-grade verification report and its inclusion in the evidence pack."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.evidence_report import render_report_html
from provenrail.ingest_client import provision_stream
from provenrail.pack import build_pack
from provenrail.policy import Policy, Rule
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app

VECTORS = Path(__file__).parent / "vectors"


def _load(name):
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


def test_clean_report_shows_verified_and_timeline():
    html = render_report_html(_load("clean"))
    assert "Integrity verified" in html
    assert "Activity timeline" in html
    assert "Model call" in html and "Decision" in html  # timeline rendered the events
    assert "TAMPERING" not in html.upper().replace("NO TRUSTED", "")  # not a tampered verdict
    assert "\u2014" not in html and "\u2013" not in html  # no em/en glyphs


def test_tampered_report_shows_failure():
    html = render_report_html(_load("tamper_payload"))
    assert "Tampering detected" in html
    assert "Failures" in html
    assert "client_hash_mismatch" in html  # the defining finding is shown to the auditor


def test_report_includes_policy_panel_when_committed():
    sink = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(sink)
    prov = provision_stream("http://t", http=c)
    pol = Policy(rules=[Rule(id="cap", effect="limit", tool="x", max_per_session=5)])
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c, policy=pol)
    with fr.session({"agent": "rep"}):
        fr.record_decision("ok")
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/export",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    html = render_report_html(bundle)
    assert "Active guardrails" in html
    assert "Committed policy verified" in html


def test_pack_now_includes_report_html():
    data = build_pack(_load("clean"), regime="eu-ai-act")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        assert "report.html" in names
        assert "cover.html" in names  # the regime cover is still there too
        report = z.read("report.html").decode("utf-8")
    assert "verification report" in report.lower()


def test_pack_is_reproducible_with_report():
    a = build_pack(_load("clean"))
    b = build_pack(_load("clean"))
    assert a == b  # byte-identical: the added report must not break reproducibility
