"""Evidence pack: builder, manifest integrity, CLI, and account-scoped endpoint."""
import io
import json
import zipfile

from fastapi.testclient import TestClient

from provenrail import cli
from provenrail.anchor import LocalAnchor
from provenrail.canonical import sha256_hex
from provenrail.ingest_client import provision_stream
from provenrail.pack import build_pack
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _bundle():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_model_call("anthropic", "claude-sonnet-4", "q", "a")
        fr.record_data_access("phi_db", "read")
        fr.record_human_oversight("approved")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c, prov, c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()


def test_pack_contains_expected_files_and_valid_manifest():
    _, _, bundle = _bundle()
    data = build_pack(bundle, regime="eu-ai-act")
    z = zipfile.ZipFile(io.BytesIO(data))
    names = set(z.namelist())
    assert {"bundle.json", "evidence-report-eu-ai-act.json", "evidence-report-eu-ai-act.md",
            "cover.html", "VERIFY.txt", "MANIFEST.json"} <= names
    cover = z.read("cover.html").decode()
    assert "Integrity:" in cover and "Art. 12" in cover
    manifest = json.loads(z.read("MANIFEST.json"))
    assert manifest["format"] == "flightrecorder.evidence-pack/1"
    # every manifest hash matches the actual file bytes (manifest excludes itself)
    for name, meta in manifest["files"].items():
        assert sha256_hex(z.read(name)) == meta["sha256"]
    # the enclosed bundle is the real verifiable bundle
    assert json.loads(z.read("bundle.json"))["format"] == "flightrecorder.bundle/1"


def test_pack_includes_pin_when_supplied():
    _, _, bundle = _bundle()
    data = build_pack(bundle, regime="hipaa", pin={"stream_id": "x", "recv_seq": 0})
    z = zipfile.ZipFile(io.BytesIO(data))
    assert "pin.json" in z.namelist()
    assert "--pin pin.json" in z.read("VERIFY.txt").decode()


def test_pack_is_reproducible():
    _, _, bundle = _bundle()
    assert build_pack(bundle, regime="generic") == build_pack(bundle, regime="generic")


def test_pack_disclaimer_present():
    _, _, bundle = _bundle()
    z = zipfile.ZipFile(io.BytesIO(build_pack(bundle, regime="eu-ai-act")))
    assert "NOT a certification" in z.read("VERIFY.txt").decode()
    att = json.loads(z.read("evidence-report-eu-ai-act.json"))
    assert "Art. 12" in json.dumps(att)


def test_verify_txt_gives_actionable_browser_url():
    """The 'verify in a browser' step must name the actual URL; an auditor cannot act on
    'open the hosted verifier' alone."""
    _, _, bundle = _bundle()
    z = zipfile.ZipFile(io.BytesIO(build_pack(bundle, regime="generic")))
    guide = z.read("VERIFY.txt").decode()
    assert "https://provenrail.com/verify" in guide
    assert "Legal notice" in guide  # disclaimer is its own section, not jammed onto a paragraph


def test_evidence_endpoint_returns_zip():
    c, prov, _ = _bundle()
    r = c.get(f"/v1/streams/{prov['stream_id']}/evidence?regime=hipaa")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "evidence-report-hipaa.md" in z.namelist()


def test_evidence_endpoint_rejects_bad_regime():
    c, prov, _ = _bundle()
    assert c.get(f"/v1/streams/{prov['stream_id']}/evidence?regime=nope").status_code == 422


def test_evidence_endpoint_is_account_scoped():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True)
    c = TestClient(app)
    a = c.post("/v1/accounts", json={}).json()
    b = c.post("/v1/accounts", json={}).json()
    ha = {"Authorization": f"Bearer {a['api_key']}"}
    sa = c.post("/v1/streams", json={"label": "a"}, headers=ha).json()
    rb = c.get(f"/v1/streams/{sa['stream_id']}/evidence",
               headers={"Authorization": f"Bearer {b['api_key']}"})
    assert rb.status_code == 403


def test_cli_pack(tmp_path, capsys):
    out = tmp_path / "bundle.json"
    pin = tmp_path / "pin.json"
    assert cli.main(["demo", "--out", str(out), "--pin", str(pin)]) == 0
    pack = tmp_path / "evidence.zip"
    assert cli.main(["pack", str(out), "--regime", "eu-ai-act", "--pin", str(pin),
                     "--out", str(pack)]) == 0
    z = zipfile.ZipFile(pack)
    assert "MANIFEST.json" in z.namelist() and "pin.json" in z.namelist()
