"""The free local loop: `pr quickstart` saves a read token so `pr export` can pull the user's
own run back out, and `pr verify` confirms it. This guards the contract the export CLI depends
on, so a user with no account can close record -> export -> verify entirely on their own box.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.easy import CONFIG_FILENAME, _load_config_file, write_config
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def test_provision_returns_read_token():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    prov = provision_stream("http://t", http=TestClient(app))
    # export needs a READ token; quickstart can only save it if provision returns it.
    assert prov.get("read_token")
    assert prov["read_token"] != prov["write_token"]


def test_quickstart_config_round_trips_read_token(tmp_path, monkeypatch):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    prov = provision_stream("http://t", http=TestClient(app))

    monkeypatch.chdir(tmp_path)
    # Mirror exactly what _cmd_quickstart now writes.
    write_config(CONFIG_FILENAME, endpoint="http://t",
                 write_token=prov["write_token"], stream_id=prov["stream_id"],
                 read_token=prov.get("read_token"), share_token=prov.get("share_token"))

    cfg = _load_config_file()
    assert cfg["read_token"] == prov["read_token"]
    assert cfg["stream_id"] == prov["stream_id"]
    # Sanity: the file on disk really carries it (this is what `pr export` reads).
    on_disk = json.loads((tmp_path / CONFIG_FILENAME).read_text())
    assert on_disk["read_token"] == prov["read_token"]


def test_export_with_saved_read_token_verifies():
    """The end the CLI automates: record a run, then export it with the saved read token and
    verify the exported bundle. This is the user verifying their OWN run, free and offline."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    client = TestClient(app)
    prov = provision_stream("http://t", http=client)
    read_token = prov["read_token"]

    fr = FlightRecorder(endpoint="http://t", write_token=prov["write_token"],
                        stream_id=prov["stream_id"], http=client)
    with fr.session({"agent": "loop"}):
        fr.record_model_call("anthropic", "claude-opus-4-8",
                             {"prompt": "hi"}, {"text": "hello"})
        fr.record_decision("ok", confidence="high")

    # Exactly what `pr export` does: anchor then export, both with the saved read token.
    client.post(f"/v1/streams/{prov['stream_id']}/anchor",
                headers={"Authorization": f"Bearer {read_token}"})
    exp = client.get(f"/v1/streams/{prov['stream_id']}/export",
                     headers={"Authorization": f"Bearer {read_token}"})
    assert exp.status_code == 200
    bundle = exp.json()

    rep = verify_bundle(bundle)
    assert rep.ok, rep.to_dict()
    assert len(bundle["anchors"]) >= 1


def test_export_rejects_write_token():
    """A write token must NOT be able to export: that separation is why the read token has to be
    saved separately. Guards against a regression that lets the append-only token read."""
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    client = TestClient(app)
    prov = provision_stream("http://t", http=client)
    exp = client.get(f"/v1/streams/{prov['stream_id']}/export",
                     headers={"Authorization": f"Bearer {prov['write_token']}"})
    assert exp.status_code in (401, 403)
