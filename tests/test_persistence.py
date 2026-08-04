"""Persisted server identity: a hosted sink reboots without breaking verification.

The transparency-log key and the KYA registry key are generated once and stored in the DB,
so the public keys an auditor pins stay stable across restarts. A regenerated log key would
make every previously witnessed checkpoint unverifiable; a regenerated registry key would
void every embedded agent-identity assertion. These tests prove the keys survive a restart.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.keys import SigningKey
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _pubkeys(app) -> tuple[str, str]:
    c = TestClient(app)
    meta = c.get("/v1/meta").json()
    return meta["tlog_pubkey"], meta["registry_pubkey"]


def test_keys_stable_across_restart(tmp_path):
    db = str(tmp_path / "fr.db")
    app1 = create_app(db, anchor=LocalAnchor(), require_account=False)
    tlog1, reg1 = _pubkeys(app1)
    app1.state.store.close()

    app2 = create_app(db, anchor=LocalAnchor(), require_account=False)
    tlog2, reg2 = _pubkeys(app2)
    assert tlog1 == tlog2
    assert reg1 == reg2
    app2.state.store.close()


def test_fresh_db_gets_distinct_keys(tmp_path):
    a = create_app(str(tmp_path / "a.db"), anchor=LocalAnchor(), require_account=False)
    b = create_app(str(tmp_path / "b.db"), anchor=LocalAnchor(), require_account=False)
    assert _pubkeys(a) != _pubkeys(b)


def test_injected_key_overrides_persistence(tmp_path):
    key = SigningKey.generate()
    app = create_app(str(tmp_path / "fr.db"), anchor=LocalAnchor(),
                     require_account=False, tlog_log_key=key)
    tlog, _ = _pubkeys(app)
    assert tlog == key.public_key_hex()


def test_to_from_pem_roundtrip():
    key = SigningKey.generate()
    again = SigningKey.from_pem(key.to_pem())
    assert again.public_key_hex() == key.public_key_hex()
    msg = b"flight recorder"
    from provenrail.keys import verify_signature
    assert verify_signature(again.public_key_hex(), msg, again.sign(msg))


def test_bundle_verifies_with_persisted_tlog_key_after_restart(tmp_path):
    """Anchor a stream, restart the sink, and confirm the exported bundle still verifies
    against the persisted (unchanged) transparency-log public key."""
    from provenrail.verifier.verify import verify_bundle

    db = str(tmp_path / "fr.db")
    app1 = create_app(db, anchor=LocalAnchor(), require_account=False)
    c1 = TestClient(app1)
    prov = provision_stream("http://t", http=c1)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c1)
    with fr.session({"agent": "persist"}):
        fr.record_decision("hello")
    c1.post(f"/v1/streams/{prov['stream_id']}/anchor",
            headers={"Authorization": f"Bearer {prov['read_token']}"})
    tlog_pub = c1.get("/v1/meta").json()["tlog_pubkey"]
    app1.state.store.close()

    # Reboot on the same DB; export and verify with the key pinned before the reboot.
    app2 = create_app(db, anchor=LocalAnchor(), require_account=False)
    c2 = TestClient(app2)
    bundle = c2.get(f"/v1/streams/{prov['stream_id']}/export",
                    headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert c2.get("/v1/meta").json()["tlog_pubkey"] == tlog_pub
    report = verify_bundle(bundle, tlog_log_key=tlog_pub)
    assert report.ok, report.to_dict()
    app2.state.store.close()
