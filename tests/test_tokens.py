"""Token expiry, revocation, and the stream-revoke endpoint."""
import sqlite3

from fastapi.testclient import TestClient

from provenrail.ingest_client import provision_stream
from provenrail.server.app import create_app
from provenrail.server.tokens import READ, WRITE, TokenStore


def _store():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    return TokenStore(db)


def test_mint_and_resolve():
    ts = _store()
    t = ts.mint("s1", WRITE)
    assert ts.resolve(t) == ("s1", WRITE)
    assert ts.resolve("garbage") is None


def test_revoke_token_makes_it_dead():
    ts = _store()
    t = ts.mint("s1", READ)
    assert ts.resolve(t) is not None
    assert ts.revoke_token(t) is True
    assert ts.resolve(t) is None
    assert ts.revoke_token(t) is False  # already revoked


def test_revoke_stream_kills_all_tokens():
    ts = _store()
    w = ts.mint("s1", WRITE)
    r = ts.mint("s1", READ)
    other = ts.mint("s2", WRITE)
    assert ts.revoke_stream("s1") == 2
    assert ts.resolve(w) is None and ts.resolve(r) is None
    assert ts.resolve(other) is not None  # other stream untouched


def test_expired_token_does_not_resolve():
    ts = _store()
    t = ts.mint("s1", READ, ttl_seconds=-1)  # already expired
    assert ts.resolve(t) is None
    live = ts.mint("s1", READ, ttl_seconds=3600)
    assert ts.resolve(live) == ("s1", READ)


def test_migration_adds_columns_to_old_table():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    # simulate an old schema with no expiry/revocation columns
    db.execute("CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, stream_id TEXT, "
               "scope TEXT, created_at TEXT)")
    db.commit()
    ts = TokenStore(db)  # __init__ migrates
    t = ts.mint("s1", WRITE)
    assert ts.resolve(t) == ("s1", WRITE)
    assert ts.revoke_token(t) is True


def test_revoke_endpoint_blocks_further_use():
    app = create_app(":memory:", require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    sid = prov["stream_id"]
    # write works before revoke
    rec = {"stream_id": sid, "seq": 0, "action_type": "tool_call",
           "record_hash": "h0", "ts_utc": "2026-06-08T00:00:00.0Z"}
    h = {"Authorization": f"Bearer {prov['write_token']}"}
    assert c.post("/v1/ingest", json={"records": [rec]}, headers=h).status_code == 200
    # revoke
    r = c.post(f"/v1/streams/{sid}/revoke")
    assert r.status_code == 200 and r.json()["revoked"] >= 3
    # write and read now rejected
    rec2 = dict(rec, seq=1, record_hash="h1")
    assert c.post("/v1/ingest", json={"records": [rec2]}, headers=h).status_code == 401
    assert c.get(f"/v1/streams/{sid}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).status_code == 401


def test_revoke_endpoint_is_account_scoped():
    app = create_app(":memory:", require_account=True)
    c = TestClient(app)
    a = c.post("/v1/accounts", json={}).json()
    b = c.post("/v1/accounts", json={}).json()
    sa = c.post("/v1/streams", json={}, headers={"Authorization": f"Bearer {a['api_key']}"}).json()
    r = c.post(f"/v1/streams/{sa['stream_id']}/revoke",
               headers={"Authorization": f"Bearer {b['api_key']}"})
    assert r.status_code == 403
