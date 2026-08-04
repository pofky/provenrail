import pytest
from fastapi.testclient import TestClient

from provenrail.server.app import create_app
from provenrail.server.storage import Storage


def make_client():
    app = create_app(":memory:", require_account=False)
    return TestClient(app)


def test_root_redirects_to_dashboard():
    """Opening the server's base URL must not 404 (reads as a broken server); it redirects to
    the dashboard."""
    client = TestClient(make_client().app, follow_redirects=False)
    r = client.get("/")
    assert r.status_code == 307
    assert r.headers["location"] == "/app"


def provision(client):
    r = client.post("/v1/streams", json={"label": "t"})
    assert r.status_code == 200
    return r.json()


def make_record(stream_id, seq=0):
    # minimal record shape the server stores (server does not validate the client chain)
    return {"stream_id": stream_id, "seq": seq, "action_type": "tool_call",
            "record_hash": f"h{seq}", "ts_utc": "2026-06-08T00:00:00.0Z"}


def test_write_token_cannot_read():
    c = make_client()
    p = provision(c)
    r = c.get(f"/v1/streams/{p['stream_id']}/export",
              headers={"Authorization": f"Bearer {p['write_token']}"})
    assert r.status_code == 403


def test_read_token_cannot_write():
    c = make_client()
    p = provision(c)
    r = c.post("/v1/ingest", json={"records": [make_record(p["stream_id"])]},
               headers={"Authorization": f"Bearer {p['read_token']}"})
    assert r.status_code == 403


def test_ingest_and_export_roundtrip():
    c = make_client()
    p = provision(c)
    recs = [make_record(p["stream_id"], i) for i in range(3)]
    r = c.post("/v1/ingest", json={"records": recs},
               headers={"Authorization": f"Bearer {p['write_token']}"})
    assert r.status_code == 200
    assert r.json()["accepted"] == 3
    e = c.get(f"/v1/streams/{p['stream_id']}/export",
              headers={"Authorization": f"Bearer {p['read_token']}"})
    assert e.status_code == 200
    body = e.json()
    assert len(body["records"]) == 3
    assert body["records"][0]["recv_seq"] == 0


def test_no_delete_route_exists():
    c = make_client()
    p = provision(c)
    # there is no delete endpoint; a DELETE on the stream must not be allowed
    r = c.delete(f"/v1/streams/{p['stream_id']}")
    assert r.status_code in (404, 405)


def test_storage_is_append_only_at_db_layer():
    import sqlite3
    s = Storage(":memory:")
    s.create_stream("s1")
    s.append_record("s1", {"stream_id": "s1", "seq": 0})
    with pytest.raises(sqlite3.Error):
        s._db.execute("DELETE FROM records WHERE stream_id='s1'")
        s._db.commit()
    with pytest.raises(sqlite3.Error):
        s._db.execute("UPDATE records SET recv_hash='x' WHERE stream_id='s1'")
        s._db.commit()


def test_share_view_is_public_html():
    c = make_client()
    p = provision(c)
    c.post("/v1/ingest", json={"records": [make_record(p["stream_id"], 0)]},
           headers={"Authorization": f"Bearer {p['write_token']}"})
    r = c.get(f"/share/{p['share_token']}")
    assert r.status_code == 200
    assert "Agent activity proof" in r.text
