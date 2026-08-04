"""Step 4: witness cosigning, split-view defenses, and the end-to-end green path."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from provenrail import tlog
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.keys import SigningKey
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.server.witness import (
    InsufficientWitnessesError,
    LocalWitness,
    WitnessClient,
    WitnessError,
    WitnessRollbackError,
    WitnessSplitViewAlert,
    collect_cosignatures,
)
from provenrail.verifier.verify import verify_bundle


def _checkpoint(origin, size, leaves):
    root = tlog.merkle_root_from_leaf_hashes(leaves)
    body = tlog.build_checkpoint(origin, size, root)
    note = tlog.sign_checkpoint(body, SigningKey.generate(), origin)
    return body, note, root


def _leafset(n):
    return [tlog.compute_leaf_hash(tlog.compute_anchor_commit(
        "s", i, i, "ab" * 32, "t", "local", f"sig{i}")) for i in range(n)]


# ---- LocalWitness cosigning logic ----

def test_local_witness_cosigns_first_checkpoint():
    leaves = _leafset(2)
    origin = "log"
    _, note, _ = _checkpoint(origin, 2, leaves)
    w = LocalWitness("w1", clock=lambda: 1_700_000_000)
    line = w.cosign(note, None)
    assert line.startswith("\u2014")
    assert w.last_cosigned_size(origin) == 2


def test_local_witness_accepts_consistent_growth():
    leaves = _leafset(4)
    origin = "log"
    w = LocalWitness("w1", clock=lambda: 1_700_000_000)
    _, note2, _ = _checkpoint(origin, 2, leaves[:2])
    w.cosign(note2, None)
    proof = tlog.make_consistency_proof(2, 4, leaves)
    _, note4, _ = _checkpoint(origin, 4, leaves)
    line = w.cosign(note4, proof)
    assert line and w.last_cosigned_size(origin) == 4


def test_local_witness_rejects_rollback():
    leaves = _leafset(4)
    origin = "log"
    w = LocalWitness("w1", clock=lambda: 1)
    _, note4, _ = _checkpoint(origin, 4, leaves)
    w.cosign(note4, None)
    _, note2, _ = _checkpoint(origin, 2, leaves[:2])
    with pytest.raises(WitnessRollbackError):
        w.cosign(note2, None)


def test_local_witness_rejects_equivocation_same_size():
    origin = "log"
    w = LocalWitness("w1", clock=lambda: 1)
    leaves_a = _leafset(2)
    leaves_b = list(leaves_a)
    leaves_b[1] = tlog.compute_leaf_hash(tlog.compute_anchor_commit(
        "s", 1, 1, "ab" * 32, "t", "local", "EVIL"))
    _, note_a, _ = _checkpoint(origin, 2, leaves_a)
    w.cosign(note_a, None)
    _, note_b, _ = _checkpoint(origin, 2, leaves_b)
    with pytest.raises(WitnessError):
        w.cosign(note_b, None)  # same size, different root: split view


def test_local_witness_rejects_inconsistent_extension():
    origin = "log"
    w = LocalWitness("w1", clock=lambda: 1)
    base = _leafset(2)
    _, note2, _ = _checkpoint(origin, 2, base)
    w.cosign(note2, None)
    # A forked larger tree with a bogus (empty) consistency proof must be refused.
    forked = _leafset(4)
    forked[0] = tlog.compute_leaf_hash(tlog.compute_anchor_commit("s", 0, 0, "cd" * 32, "t",
                                                                  "local", "fork"))
    _, note4, _ = _checkpoint(origin, 4, forked)
    with pytest.raises(WitnessError):
        w.cosign(note4, [])


def test_collect_cosignatures_counts_each():
    leaves = _leafset(1)
    origin = "log"
    body, note, _ = _checkpoint(origin, 1, leaves)
    ws = [LocalWitness("w1", clock=lambda: 1_700_000_000),
          LocalWitness("w2", clock=lambda: 1_700_000_000)]
    out, n = collect_cosignatures(ws, note, None, body)
    assert n == 2
    assert out.count("\u2014") == 3  # 1 log sig + 2 cosignatures


def test_collect_skips_failing_witness():
    origin = "log"
    leaves = _leafset(2)
    body, note, _ = _checkpoint(origin, 2, leaves)
    good = LocalWitness("w1", clock=lambda: 1_700_000_000)
    bad = LocalWitness("w2", clock=lambda: 1_700_000_000)
    bad._seen[origin] = (4, "AAAA")  # bad already saw a larger tree -> rollback, skipped
    out, n = collect_cosignatures([good, bad], note, None, body)
    assert n == 1


# ---- WitnessClient HTTP 409 reconciliation ----

class _Resp:
    def __init__(self, status_code, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeHttp:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def post(self, url, content=None, headers=None):
        self.calls.append((url, content))
        return self._resp


def test_witness_client_200_returns_line():
    http = _FakeHttp(_Resp(200, text="\u2014 w1 QUJDRA==\n"))
    wc = WitnessClient("http://w", "ab" * 32, "w1", http=http)
    line = wc.cosign("log", 0, [], "note", current_size=1)
    assert line.startswith("\u2014")


def test_witness_client_409_in_range_returns_none():
    http = _FakeHttp(_Resp(409, headers={"X-Tree-Size": "3"}))

    class _Store:
        def get_tlog_witness_state(self, url, origin):
            return 2  # last cosigned 2; witness now at 3, within [2, current 5]
    wc = WitnessClient("http://w", "ab" * 32, "w1", store=_Store(), http=http)
    assert wc.cosign("log", 0, [], "note", current_size=5) is None


def test_witness_client_409_rollback_raises():
    http = _FakeHttp(_Resp(409, headers={"X-Tree-Size": "1"}))

    class _Store:
        def get_tlog_witness_state(self, url, origin):
            return 4  # we cosigned 4 before; witness now claims 1: state went backwards
    wc = WitnessClient("http://w", "ab" * 32, "w1", store=_Store(), http=http)
    with pytest.raises(WitnessRollbackError):
        wc.cosign("log", 0, [], "note", current_size=5)


def test_witness_client_409_split_view_raises():
    http = _FakeHttp(_Resp(409, headers={"X-Tree-Size": "9"}))

    class _Store:
        def get_tlog_witness_state(self, url, origin):
            return 0
    wc = WitnessClient("http://w", "ab" * 32, "w1", store=_Store(), http=http)
    with pytest.raises(WitnessSplitViewAlert):
        wc.cosign("log", 0, [], "note", current_size=5)  # witness saw 9 > our tree 5


def test_witness_client_422_raises_witness_error():
    wc = WitnessClient("http://w", "ab" * 32, "w1", http=_FakeHttp(_Resp(422)))
    with pytest.raises(WitnessError):
        wc.cosign("log", 0, [], "note", current_size=1)


# ---- end-to-end green path through the server ----

def test_server_with_witness_produces_green_bundle():
    witness = LocalWitness("witness-A", clock=lambda: 1_900_000_000)
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     tlog_witnesses=[witness], tlog_witness_threshold=1)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})

    meta = c.get("/v1/meta").json()
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    from datetime import UTC, datetime
    now = datetime.fromtimestamp(1_900_050_000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    rep = verify_bundle(bundle, tlog_log_key=meta["tlog_pubkey"],
                        witness_pubkeys={"witness-A": witness.public_key_hex()}, now_utc=now)
    codes = {f.code for f in rep.findings}
    assert "tlog_inclusion_witnessed_ok" in codes
    assert rep.ok

    # The public checkpoint endpoint reports it as witnessed.
    r = c.get("/v1/tlog/shared/checkpoint")
    assert r.headers["x-witnessed"] == "true"
    assert int(r.headers["x-witness-count"]) >= 1


def test_witnessed_plan_without_witness_is_pending():
    # A plan with the witnessed entitlement (team) + threshold but no working witness ->
    # checkpoint marked pending. Free, which lacks the entitlement, would stay final.
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     tlog_witness_threshold=1)
    c = TestClient(app)
    acct = c.post("/v1/accounts", json={}).json()
    key = acct["api_key"]
    # Promote the account to a plan that includes the witnessed (green) path.
    app.state.store._db.execute("UPDATE accounts SET plan='team' WHERE account_id=?",
                                (acct["account_id"],))
    app.state.store._db.commit()
    prov = c.post("/v1/streams", json={}, headers={"Authorization": f"Bearer {key}"}).json()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "demo"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    origin = app.state.scheduler.tlog_origin_prefix + "/" + acct["account_id"]
    cp = app.state.store.get_latest_tlog_checkpoint(origin)
    assert cp["status"] == "pending_witness"
    assert cp["witnessed"] == 0


def test_insufficient_witnesses_error_exists():
    # The exception type is importable and is an Exception (used by remote multi-witness paths).
    assert issubclass(InsufficientWitnessesError, Exception)
