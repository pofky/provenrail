"""The anchor-only trust service: independence sold without ever receiving the data.

A customer self-hosts the AGPL sink, keeps every record, and sends nothing but a Merkle root over
their own record hashes. Provenrail timestamps that root, keeps an append-only history of it, and
will attest to it for a third party who has no account.

Two properties carry the whole design and both are tested here. The endpoint must be structurally
incapable of receiving a record, because that is what keeps the operator out of GDPR processor
territory. And coverage must never go backwards, because an anchor history that can shrink is a
log, not evidence.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor, merkle_root
from provenrail.keys import verify_signature
from provenrail.server.app import create_app


def client(**kw) -> TestClient:
    return TestClient(create_app(":memory:", **kw))


def account(c: TestClient) -> dict[str, str]:
    key = c.post("/v1/accounts", json={"label": "self-hoster"}).json()["api_key"]
    return {"Authorization": f"Bearer {key}"}


def hashes(n: int, salt: str = "") -> list[str]:
    import hashlib
    return [hashlib.sha256(f"{salt}record-{i}".encode()).hexdigest() for i in range(n)]


def test_an_anchor_carries_a_root_and_nothing_else():
    """The schema is the privacy guarantee. Anything a caller adds beyond the three declared
    fields must be dropped, so a customer cannot accidentally send us their agent's output and
    make us a processor by mistake."""
    c = client()
    h = account(c)
    root = merkle_root(hashes(8))
    r = c.post("/v1/anchors", headers=h, json={
        "stream_id": "billing-agent", "merkle_root": root, "covers_up_to": 8,
        "prompt": "the customer's actual secret prompt",
        "records": [{"content": "personal data that must never land here"}],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["merkle_root"] == root
    assert body["covers_up_to"] == 8
    assert body["anchor_id"].startswith("anc_")
    serialized = r.text
    assert "secret prompt" not in serialized
    assert "personal data" not in serialized

    # And it is not merely absent from the response: it never reached storage.
    stored = c.get(f"/v1/anchors/{body['anchor_id']}").json()
    assert "prompt" not in stored and "records" not in stored
    assert set(stored) == {"anchor_id", "stream_id", "merkle_root", "covers_up_to",
                           "receipt", "created_at"}


def test_coverage_cannot_go_backwards():
    """Anchor 1000 records, have something go wrong at 400, then try to re-anchor the shorter
    chain as though the tail never existed. Accepting that would put our signature on a rewritten
    history, which is the exact failure the product exists to prevent."""
    c = client()
    h = account(c)
    full = hashes(1000)
    assert c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(full), "covers_up_to": 1000,
    }).status_code == 200

    r = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(full[:400]), "covers_up_to": 400,
    })
    assert r.status_code == 409
    assert "drop the tail" in r.json()["detail"]

    # Growing forward is exactly what should happen, and it still works after the refusal.
    assert c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(1200)), "covers_up_to": 1200,
    }).status_code == 200


def test_the_same_prefix_cannot_have_two_histories():
    """Same coverage, different root, is a fork. One of the two is a rewrite, and we cannot know
    which, so we refuse to be the party that signed both."""
    c = client()
    h = account(c)
    c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(10)), "covers_up_to": 10})
    r = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(10, salt="other")),
        "covers_up_to": 10})
    assert r.status_code == 409
    assert "two histories" in r.json()["detail"]


def test_streams_are_independent():
    """Coverage is per stream. A customer running twenty agents must not have one agent's
    progress block another's."""
    c = client()
    h = account(c)
    c.post("/v1/anchors", headers=h, json={
        "stream_id": "a", "merkle_root": merkle_root(hashes(500)), "covers_up_to": 500})
    assert c.post("/v1/anchors", headers=h, json={
        "stream_id": "b", "merkle_root": merkle_root(hashes(3)), "covers_up_to": 3,
    }).status_code == 200


def test_a_malformed_root_is_refused_before_it_is_timestamped():
    """Timestamping a bad root would mint a receipt that can never match any bundle: an
    receipt that looks real and proves nothing. Refuse instead."""
    c = client()
    h = account(c)
    for bad in ("", "not-hex", "ab" * 16, "zz" * 32, "AB" * 33):
        r = c.post("/v1/anchors", headers=h,
                   json={"stream_id": "s", "merkle_root": bad, "covers_up_to": 1})
        assert r.status_code == 422, f"{bad!r} was accepted"


def test_coverage_must_be_a_real_count():
    c = client()
    h = account(c)
    for bad in (0, -1):
        r = c.post("/v1/anchors", headers=h, json={
            "stream_id": "s", "merkle_root": merkle_root(hashes(4)), "covers_up_to": bad})
        assert r.status_code == 422


def test_anchoring_requires_a_key_but_reading_an_receipt_does_not():
    """The asymmetry is the product. Writing is a paid account action; reading is what an auditor
    does with nothing but the id the customer gave them."""
    c = client()
    assert c.post("/v1/anchors", json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(2)), "covers_up_to": 2,
    }).status_code == 401

    h = account(c)
    anchor_id = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(2)), "covers_up_to": 2,
    }).json()["anchor_id"]

    public = c.get(f"/v1/anchors/{anchor_id}")   # no Authorization header at all
    assert public.status_code == 200
    assert public.json()["merkle_root"] == merkle_root(hashes(2))
    assert c.get("/v1/anchors/anc_does_not_exist").status_code == 404


def test_a_public_receipt_never_names_the_account_that_bought_it():
    """The auditor holds an id, not a relationship. Leaking the account id would turn a receipt
    into a customer list."""
    c = client()
    h = account(c)
    acct_id = c.get("/v1/streams", headers=h)  # forces account resolution; ignore body
    assert acct_id.status_code == 200
    anchor_id = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(2)), "covers_up_to": 2,
    }).json()["anchor_id"]
    assert "account" not in c.get(f"/v1/anchors/{anchor_id}").text


def test_one_account_cannot_list_another_accounts_anchors():
    c = client()
    a, b = account(c), account(c)
    c.post("/v1/anchors", headers=a, json={
        "stream_id": "mine", "merkle_root": merkle_root(hashes(5)), "covers_up_to": 5})
    assert c.get("/v1/anchors", headers=b).json()["anchors"] == []
    mine = c.get("/v1/anchors", headers=a).json()["anchors"]
    assert len(mine) == 1 and mine[0]["stream_id"] == "mine"


def test_the_history_reads_back_in_coverage_order():
    c = client()
    h = account(c)
    for n in (10, 40, 90):
        c.post("/v1/anchors", headers=h, json={
            "stream_id": "s", "merkle_root": merkle_root(hashes(n)), "covers_up_to": n})
    got = c.get("/v1/anchors?stream_id=s", headers=h).json()["anchors"]
    assert [a["covers_up_to"] for a in got] == [10, 40, 90]


def test_the_receipt_verifies_against_the_customers_own_records():
    """The end-to-end claim: a stranger holding the receipt and the customer's bundle can
    confirm the two describe the same history, without trusting either party."""
    c = client()
    h = account(c)
    leaves = hashes(64)
    anchor_id = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(leaves), "covers_up_to": len(leaves),
    }).json()["anchor_id"]

    receipt = c.get(f"/v1/anchors/{anchor_id}").json()
    # The auditor recomputes the root from the records the customer showed them.
    assert merkle_root(leaves) == receipt["merkle_root"]
    assert receipt["covers_up_to"] == len(leaves)
    # And a customer who quietly deletes the last record can no longer match the receipt.
    assert merkle_root(leaves[:-1]) != receipt["merkle_root"]


def test_a_local_receipt_is_signed_by_a_key_the_customer_can_check():
    c = client()
    h = account(c)
    root = merkle_root(hashes(7))
    receipt = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": root, "covers_up_to": 7,
    }).json()["receipt"]
    assert receipt["merkle_root"] == root
    if receipt["kind"] == "local":
        assert verify_signature(receipt["anchor_pubkey"],
                                (root + "|" + receipt["gen_time"]).encode("utf-8"),
                                receipt["signature"])


def test_anchor_root_and_anchor_agree():
    """`anchor_root` exists so a root computed elsewhere can be timestamped. It must produce the
    same commitment as handing the same leaves to `anchor`, or the two halves of the product
    would drift apart."""
    a = LocalAnchor()
    leaves = hashes(33)
    assert a.anchor(leaves).merkle_root == a.anchor_root(merkle_root(leaves)).merkle_root


def test_the_anchor_only_path_stores_no_records():
    """The structural claim, checked against the database rather than the API: after anchoring,
    the records table is empty. There is no code path from this endpoint to a stored record."""
    from provenrail.server import storage as storage_mod
    store = storage_mod.Storage(":memory:")
    store.append_external_anchor(
        anchor_id="anc_1", account_id="acct_1", stream_id="s",
        merkle_root=merkle_root(hashes(4)), covers_up_to=4,
        receipt={"kind": "local", "merkle_root": "x", "gen_time": "t"},
        created_at="2026-08-18T00:00:00.000000Z")
    assert store.get_records("s") == []
    assert store.count_external_anchors("acct_1") == 1


def test_the_whole_path_end_to_end_through_the_cli(tmp_path, capsys, monkeypatch):
    """The customer's real journey: they hold a bundle, they push only its root, an auditor
    checks the receipt against the bundle offline, and a customer who edits a record after
    the fact can no longer make the two agree."""
    import json

    from provenrail.cli import main as cli_main

    service = client()
    h = account(service)

    # A self-hoster's exported bundle. Only server_record_hash is load-bearing here.
    leaves = hashes(12)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({
        "format": "provenrail/1", "stream_id": "invoice-agent",
        "records": [{"recv_seq": i, "server_record_hash": leaf}
                    for i, leaf in enumerate(leaves)],
        "anchors": [],
    }), encoding="utf-8")

    # The CLI imports httpx inside the command, so swapping the module entry points its POST at
    # the in-process test server without touching the command's code.
    class _Httpx:
        HTTPError = Exception

        @staticmethod
        def post(url, json=None, timeout=None, headers=None):
            return service.post("/v1/anchors", json=json, headers=headers)

    monkeypatch.setitem(__import__("sys").modules, "httpx", _Httpx)

    att_path = tmp_path / "receipt.json"
    capsys.readouterr()
    assert cli_main(["anchor-push", str(bundle_path), "--url", "http://svc", "--key",
                     h["Authorization"].split()[1], "--receipt-out", str(att_path)]) == 0
    out = capsys.readouterr().out
    assert "anchored 12 records" in out
    assert "/v1/anchors/anc_" in out          # the auditor URL is handed to the customer
    for leaf in leaves:
        assert leaf not in out                # and the records are not in what we printed

    # The auditor's check: two files, no network, no account.
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(att_path)]) == 0
    assert "RESULT: VERIFIED" in capsys.readouterr().out

    # Now the customer quietly rewrites history and tries again.
    doctored = json.loads(bundle_path.read_text(encoding="utf-8"))
    doctored["records"][7]["server_record_hash"] = hashes(1, salt="forged")[0]
    forged_path = tmp_path / "doctored.json"
    forged_path.write_text(json.dumps(doctored), encoding="utf-8")
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(forged_path), str(att_path)]) == 1
    assert "does not describe this bundle" in capsys.readouterr().out

    # And dropping the tail is caught too, because the receipt says how far it reached.
    truncated = json.loads(bundle_path.read_text(encoding="utf-8"))
    truncated["records"] = truncated["records"][:9]
    short_path = tmp_path / "truncated.json"
    short_path.write_text(json.dumps(truncated), encoding="utf-8")
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(short_path), str(att_path)]) == 1
    assert "records are missing" in capsys.readouterr().out
