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
    checks the receipt against the bundle offline, and a customer who edits or truncates the
    bundle afterwards can no longer make the two agree."""
    import json

    from provenrail.cli import main as cli_main

    service = client()
    h = account(service)
    bundle_path, bundle = _real_bundle(tmp_path)
    leaves = [r["server_record_hash"] for r in bundle["records"]]

    # The CLI imports httpx inside the command, so swapping the module entry points its POST at
    # the in-process test server without touching the command's code.
    class _Httpx:
        HTTPError = Exception

        @staticmethod
        def post(url, json=None, timeout=None, headers=None):
            return service.post("/v1/anchors", json=json, headers=headers)

    monkeypatch.setitem(__import__("sys").modules, "httpx", _Httpx)

    receipt_path = tmp_path / "receipt.json"
    capsys.readouterr()
    assert cli_main(["anchor-push", str(bundle_path), "--url", "http://svc", "--key",
                     h["Authorization"].split()[1], "--receipt-out", str(receipt_path)]) == 0
    out = capsys.readouterr().out
    assert f"anchored {len(leaves)} records" in out
    assert "/v1/anchors/anc_" in out          # the auditor URL is handed to the customer
    for leaf in leaves:
        assert leaf not in out                # and the records are not in what we printed

    # The auditor's check: two files, no network, no account.
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(receipt_path)]) == 0
    assert "RESULT: VERIFIED" in capsys.readouterr().out

    # Dropping the tail is caught, because the receipt records how far it reached.
    truncated = json.loads(bundle_path.read_text(encoding="utf-8"))
    truncated["records"] = truncated["records"][:-2]
    short_path = tmp_path / "truncated.json"
    short_path.write_text(json.dumps(truncated), encoding="utf-8")
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(short_path), str(receipt_path)]) == 1
    assert "records are missing" in capsys.readouterr().out


def test_a_refusal_tells_the_customer_what_actually_happened(tmp_path, capsys, monkeypatch):
    """Each refusal must lead with the service's own sentence and add only advice that fits it.

    Found live, on the day the free anchor shipped: a spent allowance printed "the key rotates
    each billing period, copy the current one", which sends someone to fetch the same key and hit
    the same refusal, and buries the sentence saying the free anchor is gone. It also printed the
    raw `{"error": ...}` envelope, because the hosted service answers `error` and the self-hosted
    sink answers `detail`, and only one of the two was ever read.
    """
    from provenrail.cli import main as cli_main

    bundle_path, _bundle = _real_bundle(tmp_path)

    class _Resp:
        def __init__(self, status, body):
            self.status_code, self._body, self.text = status, body, str(body)

        def json(self):
            return self._body

    def push(status, body):
        class _Httpx:
            HTTPError = Exception

            @staticmethod
            def post(url, json=None, timeout=None, headers=None):
                return _Resp(status, body)

        monkeypatch.setitem(__import__("sys").modules, "httpx", _Httpx)
        capsys.readouterr()
        code = cli_main(["anchor-push", str(bundle_path), "--url", "http://svc", "--key", "k"])
        return code, capsys.readouterr().err

    code, err = push(403, {"error": "your one free anchor has been used. A paid plan anchors "
                                    "without limit: https://provenrail.com/pricing"})
    assert code == 3
    assert "one free anchor has been used" in err
    assert "{" not in err                      # the JSON envelope never reaches the customer
    assert "rotates each billing period" not in err   # nothing to rotate; the allowance is spent

    code, err = push(403, {"error": "this license has expired; renew it to keep anchoring"})
    assert code == 3
    assert "expired" in err
    assert "provenrail.com/account" in err     # here re-copying the key IS the fix

    code, err = push(401, {"error": "invalid API key"})
    assert code == 3
    assert "invalid API key" in err
    assert "pr activate" in err

    # The self-hosted sink words its refusals under `detail`, and must read the same.
    code, err = push(403, {"detail": "hosted anchoring is not included in the free plan"})
    assert "not included in the free plan" in err
    assert "{" not in err


def _real_bundle(tmp_path):
    """A bundle whose chain actually verifies, so anchor-verify's bundle check is exercised
    rather than short-circuited. Built by driving the real sink through the real SDK."""
    import json

    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    from provenrail.server.app import create_app

    c = TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder(endpoint="http://t", write_token=prov["write_token"],
                        stream_id=prov["stream_id"], http=c)
    with fr.session({"agent": "audit-demo"}):
        fr.record_model_call("openai", "gpt-x", {"prompt": "hi"}, {"text": "hello"},
                             usage={"in": "5", "out": "3"})
        fr.record_tool_call("add", {"a": "2", "b": "3"}, "5")
        fr.record_decision("proceed", reason="looks good")
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/export",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path, bundle


def test_a_signature_over_a_different_root_cannot_vouch_for_this_bundle(tmp_path, capsys):
    """The forgery that mattered. The receipt envelope states one root and the signature covers
    another; a first version compared the bundle against the envelope while checking the
    signature against the inner field, so any valid signature over any root passed for any
    bundle. That is the entire product promise, so it gets a test that reproduces the attack."""
    import json

    from provenrail.anchor import LocalAnchor
    from provenrail.cli import main as cli_main

    bundle_path, bundle = _real_bundle(tmp_path)
    leaves = [r["server_record_hash"] for r in bundle["records"]]

    # The attacker holds a genuine signature, just over something else entirely.
    genuine_elsewhere = LocalAnchor().anchor(hashes(3, salt="some other stream"))
    forged = {
        "anchor_id": "anc_forged",
        "merkle_root": merkle_root(leaves),      # what the bundle really hashes to
        "covers_up_to": len(leaves),
        "receipt": {"kind": "local", "merkle_root": genuine_elsewhere.merkle_root,
                    "gen_time": genuine_elsewhere.gen_time,
                    "signature": genuine_elsewhere.signature,
                    "anchor_pubkey": genuine_elsewhere.anchor_pubkey},
    }
    forged_path = tmp_path / "forged.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")

    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(forged_path)]) == 1
    out = capsys.readouterr().out
    assert "the two disagree" in out or "does not describe this bundle" in out


def test_editing_a_record_under_its_hash_is_caught(tmp_path, capsys):
    """The root commits to record hashes, not to record contents. Editing a payload without
    touching its hash left the root unchanged, and the first version of this command reported
    VERIFIED over a doctored bundle. An auditor running only this command got a false green."""
    import json

    from provenrail.cli import main as cli_main

    bundle_path, bundle = _real_bundle(tmp_path)
    leaves = [r["server_record_hash"] for r in bundle["records"]]
    receipt = {"anchor_id": "anc_1", "merkle_root": merkle_root(leaves),
               "covers_up_to": len(leaves),
               "receipt": _receipt_over(merkle_root(leaves))}
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(receipt_path)]) == 0
    assert "RESULT: VERIFIED" in capsys.readouterr().out

    doctored = json.loads(bundle_path.read_text(encoding="utf-8"))
    rec = doctored["records"][2]["record"]
    rec[next(k for k, v in rec.items() if isinstance(v, str))] = "edited after the fact"
    bad = tmp_path / "doctored.json"
    bad.write_text(json.dumps(doctored), encoding="utf-8")

    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bad), str(receipt_path)]) == 1
    assert "the bundle itself does not verify" in capsys.readouterr().out


def _receipt_over(root: str) -> dict:
    from dataclasses import asdict

    from provenrail.anchor import LocalAnchor
    return asdict(LocalAnchor().anchor_root(root))


def test_a_garbage_rfc3161_token_is_not_a_trusted_timestamp(tmp_path, capsys):
    """Presence of a token was accepted as proof of one. It has to be decoded and its imprint
    matched against the root, which is what the verifier has always done for bundles."""
    import json

    from provenrail.cli import main as cli_main

    bundle_path, bundle = _real_bundle(tmp_path)
    leaves = [r["server_record_hash"] for r in bundle["records"]]
    root = merkle_root(leaves)
    receipt = {"anchor_id": "anc_1", "merkle_root": root, "covers_up_to": len(leaves),
               "receipt": {"kind": "rfc3161", "merkle_root": root,
                           "gen_time": "2026-08-18T00:00:00.000000Z",
                           "token_b64": "bm90LWEtdG9rZW4=",   # "not-a-token"
                           "tsa_url": "https://freetsa.org/tsr"}}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(path)]) == 1
    assert "RESULT: THIS RECEIPT DOES NOT COVER THIS BUNDLE" in capsys.readouterr().out


def test_an_identical_retry_returns_the_same_anchor_rather_than_a_second_one():
    """A client with retry logic must not accumulate one anchor per attempt. The same account,
    stream, coverage and root describe one fact, and one fact gets one id."""
    c = client()
    h = account(c)
    body = {"stream_id": "s", "merkle_root": merkle_root(hashes(9)), "covers_up_to": 9}
    first = c.post("/v1/anchors", headers=h, json=body).json()
    for _ in range(4):
        again = c.post("/v1/anchors", headers=h, json=body)
        assert again.status_code == 200
        assert again.json()["anchor_id"] == first["anchor_id"]
    assert len(c.get("/v1/anchors?stream_id=s", headers=h).json()["anchors"]) == 1


def test_an_absurd_coverage_is_refused_before_a_timestamp_is_spent():
    """covers_up_to reached the INSERT unbounded and overflowed SQLite's signed 64-bit integer,
    after a live TSA round-trip had already been spent on the request."""
    c = client()
    h = account(c)
    for bad in (2**63, 2**64, 10**30):
        r = c.post("/v1/anchors", headers=h, json={
            "stream_id": "s", "merkle_root": merkle_root(hashes(2)), "covers_up_to": bad})
        assert r.status_code == 422, f"{bad} was accepted"


def test_a_conflicting_anchor_costs_no_timestamp_and_no_quota():
    """The refusal path must be cheap. Minting a receipt for a request we are about to reject
    burns a shared external resource (the TSA) to say no."""
    c = client()
    h = account(c)
    c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(50)), "covers_up_to": 50})

    calls = []
    real = c.app.state.scheduler.local_anchor.anchor_root

    def counting(root):
        calls.append(root)
        return real(root)

    c.app.state.scheduler.local_anchor.anchor_root = counting
    r = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(10)), "covers_up_to": 10})
    assert r.status_code == 409
    assert calls == [], "a refused anchor still spent a timestamp"


def test_a_browser_gets_a_page_and_a_script_gets_json():
    """The person who follows an anchor link is usually the least technical in the chain. Raw
    JSON hid the two facts that decide what the receipt is worth: whether the time came from an
    independent authority or from our own clock, and that a receipt says nothing about
    completeness. Both were in the payload and invisible in practice."""
    c = client()
    h = account(c)
    anchor_id = c.post("/v1/anchors", headers=h, json={
        "stream_id": "s", "merkle_root": merkle_root(hashes(6)), "covers_up_to": 6,
    }).json()["anchor_id"]

    api = c.get(f"/v1/anchors/{anchor_id}")
    assert api.headers["content-type"].startswith("application/json")
    assert api.json()["merkle_root"] == merkle_root(hashes(6))

    page = c.get(f"/v1/anchors/{anchor_id}", headers={"Accept": "text/html"})
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    body = page.text
    # The limitation must be on the page, not only in the docs.
    assert "That they recorded everything" in body
    assert "No record of this kind can" in body
    # A local anchor must never be described as independently timestamped.
    assert "Self-asserted time" in body
    assert "Independently timestamped" not in body
    # And it must say we never held their records, which is the product's whole shape.
    assert "We never received their records" in body
    # It must disclaim the authority we do not hold. Whitespace-normalised because the source
    # wraps, and a test that depends on where a line breaks is a test that fails on reflow.
    flat = " ".join(body.split())
    for disclaimed in ("not legal advice, a compliance guarantee, or an audit opinion",):
        assert disclaimed in flat

    missing = c.get("/v1/anchors/anc_nope", headers={"Accept": "text/html"})
    assert missing.status_code == 404
    assert "not evidence of anything" in missing.text


def test_an_rfc3161_anchor_page_says_the_time_is_independent():
    """The inverse of the test above: when the time really is third-party signed, the page must
    say so, or the honest disclosure becomes noise the reader learns to skip."""
    from provenrail.server.app import _render_anchor_page
    page = _render_anchor_page({
        "anchor_id": "anc_x", "merkle_root": "ab" * 32, "covers_up_to": 4,
        "receipt": {"kind": "rfc3161", "merkle_root": "ab" * 32,
                    "gen_time": "2026-08-18T00:00:00Z", "tsa_url": "https://freetsa.org/tsr"},
        "created_at": "2026-08-18T00:00:00Z"})
    assert "Independently timestamped" in page
    assert "freetsa.org" in page
    assert "Self-asserted time" not in page
