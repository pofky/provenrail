import copy
import json
import types

import pytest
from fastapi.testclient import TestClient

from provenrail import cli
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.integrations import instrument_anthropic, instrument_openai
from provenrail.reports import generate_attestation, render_markdown
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _session(http, prov, pin_path=None):
    return FlightRecorder("http://t", prov["write_token"], prov["stream_id"],
                          http=http, pin_path=pin_path)


def _run(anchor=None):
    app = create_app(":memory:", anchor=anchor or LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    return app, c, prov


def _export(c, prov):
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


# ---- head pinning / truncation defense ----

def test_pin_confirms_full_history(tmp_path):
    _, c, prov = _run()
    pin_file = tmp_path / "pin.json"
    fr = _session(c, prov, pin_path=str(pin_file))
    with fr.session():
        fr.record_decision("a")
        fr.record_decision("b")
    pin = json.loads(pin_file.read_text())
    bundle = _export(c, prov)
    rep = verify_bundle(bundle, pin=pin)
    assert rep.ok
    assert any(f.code == "pin_ok" for f in rep.findings)


def test_pin_detects_tail_truncation(tmp_path):
    _, c, prov = _run()
    pin_file = tmp_path / "pin.json"
    fr = _session(c, prov, pin_path=str(pin_file))
    with fr.session():
        fr.record_decision("a")
        fr.record_decision("b")
    pin = json.loads(pin_file.read_text())
    bundle = _export(c, prov)
    truncated = copy.deepcopy(bundle)
    truncated["records"] = truncated["records"][:2]  # malicious sink drops the tail
    rep = verify_bundle(truncated, pin=pin)
    assert not rep.ok
    assert any(f.code == "pin_truncated" for f in rep.findings)


def test_sink_reorder_raises_at_client():
    # if the sink returns a receipt that does not link to the last head, the SDK refuses
    _, c, prov = _run()
    fr = _session(c, prov)
    fr.start()
    # corrupt the client's view of the head, simulating a forking sink response
    fr.head["server_record_hash"] = "deadbeef"
    import pytest

    from provenrail.sdk import SinkIntegrityError
    with pytest.raises(SinkIntegrityError):
        fr.record_decision("x")


def test_stream_reuse_across_processes():
    # the quickstart config pins one stream; a second recorder (a "new process") must
    # adopt the sink's existing head instead of refusing, then verify end to end
    import pytest

    from provenrail.keys import SigningKey
    from provenrail.sdk import SinkIntegrityError
    _, c, prov = _run()
    key = SigningKey.generate()  # the persistent device key easy.make_recorder maintains

    def _fr():
        return FlightRecorder("http://t", prov["write_token"], prov["stream_id"],
                              http=c, key=key)

    for note in ("first run", "second run", "third run"):
        fr = _fr()  # fresh recorder each time, same stream: head starts at genesis
        with fr.session():
            fr.record_decision(note)
        fr.close()
    bundle = _export(c, prov)
    rep = verify_bundle(bundle)
    assert rep.ok
    # continuity is still strict after the first receipt of a process
    fr4 = _fr()
    fr4.start()
    fr4.head["server_record_hash"] = "deadbeef"
    with pytest.raises(SinkIntegrityError):
        fr4.record_decision("x")


def test_easy_flow_reruns_share_device_key(tmp_path, monkeypatch):
    # the actual quickstart journey: config pins a stream, the user runs their agent
    # three times, and the exported stream still verifies as one untampered history
    from provenrail import easy
    _, c, prov = _run()
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".provenrail.json").write_text(json.dumps({
        "endpoint": "http://t", "write_token": prov["write_token"],
        "stream_id": prov["stream_id"]}), encoding="utf-8")
    monkeypatch.setattr(easy, "_GLOBAL", {})
    for note in ("run one", "run two", "run three"):
        with easy.record("rerun-agent", http=c) as rec:
            rec.record_decision(note)
    assert (tmp_path / ".provenrail.key").is_file()
    bundle = _export(c, prov)
    rep = verify_bundle(bundle)
    assert rep.ok, [f.detail for f in rep.findings if f.severity == "fail"]


# ---- drop-in integrations ----

def _fake_response():
    return types.SimpleNamespace(
        usage=types.SimpleNamespace(input_tokens=12, output_tokens=5),
        choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="hi"))],
        content=[types.SimpleNamespace(text="hi")],
    )


def test_instrument_openai_captures():
    _, c, prov = _run()
    fr = _session(c, prov)
    resp = _fake_response()
    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=lambda **kw: resp)))
    instrument_openai(client, fr)
    with fr.session():
        out = client.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": "hi"}])
    assert out is resp
    bundle = _export(c, prov)
    kinds = [r["record"]["action_type"] for r in bundle["records"]]
    assert "model_call" in kinds
    mc = next(r["record"] for r in bundle["records"] if r["record"]["action_type"] == "model_call")
    assert mc["payload"]["provider"] == "openai" and mc["payload"]["model"] == "gpt-x"


def test_instrument_anthropic_captures():
    _, c, prov = _run()
    fr = _session(c, prov)
    resp = _fake_response()
    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **kw: resp))
    instrument_anthropic(client, fr)
    with fr.session():
        client.messages.create(model="claude-x", messages=[{"role": "user", "content": "hi"}])
    bundle = _export(c, prov)
    mc = next(r["record"] for r in bundle["records"] if r["record"]["action_type"] == "model_call")
    assert mc["payload"]["provider"] == "anthropic"


def test_instrument_is_idempotent():
    # A bare object() used to be accepted here, which is exactly the mistake the published
    # example made: instrumentation succeeded and nothing was ever recorded. The stub now has
    # the one method a recorder must have.
    fr = types.SimpleNamespace(record_model_call=lambda *a, **k: None)
    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **kw: None))
    instrument_anthropic(client, fr)
    first = client.messages.create
    instrument_anthropic(client, fr)
    assert client.messages.create is first  # not double-wrapped


def test_instrumenting_with_something_that_cannot_record_fails_loudly():
    """The bug a published example shipped: passing the provenrail module instead of the
    recorder. Every model call then succeeded and none were recorded, so the operator believed
    they had an audit trail and had none. It must fail where the mistake is made."""
    import provenrail

    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **kw: None))
    with pytest.raises(TypeError, match="cannot record"):
        instrument_anthropic(client, provenrail)


def test_a_capture_failure_is_never_silent(caplog):
    """Capture must not break the agent's call path, but it must not be quiet about failing
    either. Silence here is indistinguishable from working."""
    import logging

    from provenrail.integrations import _common

    class Broken:
        def record_model_call(self, *a, **k):
            raise RuntimeError("sink exploded")

    _common._warned.clear()
    with caplog.at_level(logging.WARNING):
        _common._capture(Broken(), "anthropic", "messages", {"model": "m"}, {"ok": True})
    assert "was NOT recorded" in caplog.text
    assert "sink exploded" in caplog.text


# ---- attestation reports ----

def test_eu_ai_act_attestation():
    _, c, prov = _run()
    fr = _session(c, prov)
    with fr.session():
        fr.record_model_call("anthropic", "claude", "q", "a")
        fr.record_data_access("patient_db", "read")
        fr.record_human_oversight("approved")
    att = generate_attestation(_export(c, prov), regime="eu-ai-act")
    assert att["integrity"]["verified"]
    assert att["regime"] == "eu-ai-act"
    assert "NOT a certification" in att["disclaimer"]
    # No RFC 3161 anchor in this in-memory run: time must be flagged as self-asserted,
    # never reported as a satisfied requirement.
    assert att["integrity"]["independently_timed"] is False
    assert "self-asserted" in att["evidence_strength"]
    statuses = [m["status"] for m in att["regime_mapping"]]
    assert "evidence present" in statuses
    assert any(s.startswith("gap:") for s in statuses)  # integrity-time gap
    md = render_markdown(att)
    assert "Art. 12" in md and "Completeness caveat" in md
    assert "Independently timed: NO" in md
    assert "WARNING: no trusted timestamp" in md


def test_hipaa_attestation_flags_missing_phi_access():
    _, c, prov = _run()
    fr = _session(c, prov)
    with fr.session():
        fr.record_decision("no phi touched")
    att = generate_attestation(_export(c, prov), regime="hipaa")
    statuses = {m["requirement"][:20]: m["status"] for m in att["regime_mapping"]}
    # no data_access event -> that requirement has no captured evidence
    assert any("no evidence" in s for s in statuses.values())


def test_attestation_reports_tampering():
    _, c, prov = _run()
    fr = _session(c, prov)
    with fr.session():
        fr.record_decision("a")
    bundle = _export(c, prov)
    bundle["records"][1]["record"]["payload"]["summary"] = "edited"
    att = generate_attestation(bundle, regime="generic")
    assert att["integrity"]["verified"] is False
    # Tampering must surface as a FAILED control, not a green status.
    assert any(m["status"].startswith("FAILED") for m in att["regime_mapping"])
    assert "INTEGRITY CHECK FAILED" in att["evidence_strength"]


# ---- CLI ----

def test_cli_demo_verify_report(tmp_path, capsys):
    out = tmp_path / "bundle.json"
    pin = tmp_path / "pin.json"
    assert cli.main(["demo", "--out", str(out), "--pin", str(pin)]) == 0
    assert out.exists() and pin.exists()
    assert cli.main(["verify", str(out), "--pin", str(pin)]) == 0
    assert cli.main(["report", "--regime", "eu-ai-act", str(out), "--md"]) == 0


def test_bare_pr_is_friendly_not_an_error(capsys):
    """`pr` with no command must greet a new user and exit 0, not print an argparse error."""
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "pr demo" in out and "error:" not in out.lower()


def test_demo_output_leads_with_verify_and_drops_dead_share_link(tmp_path, capsys):
    """The demo's primary next step is a plain `pr verify <bundle>`, and it must not print a
    /share token: the demo's in-process sink is gone, so that link would 404."""
    out = tmp_path / "bundle.json"
    assert cli.main(["demo", "--out", str(out), "--pin", str(tmp_path / "pin.json")]) == 0
    shown = capsys.readouterr().out
    assert f"pr verify {out}" in shown
    assert "/share/" not in shown


def test_verify_content_proves_held_transcript(tmp_path, capsys):
    """The store-hash-not-content default is only valuable if a recipient can prove a transcript
    they hold matches the recorded fingerprint. verify-content must MATCH the real content and
    reject altered content."""
    from provenrail.canonical import hash_value
    response = {"text": "Three key risks: A, B, C."}
    bundle = {"format": "flightrecorder.bundle/1", "records": [
        {"record": {"seq": 1, "action_type": "model_call",
                    "payload": {"response": {"hash": hash_value(response)}}}}]}
    bp = tmp_path / "b.json"
    bp.write_text(json.dumps(bundle), encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text(json.dumps(response), encoding="utf-8")
    assert cli.main(["verify-content", str(bp), "--file", str(good)]) == 0
    assert "MATCH" in capsys.readouterr().out

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"text": "Three key risks: A, B, D."}), encoding="utf-8")
    assert cli.main(["verify-content", str(bp), "--file", str(bad)]) == 1
    assert "NO MATCH" in capsys.readouterr().out


def test_verify_empty_bundle_is_no_records_not_tampered():
    """An empty bundle (nothing recorded) must not read as tampering."""
    from provenrail.verifier.verify import verify_bundle
    rep = verify_bundle({"format": "flightrecorder.bundle/1", "records": []})
    assert rep.result == "empty"
    assert not rep.ok


def test_verify_prints_advisory_footer_when_warnings(tmp_path, capsys):
    """A clean free-tier verify ends with a line clarifying the warn/info lines are not
    failures, so a beginner is not scared by them."""
    out = tmp_path / "bundle.json"
    cli.main(["demo", "--out", str(out), "--pin", str(tmp_path / "pin.json")])
    capsys.readouterr()
    assert cli.main(["verify", str(out)]) == 0
    shown = capsys.readouterr().out
    assert "advisory context, not failures" in shown


def test_cli_malformed_bundle_is_friendly(tmp_path, capsys):
    """The /start guide tells beginners to hand-edit a bundle; a stray character makes it
    invalid JSON. That must give a clear message and exit 2, not a raw Python traceback."""
    out = tmp_path / "bundle.json"
    assert cli.main(["demo", "--out", str(out)]) == 0
    out.write_text(out.read_text(encoding="utf-8")[:-3], encoding="utf-8")  # break the JSON
    assert cli.main(["verify", str(out)]) == 2
    err = capsys.readouterr().err
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_cli_missing_bundle_is_friendly(tmp_path, capsys):
    assert cli.main(["verify", str(tmp_path / "nope.json")]) == 2
    err = capsys.readouterr().err
    assert "file not found" in err
    assert "Traceback" not in err


def test_verify_non_object_json_is_malformed_not_tampered():
    """Valid JSON that is not even an object (a list/string) must not crash the verifier and
    must not be reported as tampering: it is simply not a Provenrail bundle."""
    from provenrail.verifier.verify import verify_bundle
    for value in ([1, 2, 3], "hello", 42):
        rep = verify_bundle(value)
        assert not rep.ok
        assert rep.result == "malformed"
        assert "not_a_bundle" in {f.code for f in rep.findings}


def test_verify_wrong_shape_object_is_malformed():
    from provenrail.verifier.verify import verify_bundle
    rep = verify_bundle({})
    assert rep.result == "malformed"
    assert "bad_format" in {f.code for f in rep.findings}


# ---- proof page ----

def test_proof_page_shows_verified_badge():
    _, c, prov = _run()
    fr = _session(c, prov)
    with fr.session():
        fr.record_decision("ship")
    _export(c, prov)
    r = c.get(f"/share/{prov['share_token']}")
    assert r.status_code == 200
    assert "Integrity verified" in r.text
    assert "pr verify" in r.text


# ---- more than one agent writing the same stream ----

def test_two_agents_on_one_stream_do_not_report_tampering():
    """One project with two agents running at once is an ordinary setup, and it used to fail.

    Each client keeps the receipt head the sink last issued it and expects the next receipt to
    link to exactly that. The moment a second writer appends, the assumption is false through no
    fault of the sink. Measured against a real 0.2.28 server: eight streams with three agents
    each raised SinkIntegrityError on 13,136 of 13,470 records, so a correct deployment reported
    tampering on essentially everything it wrote.

    The client now asks the sink for the links it missed and walks them, so continuity is proven
    across the gap rather than assumed adjacent.
    """
    import concurrent.futures as cf

    from provenrail.keys import SigningKey
    _, c, prov = _run()
    agents = [FlightRecorder("http://t", prov["write_token"], prov["stream_id"],
                             http=c, key=SigningKey.generate()) for _ in range(3)]

    def work(a):
        with a.session({"agent": id(a)}):
            for i in range(10):
                a.record_decision(f"step {i}")
        return True

    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        assert all(ex.map(work, agents))  # no SinkIntegrityError from any of them

    bundle = _export(c, prov)
    assert len(bundle["records"]) >= 30
    assert verify_bundle(bundle).ok, "a stream written by three agents must still verify"


def test_closing_a_gap_still_catches_a_sink_that_does_not_join_up():
    """The gap walk must not become a way to wave through any receipt at all.

    A sink that reorders, forks or rolls back cannot produce a run of receipts leading from the
    head it issued us to the record it now claims, so the walk has to fail. This forces exactly
    that: the sink answers the gap query with a segment that does not link.
    """
    import pytest

    from provenrail.sdk import SinkIntegrityError
    _, c, prov = _run()
    fr = _session(c, prov)
    fr.start()
    fr.record_decision("real")

    # The sink now lies about the part of the chain the client did not write.
    fr.client.receipts_after = lambda *a, **k: [
        {"recv_seq": 99, "server_prev_hash": "00" * 32, "server_record_hash": "11" * 32}]
    fr.head["server_record_hash"] = "de" * 32  # our head is no longer what the sink will claim
    with pytest.raises(SinkIntegrityError):
        fr.record_decision("x")

    # And a sink that refuses to show the gap at all is not given the benefit of the doubt.
    def _refuse(*a, **k):
        raise RuntimeError("nope")
    fr.client.receipts_after = _refuse
    fr.head["server_record_hash"] = "ad" * 32
    with pytest.raises(SinkIntegrityError):
        fr.record_decision("y")


def test_the_gap_query_returns_links_only_and_needs_a_write_token():
    """The endpoint answers "does your chain join up", not "what did the other agent record".

    It is reachable with a write token, because the holder can already append here. It must not
    hand back record bodies, or a write token would quietly become a read token.
    """
    _, c, prov = _run()
    fr = _session(c, prov)
    with fr.session({"agent": "a"}):
        fr.record_decision("secret payload marker")

    r = c.get(f"/v1/streams/{prov['stream_id']}/receipts",
              params={"after_seq": -1},
              headers={"Authorization": f"Bearer {prov['write_token']}"})
    assert r.status_code == 200
    receipts = r.json()["receipts"]
    assert receipts and receipts[0]["recv_seq"] == 0
    assert set(receipts[0]) == {"recv_seq", "recv_ts", "server_prev_hash", "server_record_hash"}
    assert "secret payload marker" not in r.text

    # The chain it returns is the real one: each link points at the one before it.
    prev = receipts[0]["server_prev_hash"]
    for link in receipts:
        assert link["server_prev_hash"] == prev
        prev = link["server_record_hash"]

    # No token, and a read token, are both refused: this is a writer's continuity check.
    assert c.get(f"/v1/streams/{prov['stream_id']}/receipts").status_code == 401
    assert c.get(f"/v1/streams/{prov['stream_id']}/receipts",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).status_code == 403
