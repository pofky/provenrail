
import io
import pathlib

import pytest
from fastapi.testclient import TestClient

from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def client(**caps):
    caps.setdefault("require_account", False)
    return TestClient(create_app(":memory:", **caps))


def provision(c):
    return c.post("/v1/streams", json={}).json()


def rec(stream_id, seq, extra=""):
    return {"stream_id": stream_id, "seq": seq, "action_type": "tool_call",
            "record_hash": f"h{seq}{extra}", "ts_utc": "2026-06-08T00:00:00.0Z", "pad": extra}


def hdr(p):
    return {"Authorization": f"Bearer {p['write_token']}"}


def test_batch_cap_enforced():
    c = client(max_batch=2)
    p = provision(c)
    r = c.post("/v1/ingest", json={"records": [rec(p["stream_id"], i) for i in range(3)]}, headers=hdr(p))
    assert r.status_code == 413


def test_record_size_cap_enforced():
    c = client(max_record_bytes=200)
    p = provision(c)
    big = rec(p["stream_id"], 0, extra="x" * 500)
    r = c.post("/v1/ingest", json={"records": [big]}, headers=hdr(p))
    assert r.status_code == 413


def test_missing_required_fields_rejected():
    c = client()
    p = provision(c)
    bad = {"stream_id": p["stream_id"], "action_type": "x"}  # no record_hash / seq
    r = c.post("/v1/ingest", json={"records": [bad]}, headers=hdr(p))
    assert r.status_code == 422


def test_idempotent_dedupe():
    c = client()
    p = provision(c)
    one = rec(p["stream_id"], 0)
    c.post("/v1/ingest", json={"records": [one]}, headers=hdr(p))
    r2 = c.post("/v1/ingest", json={"records": [one]}, headers=hdr(p))
    assert r2.json()["receipts"][0].get("duplicate") is True
    exp = c.get(f"/v1/streams/{p['stream_id']}/export",
                headers={"Authorization": f"Bearer {p['read_token']}"}).json()
    assert len(exp["records"]) == 1  # not duplicated


def test_stream_record_cap():
    c = client(max_records_per_stream=2)
    p = provision(c)
    c.post("/v1/ingest", json={"records": [rec(p["stream_id"], 0), rec(p["stream_id"], 1)]}, headers=hdr(p))
    r = c.post("/v1/ingest", json={"records": [rec(p["stream_id"], 2)]}, headers=hdr(p))
    assert r.status_code == 429


def test_local_only_anchor_warns_but_passes():
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    exp = c.get(f"/v1/streams/{prov['stream_id']}/export",
                headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    rep = verify_bundle(exp)
    assert rep.ok
    assert any(f.code == "local_anchor_only" for f in rep.findings)


def test_share_badge_amber_for_local_anchor_only():
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    r = c.get(f"/share/{prov['share_token']}")
    assert r.status_code == 200
    # integrity is real but there is no third-party timestamp: amber, not green
    assert "badge amber" in r.text
    assert "no trusted timestamp" in r.text
    assert "Integrity verified</span>" not in r.text


def test_anchor_rate_limit_enforced():
    from provenrail.ingest_client import provision_stream
    from provenrail.sdk import FlightRecorder
    app = create_app(":memory:", require_account=False, anchor_per_min=1)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_decision("x")
    h = {"Authorization": f"Bearer {prov['read_token']}"}
    first = c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=h)
    second = c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=h)
    assert first.status_code == 200
    assert second.status_code == 429


def test_an_uncanonicalizable_record_is_refused_not_a_crash():
    """A float or an out-of-JS-range integer anywhere in a record means the record can never be
    hashed, so it can never be verified. It reached the client as a 500, which reads as "our
    fault, retry", for a record that will never be accepted no matter how often it is sent."""
    from provenrail.anchor import LocalAnchor
    from provenrail.ingest_client import provision_stream
    from provenrail.server.app import create_app

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    h = {"Authorization": f"Bearer {prov['write_token']}"}
    base = {"stream_id": prov["stream_id"], "record_hash": "bb" * 32, "seq": 0,
            "action_type": "model_call", "ts_utc": "2026-01-01T00:00:00Z"}
    for bad in ({**base, "seq": 0, "payload": {"cost": 1.5}},
                {**base, "seq": 1, "payload": {"tokens": 9007199254740992}},
                {**base, "seq": 2, "payload": {"nested": {"deep": [1, 2.25]}}}):
        r = c.post("/v1/ingest", json={"records": [bad]}, headers=h)
        assert r.status_code == 422, (r.status_code, r.text)
        assert "canonicaliz" in r.text


def test_rotating_with_the_wrong_old_key_changes_nothing():
    """A rotation is what someone does the hour they think a key was stolen, and the only
    question that matters is whether the old key is dead. It used to revoke nothing, add the new
    key anyway, and answer 200: the compromised key stayed active and a second live key
    appeared."""
    from provenrail.anchor import LocalAnchor
    from provenrail.server.app import create_app

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret="s")
    c = TestClient(app)
    key = c.post("/v1/accounts", json={}).json()["api_key"]
    h = {"Authorization": f"Bearer {key}"}
    real, other, new = "aa" * 32, "bb" * 32, "cc" * 32
    assert c.post("/v1/agents", json={"agent_id": "a", "pubkey": real}, headers=h).status_code == 200

    r = c.post("/v1/agents/a/rotate", json={"old_pubkey": other, "new_pubkey": new}, headers=h)
    assert r.status_code == 404, r.text
    keys = c.get("/v1/agents", headers=h).json()["agents"]
    assert [(k["pubkey"], k["status"]) for k in keys] == [(real, "active")], (
        "a failed rotation must add nothing and revoke nothing")

    ok = c.post("/v1/agents/a/rotate", json={"old_pubkey": real, "new_pubkey": new}, headers=h)
    assert ok.status_code == 200
    after = {k["pubkey"]: k["status"] for k in c.get("/v1/agents", headers=h).json()["agents"]}
    assert after == {real: "revoked", new: "active"}


def test_a_binary_file_gets_a_sentence_not_a_decoder_traceback(tmp_path, capsys):
    """Pointing the verifier at a PDF, a zip, or a half-finished download is the same class of
    mistake as pointing it at broken JSON. It used to surface as a raw UnicodeDecodeError
    traceback out of the file read, which tells the user about our internals rather than their
    problem, and makes a working tool look broken."""
    from provenrail.cli import main as cli_main
    from provenrail.verifier.verify import main as verify_main

    binary = tmp_path / "not-a-bundle.pdf"
    binary.write_bytes(b"%PDF-1.7\n\xff\xfe\x00\x01 binary payload")

    for run in (lambda: verify_main([str(binary)]),          # the `pr-verify` console script
                lambda: cli_main(["verify", str(binary)])):  # and the `pr verify` subcommand
        capsys.readouterr()
        assert run() == 2
        out = capsys.readouterr()
        assert "Traceback" not in out.out + out.err
        assert "UnicodeDecodeError" not in out.out + out.err
        assert "not valid UTF-8" in out.err
        # A caller reading stdout for a verdict must never get silence.
        assert "RESULT: NOT A BUNDLE" in out.out


def test_an_unparseable_file_still_prints_a_verdict_line(tmp_path, capsys):
    """Exit code 2 says "I could not read this", but a script that greps stdout for RESULT: had
    nothing to read and would hang or mis-report."""
    from provenrail.cli import main as cli_main

    for content in ("", "{ not json }"):
        bad = tmp_path / "b.json"
        bad.write_text(content, encoding="utf-8")
        capsys.readouterr()
        assert cli_main(["verify", str(bad)]) == 2
        out = capsys.readouterr()
        assert "RESULT: NOT A BUNDLE" in out.out
        assert "not valid JSON" in out.err
        assert "Traceback" not in out.out + out.err


def test_the_hook_arms_the_packs_it_was_asked_for(tmp_path, monkeypatch, capsys):
    """`pr guard hook --use destructive` accepted the flag and then ignored it: with no config
    file the hook allowed everything while its own help text said the packs were armed. A
    guardrail that reports itself as on and is off is worse than no guardrail."""
    import json as _json

    from provenrail.cli import main as cli_main

    monkeypatch.chdir(tmp_path)   # deliberately no .provenrail.json here
    payload = _json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": "rm -rf /"}})

    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    capsys.readouterr()
    code = cli_main(["guard", "hook", "--use", "destructive"])
    out = capsys.readouterr()
    assert code != 0 or "deny" in (out.out + out.err).lower(), (
        f"a recursive force-remove must not be waved through: exit={code} {out.out} {out.err}")

    # A typo must refuse to enforce and say so, rather than silently arming nothing.
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    capsys.readouterr()
    assert cli_main(["guard", "hook", "--use", "destructiv"]) == 0   # never block on our own error
    err = capsys.readouterr().err
    assert "unknown guardrail pack" in err and "NOT enforcing" in err


def test_a_use_flag_that_names_no_pack_refuses_rather_than_falling_back(tmp_path, monkeypatch,
                                                                       capsys):
    """`--use "  "` and `--use ,,` parse to an empty list, which is falsy, which used to mean
    "no --use given" and quietly armed whatever the config file said. The flag then reads as if
    the user chose those packs. Same class of lie as the typo case: refuse, and say so."""
    import json as _json

    from provenrail.cli import main as cli_main

    monkeypatch.chdir(tmp_path)
    payload = _json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": "rm -rf /"}})
    for empty in ("   ", ",,", ""):
        monkeypatch.setattr("sys.stdin", io.StringIO(payload))
        capsys.readouterr()
        assert cli_main(["guard", "hook", "--use", empty]) == 0   # never block on our own error
        err = capsys.readouterr().err
        assert "names no guardrail pack" in err and "NOT enforcing" in err, err

    # `pr guard install` writes the packs to disk, so the same value must not be persisted.
    (tmp_path / ".provenrail.json").write_text('{"endpoint": "http://localhost:8787"}\n')
    capsys.readouterr()
    assert cli_main(["guard", "install", "--use", "  "]) == 2
    cfg = _json.loads((tmp_path / ".provenrail.json").read_text())
    assert "policy" not in cfg, f"a refused --use must arm nothing on disk: {cfg}"


def test_the_exit_code_contract_is_documented_where_a_script_author_looks():
    """A CI job gates on the exit code. 2 (could not read the file) and 1 (a real verdict that is
    not a pass) mean opposite things, and conflating them turns a mistyped path into a tampering
    incident. It has to be in --help, not only in our heads."""
    import contextlib

    from provenrail.cli import build_parser
    from provenrail.verifier.verify import main as verify_main

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        verify_main(["--help"])
    help_text = buf.getvalue()
    assert "exit codes" in help_text
    assert "NOT A PROVENRAIL BUNDLE" in help_text and "NOT A BUNDLE" in help_text

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        build_parser().parse_args(["verify", "--help"])
    assert "exit codes" in buf.getvalue()


def test_a_pack_name_in_capitals_is_the_same_pack(tmp_path, monkeypatch, capsys):
    """The ids are lowercase, so `--use DESTRUCTIVE` errored during setup. The user meant the
    pack that exists, and there is no second pack the capitals could refer to."""
    import json as _json

    from provenrail.cli import main as cli_main

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".provenrail.json").write_text('{"endpoint": "http://localhost:8787"}\n')
    capsys.readouterr()
    assert cli_main(["guard", "install", "--use", "DESTRUCTIVE, Secrets "]) == 0
    cfg = _json.loads((tmp_path / ".provenrail.json").read_text())
    assert cfg["policy"]["use"] == ["destructive", "secrets"], cfg


def test_writing_a_receipt_is_not_a_failure_just_because_it_contains_denials(monkeypatch,
                                                                            tmp_path, capsys):
    """`pr guard receipt` delegated its exit code to `pr risk`, which exits 1 when it finds
    denials. Denials are the reason you run it, so a successful export reported itself as a
    failure, and did so with the same code as an export that produced nothing at all."""
    import argparse

    from provenrail import cli

    bundle = tmp_path / "guard-receipt.json"
    denial = {"action_type": "policy.decision", "seq": 0,
              "payload": {"effect": "deny", "rule": "destructive.recursive-force-remove",
                          "reason": "argument contains a recursive delete",
                          "event_type": "PreToolUse", "target": "Bash"}}
    bundle.write_text(_json_dumps({"records": [{"record": denial}]}))

    monkeypatch.setattr(cli, "_cmd_export", lambda ns: 0)
    capsys.readouterr()
    code = cli._cmd_guard(argparse.Namespace(action="receipt", out=str(bundle), use=None,
                                             event="pre"))
    out = capsys.readouterr().out
    assert code == 0, "writing the receipt succeeded"
    assert "destructive.recursive-force-remove" in out, "the denial is still reported"

    # ...and the gating exit code is still available where a CI job would look for it.
    assert cli._cmd_risk(argparse.Namespace(bundle=str(bundle), json=False)) == 1


def _json_dumps(o):
    import json as _json
    return _json.dumps(o)


def test_pr_reports_its_own_version(capsys):
    """The first line of any bug report."""
    from provenrail import __version__
    from provenrail.cli import main as cli_main

    with pytest.raises(SystemExit) as e:
        cli_main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_report_writes_the_file_it_was_asked_for(tmp_path, capsys):
    """`--out` was honoured only on the --html path. With --md or the default JSON it was
    silently ignored and the report went to stdout, so the evidence file someone believed they
    had saved did not exist, and nothing said so."""
    import argparse
    import json as _json

    from provenrail.cli import _cmd_demo, _cmd_report

    bundle = tmp_path / "b.json"
    _cmd_demo(argparse.Namespace(out=str(bundle), pin=str(tmp_path / "pin.json"),
                                 anchor="local", tsa=""))
    capsys.readouterr()

    for flag, name in ((("md", True), "r.md"), (("md", False), "r.json")):
        out = tmp_path / name
        rc = _cmd_report(argparse.Namespace(
            bundle=str(bundle), regime="generic", pin=None, md=flag[1], html=False,
            out=str(out), tlog_pubkey=None, witness_pubkeys=None))
        assert rc in (0, 1)
        assert out.is_file(), f"{name} was requested with --out and never written"
        assert out.read_text(encoding="utf-8").strip(), f"{name} is empty"
    _json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))   # valid JSON, not markdown
    assert (tmp_path / "r.md").read_text(encoding="utf-8").startswith("#")


def test_pack_lists_what_is_actually_in_the_archive(tmp_path, capsys):
    """The summary was a hardcoded list that had drifted from the builder: it named an
    "attestation" entry the pack does not contain and omitted the rendered report an auditor
    opens first. A contents list that is not read from the archive is a guess."""
    import argparse
    import io
    import zipfile

    from provenrail.cli import _cmd_demo, _cmd_pack

    bundle = tmp_path / "b.json"
    _cmd_demo(argparse.Namespace(out=str(bundle), pin=str(tmp_path / "pin.json"),
                                 anchor="local", tsa=""))
    zip_path = tmp_path / "pack.zip"
    capsys.readouterr()
    _cmd_pack(argparse.Namespace(bundle=str(bundle), out=str(zip_path), regime="generic",
                                 pin=None))
    printed = capsys.readouterr().out
    with zipfile.ZipFile(io.BytesIO(zip_path.read_bytes())) as z:
        names = z.namelist()
    assert names
    for n in names:
        assert n in printed, f"{n} is in the pack but not in the printed contents"
    assert "attestation," not in printed, "the stale hardcoded entry is back"


def test_diff_exits_nonzero_when_the_runs_differ(tmp_path, capsys):
    """`pr diff` answers one question: did the rerun do the same thing? It exited 0 either way,
    so that question could not be gated on in CI without parsing stdout. diff(1) convention."""
    import argparse
    import json as _json

    from provenrail.cli import _cmd_demo, _cmd_diff

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    for p in (a, b):
        _cmd_demo(argparse.Namespace(out=str(p), pin=str(tmp_path / "pin.json"),
                                     anchor="local", tsa=""))
    capsys.readouterr()
    assert _cmd_diff(argparse.Namespace(bundle_a=str(a), bundle_b=str(b), json=False)) == 0

    changed = _json.loads(b.read_text(encoding="utf-8"))
    for r in changed["records"]:
        rec = r.get("record", r)
        if rec.get("action_type") == "tool_call":
            rec.setdefault("payload", {})["tool"] = "something_else"
            break
    b.write_text(_json.dumps(changed), encoding="utf-8")
    capsys.readouterr()
    assert _cmd_diff(argparse.Namespace(bundle_a=str(a), bundle_b=str(b), json=False)) == 1
    assert "RUNS DIFFER" in capsys.readouterr().out
    # --json must agree: same verdict, machine-readable.
    assert _cmd_diff(argparse.Namespace(bundle_a=str(a), bundle_b=str(b), json=True)) == 1


def test_the_sink_reports_the_version_it_is_actually_running():
    """/v1/meta carried the literal "0.2.0" long after the package moved on, so every deployed
    sink misreported itself. This is the field you read during an incident to answer "which
    build is this?"."""
    from provenrail import __version__

    c = client()
    assert c.get("/v1/meta").json()["version"] == __version__


def test_concurrent_ingest_never_returns_a_spurious_auth_or_missing_stream(tmp_path):
    """Two agents writing at the same moment used to break each other's reads.

    `sqlite3.Connection` is not safe for concurrent cursor use across threads, and only writes
    were serialised here. A read cursor interleaved with another thread's statement made
    `fetchone()` return None for rows that plainly exist. Against a real server on CPython
    3.14 a 400-request burst from 16 threads reliably produced ~28 500s (count_records doing
    `fetchone()["n"]` on the None), ~22 401 "invalid token" for a VALID token, and ~8 404
    "unknown stream" for a stream that exists. On 3.11 the same burst was clean, which is why
    this went unnoticed: our CI matrix stopped at 3.13.

    The 401 is the worst of them: a client is entitled to read that as "my credentials were
    revoked", stop, and drop the run. Nothing was wrong with the credentials.

    Driven through the ASGI app rather than Storage directly, because the interleaving only
    shows up with the server's own read-read-read-write pattern per request.
    """
    import concurrent.futures as cf
    from collections import Counter

    from provenrail.server.app import create_app

    app = create_app(str(tmp_path / "s.db"), require_account=False)
    with TestClient(app) as c:
        prov = c.post("/v1/streams", json={}).json()
        sid, wt = prov["stream_id"], prov["write_token"]

        def send(seq):
            r = c.post("/v1/ingest", json={"records": [{
                "stream_id": sid, "seq": seq, "action_type": "tool_call",
                "record_hash": f"{seq:064x}", "ts_utc": "2026-08-05T10:00:00.0Z"}]},
                headers={"Authorization": f"Bearer {wt}"})
            return r.status_code

        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            codes = Counter(ex.map(send, range(400)))

    assert set(codes) == {200}, (
        f"a valid writer was refused under concurrency: {dict(codes)}. 401/404 here are "
        f"spurious (the token and stream are fine) and 500 is a crash on a None row.")


def test_python_m_provenrail_works_when_pr_is_shadowed():
    """`pr` is also GNU coreutils' paginator. On Windows under Git Bash that one wins on PATH,
    so `pr --version` prints "pr (GNU coreutils) 8.32" and `pr verify --pin` dies on an unknown
    option. Anyone who hits that needs an entry point PATH cannot shadow."""
    import subprocess
    import sys

    from provenrail import __version__

    out = subprocess.run([sys.executable, "-m", "provenrail", "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert __version__ in out.stdout + out.stderr


def test_quickstart_offers_a_zero_code_first_step(tmp_path, monkeypatch, capsys):
    """The first thing quickstart tells you to do must be a command, not a code sample.

    It used to open with a Python snippet: a new user arriving from the "never touched a
    terminal" guide had to create a file and author code before anything had demonstrated the
    tool works at all. `pr demo` produces a real signed run in one line, so success comes first
    and writing code comes second.
    """
    import inspect
    import re

    from provenrail import cli
    src = inspect.getsource(cli._cmd_quickstart)
    # Only what the command actually prints. Reading the raw source counted the explanatory
    # comment above the code, which mentions `pr demo`, so the check passed with the fix
    # reverted: a vacuous test that proved nothing.
    printed = "\n".join(re.findall(r'print\((?:f?"([^"]*)")\)', src))
    assert "pr demo" in printed, "quickstart never offers the zero-code demo"
    assert printed.index("pr demo") < printed.index("import provenrail as fr"), (
        "quickstart must lead with the zero-code demo, not a code sample")


def test_a_malformed_trust_key_is_an_argument_error_not_a_tampering_verdict(capsys):
    """A typo in --tlog-pubkey used to reach the checkpoint check, fail the signature, and print
    TAMPERING DETECTED with exit 1. That sends an operator hunting an attack that never happened,
    and in CI it gates the build on a shell typo. A key that is not 32 hex-encoded bytes is a bad
    argument: exit 2, say so, verify nothing."""
    from provenrail.cli import main as cli_main
    from provenrail.verifier.verify import main as verify_main

    bundle = pathlib.Path(__file__).resolve().parents[1] / "web" / "demo-bundle.json"
    assert bundle.exists(), "the demo bundle the homepage ships is the fixture here"
    good = "ab" * 32  # right length, wrong key: that IS a verdict, not an argument error

    for flag in ("--tlog-pubkey", "--registry-pubkey"):
        for bad in ("none", "zz" * 32, "ab" * 16):  # not hex, not hex, right hex wrong length
            capsys.readouterr()
            assert verify_main([str(bundle), flag, bad]) == 2
            err = capsys.readouterr().err
            assert flag in err and "Nothing was verified against it." in err

    capsys.readouterr()
    assert cli_main(["verify", str(bundle), "--tlog-pubkey", "none"]) == 2
    assert "TAMPERING" not in capsys.readouterr().out

    capsys.readouterr()
    assert verify_main([str(bundle), "--witness-pubkeys", "w=none"]) == 2
    assert "Nothing was verified against it." in capsys.readouterr().err

    # A well-formed key that simply is not the log's key must still reach the real check.
    capsys.readouterr()
    assert verify_main([str(bundle), "--tlog-pubkey", good]) != 2


def test_a_dead_sink_does_not_wedge_the_next_quickstart(tmp_path, monkeypatch, capsys):
    """A quickstart whose sink never came up left its pid file behind, so the NEXT quickstart
    refused to start ("already recorded as running") naming a pid that was already dead. The fix
    it suggested, `--stop`, had nothing to stop. A new user's second command wedged them, and the
    only way out was deleting a file nobody had mentioned."""
    import os

    from provenrail.cli import _process_is_alive
    from provenrail.cli import main as cli_main

    # The liveness check is the whole fix, so it is checked directly and honestly.
    assert _process_is_alive(str(os.getpid())) is True
    assert _process_is_alive("2147483646") is False     # above any real pid on these platforms
    assert _process_is_alive("not-a-pid") is False

    monkeypatch.chdir(tmp_path)
    pid_file = tmp_path / ".provenrail.pid"
    pid_file.write_text("2147483646")                   # the corpse the old code tripped over

    capsys.readouterr()
    # It must get past the stale file. Whatever happens next (it will try to bind a port), the
    # one thing it must not do is refuse because of a pid that is not running.
    cli_main(["quickstart", "--port", "18931", "--db", str(tmp_path / "q.db")])
    err = capsys.readouterr().err
    assert "already recorded as running" not in err
    assert "stale record" in err


def test_pr_verify_accepts_every_flag_pr_verify_the_script_does(capsys):
    """`pr verify` and the `pr-verify` console script are two doors onto the same verifier, and
    the docs do not distinguish them. --tsa-root existed on one and not the other, so a
    documented command worked or failed depending on which door the reader used."""
    import contextlib
    import io
    import re

    from provenrail.cli import build_parser
    from provenrail.verifier.verify import main as verify_main

    def flags_of(parser_help: str) -> set[str]:
        return set(re.findall(r"--[a-z0-9][a-z0-9-]+", parser_help))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        verify_main(["--help"])
    standalone = flags_of(buf.getvalue())

    sub_help = io.StringIO()
    with contextlib.redirect_stdout(sub_help), contextlib.suppress(SystemExit):
        build_parser().parse_args(["verify", "--help"])
    subcommand = flags_of(sub_help.getvalue())

    # --help itself and output-only flags are shared; anything the standalone verifier accepts
    # that changes what is CHECKED must be reachable from the subcommand too.
    trust_flags = {f for f in standalone
                   if any(k in f for k in ("pubkey", "tsa", "pin", "openings", "bitcoin", "cosig"))}
    missing = trust_flags - subcommand
    assert not missing, f"`pr verify` cannot pass these to the verifier: {sorted(missing)}"
