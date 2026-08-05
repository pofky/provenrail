"""The simple-to-the-max front door: one-line record(), config resolution, decorator."""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

import provenrail as fr
from provenrail import easy
from provenrail.anchor import LocalAnchor
from provenrail.server.app import create_app


def _server():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    return app, TestClient(app)


def _reset():
    easy._GLOBAL.clear()


def test_one_line_record_captures(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)  # no stray config file
    app, c = _server()
    fr.configure(endpoint="http://t", http=c)

    with fr.record("billing-agent") as rec:
        rec.record_decision("ship it")

    # exactly one stream was auto-provisioned and the session is sealed and off-box
    streams = app.state.store.list_streams(None)
    assert len(streams) == 1
    bundle = c.get(f"/v1/streams/{streams[0]['stream_id']}/bundle").json()
    actions = [r["record"]["action_type"] for r in bundle["records"]]
    assert "lifecycle.session_start" in actions
    assert "decision" in actions
    assert "lifecycle.session_end" in actions  # sealed automatically on exit
    _reset()


def test_decorator_form(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    fr.configure(endpoint="http://t", http=c)

    @fr.recorded("nightly-job")
    def run():
        return 42

    assert run() == 42
    assert len(app.state.store.list_streams(None)) == 1
    _reset()


def test_reuses_existing_token_without_provisioning(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    from provenrail.ingest_client import provision_stream
    prov = provision_stream("http://t", http=c)
    fr.configure(endpoint="http://t", http=c, write_token=prov["write_token"],
                 stream_id=prov["stream_id"])

    with fr.record("agent") as rec:
        rec.record_decision("x")
    # no NEW stream created: the configured one was reused
    assert len(app.state.store.list_streams(None)) == 1
    _reset()


def test_config_file_resolution(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    # write a .provenrail.json like `pr quickstart` would, then inject only the http client
    easy.write_config(tmp_path / easy.CONFIG_FILENAME, endpoint="http://t")
    fr.configure(http=c)  # http cannot live in a file; everything else comes from the file

    with fr.record("agent"):
        pass
    assert len(app.state.store.list_streams(None)) == 1
    _reset()


def test_env_var_resolution(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    monkeypatch.setenv("FLIGHTRECORDER_URL", "http://t")
    fr.configure(http=c)
    with fr.record("agent"):
        pass
    assert len(app.state.store.list_streams(None)) == 1
    _reset()


def test_missing_endpoint_raises(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FLIGHTRECORDER_URL", raising=False)
    import pytest
    with pytest.raises(RuntimeError, match="endpoint"):
        with fr.record("agent"):
            pass
    _reset()


def test_auto_instrument_detects_client(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    fr.configure(endpoint="http://t", http=c)

    # a fake client whose module looks like 'anthropic' so auto-instrument picks the wrapper
    captured = {}

    def fake_instrument(client, recorder):
        captured["wrapped"] = True

    monkeypatch.setattr("provenrail.integrations.instrument_anthropic", fake_instrument)

    class _FakeAnthropic:
        pass
    _FakeAnthropic.__module__ = "anthropic.client"

    with fr.record("agent", clients=[_FakeAnthropic()]):
        pass
    assert captured.get("wrapped") is True
    _reset()


def test_auto_instrument_unknown_client_warns_not_silent(monkeypatch, tmp_path):
    """An unrecognized client passed to clients=[...] must warn loudly: silently capturing
    nothing would let a user ship believing calls are recorded when none are."""
    import warnings

    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    fr.configure(endpoint="http://t", http=c)

    class _MysteryClient:  # not openai/anthropic, no call_tool
        pass

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with fr.record("agent", clients=[_MysteryClient()]):
            pass
    msgs = [str(w.message) for w in caught]
    assert any("not be captured" in m.lower() and "_MysteryClient" in m for m in msgs), msgs
    _reset()


def test_record_with_policy_enforces(monkeypatch, tmp_path):
    _reset()
    monkeypatch.chdir(tmp_path)
    app, c = _server()
    fr.configure(endpoint="http://t", http=c)
    from provenrail.policy import Policy, PolicyViolation, Rule

    policy = Policy(rules=[Rule(id="no-x", effect="deny", event_type="tool_call", tool="danger")])
    raised = False
    try:
        with fr.record("agent", policy=policy) as rec:
            rec.record_tool_call("danger", {}, {})
    except PolicyViolation:
        raised = True
    assert raised
    _reset()


def test_the_cli_never_shows_a_traceback_for_a_missing_sink(tmp_path, monkeypatch):
    """`pr sidecar` in a fresh folder printed eleven lines of traceback around one useful
    sentence. A traceback tells the user about our internals; they asked about theirs."""
    import subprocess
    import sys

    env = dict(os.environ)
    env.pop("PROVENRAIL_URL", None)
    r = subprocess.run([sys.executable, "-m", "provenrail.cli", "sidecar",
                        "--upstream", "https://api.openai.com"],
                       cwd=tmp_path, capture_output=True, text=True, env=env)
    assert r.returncode != 0
    assert "Traceback" not in r.stderr and "Traceback" not in r.stdout, r.stderr
    assert "quickstart" in (r.stderr + r.stdout)


def test_an_unknown_rule_pack_is_an_error_not_the_whole_catalogue(tmp_path):
    """`pr rules --use secretts` printed every pack and exited 0, so a typo looked exactly like
    success. The same typo in .provenrail.json is how a pack ends up unarmed while its owner
    believes otherwise."""
    import subprocess
    import sys

    bad = subprocess.run([sys.executable, "-m", "provenrail.cli", "rules", "--use", "secretts"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert bad.returncode == 2, bad.stdout
    assert "unknown pack" in bad.stderr

    good = subprocess.run([sys.executable, "-m", "provenrail.cli", "rules", "--use", "secrets"],
                          cwd=tmp_path, capture_output=True, text=True)
    assert good.returncode == 0
    assert "secrets" in good.stdout and "destructive  (" not in good.stdout


def test_ots_verify_explains_the_companion_file_instead_of_naming_a_path_nobody_typed(tmp_path):
    """The error was `file not found: test` for a command whose only argument was test.ots."""
    import subprocess
    import sys

    proof = tmp_path / "proof.ots"
    proof.write_bytes(b"not a real proof")
    r = subprocess.run([sys.executable, "-m", "provenrail.cli", "ots-verify", str(proof)],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "--data-sha256" in r.stderr and str(proof) in r.stderr
    assert "file not found" not in r.stderr
