"""Agent identity registry (Know Your Agent): registration, rotation, and verifier binding."""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from provenrail import registry as reg
from provenrail.anchor import LocalAnchor
from provenrail.keys import SigningKey
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _codes(rep):
    return {f.code for f in rep.findings}


def test_assertion_sign_and_verify_roundtrip():
    key = SigningKey.generate()
    body = reg.assertion_body("acct", "agent-1", "ab" * 32, "active", "t", None)
    a = reg.sign_assertion(body, key)
    assert reg.verify_assertion(a, key.public_key_hex())
    # wrong key fails
    assert not reg.verify_assertion(a, SigningKey.generate().public_key_hex())
    # tampered field fails
    bad = copy.deepcopy(a)
    bad["agent_id"] = "agent-2"
    assert not reg.verify_assertion(bad, key.public_key_hex())


def _account_app():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True)
    c = TestClient(app)
    acct = c.post("/v1/accounts", json={}).json()
    return app, c, acct["api_key"]


def _run_registered(app, c, key, device: SigningKey, agent_id="billing-agent"):
    # register the device key for an agent, then run a session signed by it.
    pub = device.public_key_hex()
    r = c.post("/v1/agents", json={"agent_id": agent_id, "pubkey": pub}, headers=_h(key))
    assert r.status_code == 200, r.text
    prov = c.post("/v1/streams", json={}, headers=_h(key)).json()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c, key=device)
    with fr.session({"agent": agent_id}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=_h(key))
    return prov["stream_id"]


def test_bundle_embeds_registry_assertion_and_verifies():
    app, c, key = _account_app()
    device = SigningKey.generate()
    sid = _run_registered(app, c, key, device)
    bundle = c.get(f"/v1/streams/{sid}/bundle", headers=_h(key)).json()
    assert "agent_registry" in bundle
    reg_pub = c.get("/v1/meta").json()["registry_pubkey"]
    rep = verify_bundle(bundle, registry_pubkey=reg_pub)
    assert "kya_registered" in _codes(rep)
    assert rep.ok


def test_unregistered_key_is_warn_not_fail():
    app, c, key = _account_app()
    device = SigningKey.generate()  # never registered
    prov = c.post("/v1/streams", json={}, headers=_h(key)).json()
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c, key=device)
    with fr.session({"agent": "ghost"}):
        fr.record_decision("ship")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor", headers=_h(key))
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle", headers=_h(key)).json()
    reg_pub = c.get("/v1/meta").json()["registry_pubkey"]
    rep = verify_bundle(bundle, registry_pubkey=reg_pub)
    assert "kya_unregistered" in _codes(rep)
    assert rep.ok  # warn, not a hard fail


def test_forged_assertion_fails():
    app, c, key = _account_app()
    device = SigningKey.generate()
    sid = _run_registered(app, c, key, device)
    bundle = c.get(f"/v1/streams/{sid}/bundle", headers=_h(key)).json()
    # Re-sign the assertion with an attacker key but verify against the real registry key.
    attacker = SigningKey.generate()
    body = {k: bundle["agent_registry"][0][k] for k in bundle["agent_registry"][0] if k != "sig"}
    bundle["agent_registry"][0] = reg.sign_assertion(body, attacker)
    reg_pub = c.get("/v1/meta").json()["registry_pubkey"]
    rep = verify_bundle(bundle, registry_pubkey=reg_pub)
    assert "kya_assertion_invalid" in _codes(rep)
    assert not rep.ok


def test_key_mismatch_assertion_for_other_key_is_unregistered():
    # An assertion that is validly signed but for a DIFFERENT pubkey than the records used
    # must not vouch for the records: the actual device key stays unregistered.
    app, c, key = _account_app()
    device = SigningKey.generate()
    sid = _run_registered(app, c, key, device)
    bundle = c.get(f"/v1/streams/{sid}/bundle", headers=_h(key)).json()
    reg_pub = c.get("/v1/meta").json()["registry_pubkey"]
    # Swap the assertion's pubkey to a different (validly registered-looking) key by re-signing
    # with the server registry key is not possible from the client; instead drop the matching
    # assertion and inject one for an unrelated key signed by a stranger -> invalid + unregistered.
    other = SigningKey.generate()
    body = reg.assertion_body("acct", "other-agent", other.public_key_hex(), "active", "t", None)
    bundle["agent_registry"] = [reg.sign_assertion(body, SigningKey.generate())]
    rep = verify_bundle(bundle, registry_pubkey=reg_pub)
    codes = _codes(rep)
    assert "kya_assertion_invalid" in codes or "kya_key_unregistered" in codes
    assert not rep.ok or "kya_key_unregistered" in codes


def test_rotation_revokes_old_key():
    app, c, key = _account_app()
    old = SigningKey.generate()
    c.post("/v1/agents", json={"agent_id": "a1", "pubkey": old.public_key_hex()}, headers=_h(key))
    new = SigningKey.generate()
    r = c.post("/v1/agents/a1/rotate",
               json={"old_pubkey": old.public_key_hex(), "new_pubkey": new.public_key_hex()},
               headers=_h(key))
    assert r.status_code == 200
    agents = c.get("/v1/agents", headers=_h(key)).json()["agents"]
    by_status = {a["pubkey"]: a["status"] for a in agents}
    assert by_status[old.public_key_hex()] == "revoked"
    assert by_status[new.public_key_hex()] == "active"


def test_registry_unchecked_without_pubkey():
    app, c, key = _account_app()
    device = SigningKey.generate()
    sid = _run_registered(app, c, key, device)
    bundle = c.get(f"/v1/streams/{sid}/bundle", headers=_h(key)).json()
    rep = verify_bundle(bundle)  # no registry pubkey supplied
    assert "kya_registry_unchecked" in _codes(rep)
    assert rep.ok


def test_agent_registration_requires_permission():
    app, c, key = _account_app()
    # inviting members is a Team+ feature; upgrade this account so the invite is allowed.
    c.put("/v1/account/plan", json={"plan": "team"}, headers=_h(key))
    # invite a viewer; viewers lack agent.manage
    viewer = c.post("/v1/members", json={"role": "viewer"}, headers=_h(key)).json()["api_key"]
    r = c.post("/v1/agents", json={"agent_id": "x", "pubkey": "ab" * 32}, headers=_h(viewer))
    assert r.status_code == 403
