"""Offline commercial-license verification + the server tier unlock it drives.

The license is a commercial control, not security: see src/provenrail/license.py. These tests
prove the mechanics work (sign -> verify, tamper/expiry/wrong-key rejected) and that a valid
license makes a self-hosted server run a free account at the licensed tier.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from provenrail import license as lic
from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_account, provision_stream
from provenrail.server.app import create_app


def _keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw).hex()
    return priv, pub


def test_sign_then_verify_roundtrips():
    priv, pub = _keypair()
    tok = lic.sign_license({"account": "acc_1", "plan": "team", "iat": 1000, "exp": None}, priv)
    assert tok.startswith("prl_live_")
    info = lic.verify_license(tok, public_key_hex=pub)
    assert info.valid and info.plan == "team" and info.account == "acc_1"


def test_tampered_payload_rejected():
    priv, pub = _keypair()
    tok = lic.sign_license({"account": "a", "plan": "builder", "iat": 1, "exp": None}, priv)
    # Flip a character in the payload segment; the signature must no longer verify.
    head, sig = tok.split(".", 1)
    tampered = head[:-1] + ("A" if head[-1] != "A" else "B") + "." + sig
    assert lic.verify_license(tampered, public_key_hex=pub).valid is False


def test_wrong_key_rejected():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    tok = lic.sign_license({"account": "a", "plan": "team", "iat": 1, "exp": None}, priv)
    info = lic.verify_license(tok, public_key_hex=other_pub)
    assert info.valid is False and "signature" in (info.reason or "")


def test_expiry_enforced():
    priv, pub = _keypair()
    tok = lic.sign_license({"account": "a", "plan": "team", "iat": 1, "exp": 2000}, priv)
    assert lic.verify_license(tok, public_key_hex=pub, now=1999).valid is True
    expired = lic.verify_license(tok, public_key_hex=pub, now=2001)
    assert expired.valid is False and expired.reason == "license expired"


def test_non_license_strings_rejected():
    for junk in (None, "", "hello", "prl_live_nope", "prl_live_a.b.c"):
        assert lic.verify_license(junk).valid is False


def _mint_like_deno(account: str, plan: str, iat: int, exp: int | None, priv_hex: str) -> str:
    """Reproduce supabase/functions/polar-webhook mintLicense() byte-for-byte in pure Python.

    Production license issuance happens in the Deno webhook, not via sign_license(); this mirrors
    its exact construction (JS JSON.stringify field order/compaction, base64url with -_ and no
    padding, Ed25519 signature over the base64url payload segment) so a drift on either side of the
    contract fails here. Ed25519 is deterministic (RFC 8032), so cryptography's signature is
    identical to @noble/ed25519's for the same key and message.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # JS: JSON.stringify({account, plan, iat, exp}) -> compact, this key order, exp:null when None.
    exp_json = "null" if exp is None else str(exp)
    payload = f'{{"account":"{account}","plan":"{plan}","iat":{iat},"exp":{exp_json}}}'

    def b64url(raw: bytes) -> str:  # JS: btoa(...).replace(+/->-_).replace(/=+$/,"")
        return base64.b64encode(raw).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")

    b64payload = b64url(payload.encode("utf-8"))
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    sig = sk.sign(b64payload.encode("ascii"))  # JS: ed.signAsync(utf8(b64payload), secretHex)
    return "prl_live_" + b64payload + "." + b64url(sig)


def test_deno_minted_token_verifies_in_python():
    # The revenue-critical cross-language contract: a key minted exactly as the Deno webhook mints
    # it must verify under the Python server. A break here silently blocks every paid activation.
    priv, pub = _keypair()
    tok = _mint_like_deno("acc_42", "team", 1700000000, None, priv)
    info = lic.verify_license(tok, public_key_hex=pub)
    assert info.valid and info.plan == "team" and info.account == "acc_42"
    # And the Python signer produces the identical token for the same inputs (full byte parity).
    assert lic.sign_license(
        {"account": "acc_42", "plan": "team", "iat": 1700000000, "exp": None}, priv) == tok


def test_deno_minted_token_respects_period_expiry():
    # The webhook now mints with exp = period_end + grace, so a one-month payment is not perpetual.
    priv, pub = _keypair()
    tok = _mint_like_deno("acc_42", "builder", 1700000000, 1700000600, priv)
    assert lic.verify_license(tok, public_key_hex=pub, now=1700000500).valid is True
    expired = lic.verify_license(tok, public_key_hex=pub, now=1700000601)
    assert expired.valid is False and expired.reason == "license expired"


def test_self_hosted_server_unlocks_tier_with_license(monkeypatch):
    # A valid team license must let a free account use a Team-only feature (bulk export).
    priv, pub = _keypair()
    monkeypatch.setattr(lic, "PUBLIC_KEY_HEX", pub)
    token = lic.sign_license({"account": "acc", "plan": "team", "iat": 1, "exp": None}, priv)

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True, license_token=token)
    c = TestClient(app)
    key = provision_account("http://t", http=c)["api_key"]
    prov = provision_stream("http://t", http=c, api_key=key)
    sid = prov["stream_id"]
    h = {"Authorization": f"Bearer {key}"}
    c.post("/v1/ingest", json={"records": [{"stream_id": sid, "record_hash": "h0", "seq": 0}]},
           headers={"Authorization": f"Bearer {prov['write_token']}"})

    # Usage reports the licensed tier, not the stored free plan.
    body = c.get("/v1/usage", headers=h).json()
    assert body["plan"] == "team"
    assert body["features"]["exports"] is True
    # And the Team-gated export actually works on this otherwise-free account.
    assert c.get(f"/v1/streams/{sid}/export.ndjson", headers=h).status_code == 200


def test_invalid_license_does_not_unlock(monkeypatch):
    # A token signed by the wrong key is ignored; the account stays free and gated.
    priv, _ = _keypair()
    _, embedded_pub = _keypair()
    monkeypatch.setattr(lic, "PUBLIC_KEY_HEX", embedded_pub)
    token = lic.sign_license({"account": "acc", "plan": "team", "iat": 1, "exp": None}, priv)

    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True, license_token=token)
    c = TestClient(app)
    key = provision_account("http://t", http=c)["api_key"]
    prov = provision_stream("http://t", http=c, api_key=key)
    h = {"Authorization": f"Bearer {key}"}
    assert c.get("/v1/usage", headers=h).json()["plan"] == "free"
    assert c.get(f"/v1/streams/{prov['stream_id']}/export.ndjson", headers=h).status_code == 402
