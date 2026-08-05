"""OIDC SSO: strict ID-token validation and JIT member provisioning, with a mock IdP."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.server import sso
from provenrail.server.app import create_app

#: Stands in for the payment provider webhook secret. An upgrade is applied by the billing
#: provider after payment, never by the account holder's own API key.
BILLING_SECRET = "test-billing-secret"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_int(i: int) -> str:
    return _b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))


class MockIdP:
    """A minimal RS256 OpenID provider for tests: mints ID tokens and publishes a JWKS."""

    def __init__(self, issuer="https://idp.example.com", kid="k1"):
        self.issuer = issuer
        self.kid = kid
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict:
        nums = self._priv.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig",
                          "n": _b64u_int(nums.n), "e": _b64u_int(nums.e)}]}

    def token(self, audience, email, exp_in=3600, alg="RS256", **extra) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        header = {"alg": alg, "kid": self.kid, "typ": "JWT"}
        claims = {"iss": self.issuer, "aud": audience, "email": email,
                  "sub": "sub-" + email, "exp": int(time.time()) + exp_in,
                  "iat": int(time.time()), **extra}
        signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(claims).encode())}"
        sig = self._priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64u(sig)}"


def _now():
    return int(time.time())


# ---- unit: verify_id_token ----

def test_verify_valid_rs256_token():
    idp = MockIdP()
    tok = idp.token("fr-app", "alice@corp.com")
    claims = sso.verify_id_token(tok, jwks=idp.jwks(), issuer=idp.issuer,
                                 audience="fr-app", now=_now())
    assert claims["email"] == "alice@corp.com"


def test_reject_wrong_audience():
    idp = MockIdP()
    tok = idp.token("other-app", "a@corp.com")
    with pytest.raises(sso.SSOError):
        sso.verify_id_token(tok, jwks=idp.jwks(), issuer=idp.issuer, audience="fr-app", now=_now())


def test_reject_expired():
    idp = MockIdP()
    tok = idp.token("fr-app", "a@corp.com", exp_in=-7200)
    with pytest.raises(sso.SSOError):
        sso.verify_id_token(tok, jwks=idp.jwks(), issuer=idp.issuer, audience="fr-app", now=_now())


def test_reject_wrong_issuer():
    idp = MockIdP(issuer="https://evil.example.com")
    tok = idp.token("fr-app", "a@corp.com")
    with pytest.raises(sso.SSOError):
        sso.verify_id_token(tok, jwks=idp.jwks(), issuer="https://idp.example.com",
                            audience="fr-app", now=_now())


def test_reject_alg_none():
    idp = MockIdP()
    header = _b64u(json.dumps({"alg": "none", "kid": "k1"}).encode())
    payload = _b64u(json.dumps({"iss": idp.issuer, "aud": "fr-app", "email": "a@corp.com",
                                "exp": _now() + 3600}).encode())
    forged = f"{header}.{payload}."
    with pytest.raises(sso.SSOError):
        sso.verify_id_token(forged, jwks=idp.jwks(), issuer=idp.issuer, audience="fr-app",
                            now=_now())


def test_reject_tampered_signature():
    idp = MockIdP()
    tok = idp.token("fr-app", "a@corp.com")
    head, payload, sig = tok.split(".")
    # flip a byte in the payload, keep the old signature
    bad_claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    bad_claims["email"] = "attacker@corp.com"
    forged = f"{head}.{_b64u(json.dumps(bad_claims).encode())}.{sig}"
    with pytest.raises(sso.SSOError):
        sso.verify_id_token(forged, jwks=idp.jwks(), issuer=idp.issuer, audience="fr-app",
                            now=_now())


def test_eddsa_token():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "e1", "x": _b64u(pub)}]}
    header = _b64u(json.dumps({"alg": "EdDSA", "kid": "e1"}).encode())
    claims = _b64u(json.dumps({"iss": "https://idp", "aud": "app", "email": "e@c.com",
                               "exp": _now() + 3600}).encode())
    si = f"{header}.{claims}"
    sig = priv.sign(si.encode())
    tok = f"{si}.{_b64u(sig)}"
    out = sso.verify_id_token(tok, jwks=jwks, issuer="https://idp", audience="app", now=_now())
    assert out["email"] == "e@c.com"


# ---- end to end through the server ----

def _app_with_sso(default_role="member", email_domain=None):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret="test-billing-secret")
    c = TestClient(app)
    owner_key = c.post("/v1/accounts", json={}).json()["api_key"]
    # SSO + members are Team+ features.
    c.put("/v1/account/plan", json={"plan": "team"},
          headers={"Authorization": f"Bearer {owner_key}",
                   "X-Provenrail-Billing-Secret": BILLING_SECRET})
    idp = MockIdP()
    cfg = {"issuer": idp.issuer, "audience": "fr-app", "jwks": idp.jwks(),
           "default_role": default_role}
    if email_domain:
        cfg["email_domain"] = email_domain
    r = c.put("/v1/sso/config", json=cfg, headers={"Authorization": f"Bearer {owner_key}"})
    assert r.status_code == 200, r.text
    return c, owner_key, idp


def test_sso_login_provisions_member():
    c, owner_key, idp = _app_with_sso()
    tok = idp.token("fr-app", "newhire@corp.com")
    r = c.post("/v1/sso/login", json={"id_token": tok})
    assert r.status_code == 200, r.text
    member_key = r.json()["api_key"]
    assert r.json()["role"] == "member"
    # the issued key works and is scoped to the org
    assert c.get("/v1/streams", headers={"Authorization": f"Bearer {member_key}"}).status_code == 200
    # the member appears in the org roster
    members = c.get("/v1/members", headers={"Authorization": f"Bearer {owner_key}"}).json()["members"]
    assert any(m["email"] == "newhire@corp.com" for m in members)


def test_sso_login_rejects_bad_token():
    c, owner_key, idp = _app_with_sso()
    evil = MockIdP(issuer=idp.issuer)  # right issuer, wrong (unknown) signing key
    tok = evil.token("fr-app", "imposter@corp.com")
    r = c.post("/v1/sso/login", json={"id_token": tok})
    assert r.status_code == 401


def test_sso_email_domain_enforced():
    c, owner_key, idp = _app_with_sso(email_domain="corp.com")
    bad = idp.token("fr-app", "contractor@gmail.com")
    assert c.post("/v1/sso/login", json={"id_token": bad}).status_code == 403
    good = idp.token("fr-app", "staff@corp.com")
    assert c.post("/v1/sso/login", json={"id_token": good}).status_code == 200


def test_sso_repeat_login_reuses_member_rotating_key():
    c, owner_key, idp = _app_with_sso()
    k1 = c.post("/v1/sso/login", json={"id_token": idp.token("fr-app", "a@corp.com")}).json()
    k2 = c.post("/v1/sso/login", json={"id_token": idp.token("fr-app", "a@corp.com")}).json()
    assert k1["member_id"] == k2["member_id"]
    assert k1["api_key"] != k2["api_key"]  # a fresh session key each login
    # only one member row for that email
    members = c.get("/v1/members", headers={"Authorization": f"Bearer {owner_key}"}).json()["members"]
    assert sum(1 for m in members if m["email"] == "a@corp.com") == 1


def test_sso_config_requires_owner():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret="test-billing-secret")
    c = TestClient(app)
    owner_key = c.post("/v1/accounts", json={}).json()["api_key"]
    c.put("/v1/account/plan", json={"plan": "team"},
          headers={"Authorization": f"Bearer {owner_key}",
                   "X-Provenrail-Billing-Secret": BILLING_SECRET})
    admin = c.post("/v1/members", json={"role": "admin"},
                   headers={"Authorization": f"Bearer {owner_key}"}).json()["api_key"]
    r = c.put("/v1/sso/config", json={"issuer": "i", "audience": "a", "jwks": {"keys": []}},
              headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 403  # admin lacks owner.manage
