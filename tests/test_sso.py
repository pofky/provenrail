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


def test_sso_jit_provisioning_cannot_exceed_the_plans_seat_limit():
    """A first-time SSO login buys a seat, so it must obey the seat cap the invite path obeys.

    Against a real 0.2.27 server this was the hole: `POST /v1/members` checked
    `plans.would_exceed(plan, "seats", ...)` but `POST /v1/sso/login` called
    `store.create_member` directly, so an org on the 10-seat Team plan grew past 10 simply by
    having more staff sign in with its IdP. Measured live: an account already at 10 members
    went to 11. That is a billing hole and it contradicts what the pricing card sells ("up to
    10 team members"). Only NEW users may be refused; people who already hold a seat must keep
    signing in, or a full org locks itself out of its own audit trail at renewal time.
    """
    c, owner_key, idp = _app_with_sso()
    owner_h = {"Authorization": f"Bearer {owner_key}"}

    # Seat 2 arrives via SSO, so we have a real SSO-provisioned member to re-check later.
    first = c.post("/v1/sso/login", json={"id_token": idp.token("fr-app", "early@corp.com")})
    assert first.status_code == 200, first.text

    # Fill the remaining seats by invitation: owner + 1 SSO member + 8 invites = 10 of 10.
    for i in range(8):
        r = c.post("/v1/members", json={"email": f"staff{i}@corp.com", "role": "viewer"},
                   headers=owner_h)
        assert r.status_code == 200, r.text
    assert len(c.get("/v1/members", headers=owner_h).json()["members"]) == 9  # + owner = 10

    # A brand-new person signing in is refused, with a message an admin can act on.
    over = c.post("/v1/sso/login", json={"id_token": idp.token("fr-app", "eleventh@corp.com")})
    assert over.status_code == 402, over.text
    assert "seat limit" in over.json()["detail"]
    assert len(c.get("/v1/members", headers=owner_h).json()["members"]) == 9  # nothing created

    # Someone who already has a seat is unaffected by the cap.
    again = c.post("/v1/sso/login", json={"id_token": idp.token("fr-app", "early@corp.com")})
    assert again.status_code == 200, again.text
    assert again.json()["member_id"] == first.json()["member_id"]


def test_disabling_a_member_frees_the_seat_they_occupied():
    """Seats are what an org pays for, so they must track people who can actually sign in.

    A member row is never deleted (the audit log points at it), and a disabled member's key is
    refused at authentication. Counting disabled rows toward the cap meant a Team account that
    replaced one person could never fill the tenth seat again: the 402 told an admin to free a
    seat, and no request existed that would free one.
    """
    c, owner_key, idp = _app_with_sso()
    owner_h = {"Authorization": f"Bearer {owner_key}"}
    ids = []
    for i in range(9):  # owner + 9 = 10 of 10
        r = c.post("/v1/members", json={"email": f"s{i}@corp.com", "role": "viewer"},
                   headers=owner_h)
        assert r.status_code == 200, r.text
        ids.append(r.json()["member_id"])
    assert c.post("/v1/members", json={"email": "over@corp.com", "role": "viewer"},
                  headers=owner_h).status_code == 402

    # Someone leaves.
    off = c.patch(f"/v1/members/{ids[0]}", json={"status": "disabled"}, headers=owner_h)
    assert off.status_code == 200, off.text

    # Their replacement fits, by invite and by SSO alike.
    hired = c.post("/v1/members", json={"email": "replacement@corp.com", "role": "viewer"},
                   headers=owner_h)
    assert hired.status_code == 200, hired.text
    assert c.post("/v1/members", json={"email": "one-too-many@corp.com", "role": "viewer"},
                  headers=owner_h).status_code == 402
    c.patch(f"/v1/members/{ids[1]}", json={"status": "disabled"}, headers=owner_h)
    assert c.post("/v1/sso/login",
                  json={"id_token": idp.token("fr-app", "viasso@corp.com")}).status_code == 200

    # The rows are still there for the audit trail, just not billable.
    members = c.get("/v1/members", headers=owner_h).json()["members"]
    assert sum(1 for m in members if m["status"] == "disabled") == 2


def test_a_member_key_stops_working_when_the_plan_no_longer_covers_the_seat():
    """Seats were checked at invite time only, so a plan could shrink out from under one.

    Measured on 0.2.27: an owner upgraded to Team, invited a teammate, then downgraded to Free
    (a single-seat plan). The teammate's key still authenticated and still returned the stream
    list and usage. Cancelling a subscription left every former colleague with standing read
    access to the audit trail. Restoring the plan must restore access, because nothing is
    deleted, only refused.
    """
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret=BILLING_SECRET)
    c = TestClient(app)
    owner_key = c.post("/v1/accounts", json={}).json()["api_key"]
    owner_h = {"Authorization": f"Bearer {owner_key}"}
    bill_h = {**owner_h, "X-Provenrail-Billing-Secret": BILLING_SECRET}
    c.put("/v1/account/plan", json={"plan": "team"}, headers=bill_h)
    member = c.post("/v1/members", json={"email": "t@corp.com", "role": "member"},
                    headers=owner_h).json()
    mh = {"Authorization": f"Bearer {member['api_key']}"}
    assert c.get("/v1/streams", headers=mh).status_code == 200

    c.put("/v1/account/plan", json={"plan": "free"}, headers=bill_h)
    r = c.get("/v1/streams", headers=mh)
    assert r.status_code == 402, r.text
    assert "does not include team members" in r.json()["detail"]
    assert c.get("/v1/usage", headers=mh).status_code == 402
    # The owner is never locked out of their own account by this.
    assert c.get("/v1/streams", headers=owner_h).status_code == 200

    c.put("/v1/account/plan", json={"plan": "team"}, headers=bill_h)
    assert c.get("/v1/streams", headers=mh).status_code == 200  # same key, nothing re-issued


def test_downgrading_seat_count_keeps_the_longest_standing_members():
    """Enterprise (unlimited seats) to Team (10) has to pick which members keep access.

    Invitation order, oldest first, so every request agrees and the answer does not depend on
    who happens to call. The owner always holds seat one.
    """
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=True,
                     billing_secret=BILLING_SECRET)
    c = TestClient(app)
    owner_key = c.post("/v1/accounts", json={}).json()["api_key"]
    owner_h = {"Authorization": f"Bearer {owner_key}"}
    bill_h = {**owner_h, "X-Provenrail-Billing-Secret": BILLING_SECRET}
    c.put("/v1/account/plan", json={"plan": "enterprise"}, headers=bill_h)
    keys = [c.post("/v1/members", json={"email": f"m{i}@corp.com", "role": "member"},
                   headers=owner_h).json()["api_key"] for i in range(12)]
    assert all(c.get("/v1/streams", headers={"Authorization": f"Bearer {k}"}).status_code == 200
               for k in keys)

    c.put("/v1/account/plan", json={"plan": "team"}, headers=bill_h)  # 10 seats incl. owner
    codes = [c.get("/v1/streams", headers={"Authorization": f"Bearer {k}"}).status_code
             for k in keys]
    assert codes == [200] * 9 + [402] * 3, codes
    assert "more active members than plan" in c.get(
        "/v1/streams", headers={"Authorization": f"Bearer {keys[-1]}"}).json()["detail"]
