"""Buying the plan is the only provisioning step, so the key must mean the same thing everywhere.

The hosted anchor service authenticates a customer by verifying their license key at the edge:
Ed25519, offline, no lookup. That key is minted by the Polar webhook and verified elsewhere by
src/provenrail/license.py. Three implementations of one token is where a customer ends up with a
key that their own sink accepts and the hosted service rejects, on the day they try to use what
they paid for.

These sign keys with the real Python issuer and require the service's actual verifier, running
under Node, to reach the same verdict, including on the cases that must be refused.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time

import pytest

from provenrail.license import PREFIX, PUBLIC_KEY_HEX, sign_license, verify_license

HERE = pathlib.Path(__file__).parent
RUNNER = HERE / "js" / "verify_license.mjs"
EDGE_FN = HERE.parent / "supabase" / "functions" / "anchor" / "index.ts"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture(scope="module")
def issuer():
    """A throwaway issuing key, so the tests never need the real private key to exist."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw).hex()
    return seed, pub


def _node(token: str, pub: str, now: int) -> dict:
    res = subprocess.run(["node", str(RUNNER), json.dumps({"token": token, "pub": pub, "now": now})],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(res.stdout)


def _mint(seed_hex: str, account: str, plan: str, exp: int | None) -> str:
    return sign_license({"account": account, "plan": plan, "iat": 1_700_000_000, "exp": exp},
                        seed_hex)


def test_a_key_the_python_verifier_accepts_is_accepted_at_the_edge(issuer):
    sk, pub = issuer
    now = int(time.time())
    token = _mint(sk, "user-42", "builder", now + 3600)

    py = verify_license(token, public_key_hex=pub, now=now)
    js = _node(token, pub, now)
    assert py.valid and js["valid"]
    assert js["plan"] == py.plan == "builder"
    assert js["account"] == py.account == "user-42"


def test_a_tampered_payload_is_refused_at_the_edge(issuer):
    """The signature covers the base64url payload as ASCII. Editing the plan inside it and
    re-encoding produces a key that still looks entirely well-formed."""
    sk, pub = issuer
    now = int(time.time())
    token = _mint(sk, "user-42", "free", now + 3600)
    body = token[len(PREFIX):]
    b64payload, sig = body.split(".", 1)

    import base64
    raw = base64.urlsafe_b64decode(b64payload + "=" * (-len(b64payload) % 4))
    forged_payload = json.loads(raw)
    forged_payload["plan"] = "team"
    reencoded = base64.urlsafe_b64encode(
        json.dumps(forged_payload, separators=(",", ":")).encode()).decode().rstrip("=")
    forged = PREFIX + reencoded + "." + sig

    assert not verify_license(forged, public_key_hex=pub, now=now).valid
    js = _node(forged, pub, now)
    assert not js["valid"], "the edge accepted a key whose plan was rewritten"
    assert js["reason"] == "license signature does not verify"


def test_an_expired_key_is_refused_at_the_edge_on_the_same_second(issuer):
    """Both sides must agree on where the boundary is, or a customer is anchoring on one and
    locked out of the other for as long as the two disagree."""
    sk, pub = issuer
    exp = 1_800_000_000
    token = _mint(sk, "user-42", "builder", exp)

    assert verify_license(token, public_key_hex=pub, now=exp).valid
    assert _node(token, pub, exp)["valid"], "the edge expired a key one second early"

    assert not verify_license(token, public_key_hex=pub, now=exp + 1).valid
    late = _node(token, pub, exp + 1)
    assert not late["valid"]
    assert late["reason"] == "license expired"


def test_a_key_signed_by_someone_else_is_refused(issuer):
    """Anyone can generate an Ed25519 key and mint a well-formed token with it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _sk, pub = issuer
    now = int(time.time())
    other = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()
    impostor = _mint(other, "user-42", "team", now + 3600)
    assert not verify_license(impostor, public_key_hex=pub, now=now).valid
    assert not _node(impostor, pub, now)["valid"]


@pytest.mark.parametrize("junk", ["", "hello", "prl_live_", "prl_live_abc", "prl_live_a.b.c",
                                  "prl_live_!!!.!!!"])
def test_malformed_keys_are_refused_rather_than_crashing(junk, issuer):
    """A service that throws on a malformed key answers 500 to what is really a 401, and turns
    every scanner hitting the endpoint into an error-rate alert."""
    _sk, pub = issuer
    js = _node(junk, pub, int(time.time()))
    assert js["valid"] is False
    assert js.get("reason")


def test_the_edge_checks_the_plan_and_says_which_one():
    """A free-plan key is a real key. Answering "invalid API key" sends someone with a working
    key hunting for a typo that is not there."""
    src = " ".join(EDGE_FN.read_text(encoding="utf-8").split())
    assert 'ANCHOR_PLANS = new Set(["builder", "team", "enterprise"])' in src
    assert "hosted anchoring is not included in the ${lic.plan} plan" in src
    assert "403" in src


def test_the_edge_verifies_against_the_shipped_public_key():
    """If the edge trusted a different issuer than the CLI does, a key that works locally would
    be rejected by the service, or worse, one the CLI rejects would be accepted."""
    src = EDGE_FN.read_text(encoding="utf-8")
    assert PUBLIC_KEY_HEX in src, "the anchor service verifies licenses against a different key"
