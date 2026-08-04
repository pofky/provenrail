"""OIDC single sign-on: validate an IdP-issued ID token and map it to an org member.

This is an API-first SSO: the org configures its IdP (issuer, audience, JWKS), the user
authenticates with the IdP however they normally do, and presents the resulting ID token (a
JWT) to Provenrail, which validates it and issues a member key. That covers the
procurement requirement ("our staff log in with our IdP, we do not manage a second set of
credentials") without Provenrail running a browser redirect flow.

Security posture (this is the sensitive part, so it is deliberately strict):
  - Algorithm allowlist only: RS256 and EdDSA. "none" and HMAC algs are rejected outright, so
    there is no alg-confusion or unsigned-token bypass.
  - The signing key is selected from the configured JWKS by kid and key type; an attacker
    cannot smuggle their own key in the token header.
  - issuer, audience, and expiry are all validated; a small clock skew is tolerated.
There is no external network call here: the JWKS is configured per org (fetched and pinned out
of band), so validation is hermetic and offline-testable.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

_ALLOWED_ALGS = {"RS256", "EdDSA"}
_CLOCK_SKEW_S = 60


class SSOError(Exception):
    """An ID token failed validation. The message is safe to surface (no secrets)."""


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_int(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def _select_jwk(jwks: dict[str, Any], kid: str | None, alg: str) -> dict[str, Any]:
    keys = jwks.get("keys", [])
    want_kty = "RSA" if alg == "RS256" else "OKP"
    candidates = [k for k in keys if k.get("kty") == want_kty]
    if kid is not None:
        candidates = [k for k in candidates if k.get("kid") == kid] or candidates
    if not candidates:
        raise SSOError("no matching key in the configured JWKS for this token")
    return candidates[0]


def _verify_signature(alg: str, jwk: dict[str, Any], signing_input: bytes, sig: bytes) -> None:
    try:
        if alg == "RS256":
            pub = RSAPublicNumbers(_b64url_int(jwk["e"]), _b64url_int(jwk["n"])).public_key()
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:  # EdDSA (Ed25519)
            pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
            pub.verify(sig, signing_input)
    except InvalidSignature as e:
        raise SSOError("ID token signature is invalid") from e
    except Exception as e:
        raise SSOError(f"ID token signature could not be checked: {e}") from e


def verify_id_token(token: str, *, jwks: dict[str, Any], issuer: str, audience: str,
                    now: int) -> dict[str, Any]:
    """Validate a JWT ID token and return its claims, or raise SSOError.

    `now` is a posix timestamp (injected so the check is deterministic in tests)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise SSOError("malformed JWT (expected three dot-separated segments)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
    except Exception as e:
        raise SSOError("JWT segments are not valid base64url JSON") from e

    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise SSOError(f"algorithm {alg!r} is not allowed (only RS256 and EdDSA)")
    jwk = _select_jwk(jwks, header.get("kid"), alg)
    _verify_signature(alg, jwk, f"{parts[0]}.{parts[1]}".encode("ascii"), sig)

    if claims.get("iss") != issuer:
        raise SSOError("token issuer does not match the configured IdP")
    aud = claims.get("aud")
    aud_ok = audience == aud or (isinstance(aud, list) and audience in aud)
    if not aud_ok:
        raise SSOError("token audience does not match this application")
    exp = claims.get("exp")
    if not isinstance(exp, int) or now > exp + _CLOCK_SKEW_S:
        raise SSOError("token is expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, int) and now + _CLOCK_SKEW_S < nbf:
        raise SSOError("token is not yet valid")
    if not claims.get("email") and not claims.get("sub"):
        raise SSOError("token has neither an email nor a sub claim to identify the user")
    return claims
