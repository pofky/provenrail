"""Offline commercial-license verification.

A Provenrail commercial license is a short, signed token. provenrail.com mints it when a
subscription goes active (the Polar webhook signs it with a private key we hold), and the
self-hosted server verifies it here with the matching PUBLIC key, which is embedded below and
ships in the open-source package. Verification is fully offline: no network call, nothing
phones home, so a licensed build works air-gapped and leaks nothing about the operator.

Token shape (the `prl_live_` prefix is the user-facing brand):

    prl_live_<base64url(payload_json)>.<base64url(ed25519_signature)>

The signature is over the ASCII bytes of the `<base64url(payload_json)>` segment, so we verify
the signature against exactly the bytes received and only then parse the payload. That makes
verification independent of JSON key order or whitespace: the signer's exact bytes are checked,
not a re-serialization of them.

Payload fields:
    account  the provenrail.com account id the license was issued to (informational)
    plan     one of plans.ORDER ("builder", "team", "enterprise")
    iat      issued-at, unix seconds
    exp      expiry, unix seconds, or null for non-expiring

Honesty note, load-bearing: this is a COMMERCIAL control, not DRM. The server is open-source
(AGPL); a determined operator can edit out this check. The signed license stops casual
self-upgrade (you cannot mint a higher tier without a key we signed); it does not, and is not
meant to, stop someone who patches the code. That is the correct enforcement ceiling for
open-core, and it is consistent with server/plans.py ("a commercial control, not a security
control"). The integrity guarantee never depends on any of this.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "prl_live_"

# The Provenrail license PUBLIC key (Ed25519, raw, hex). The matching private key lives only in
# the issuing service (a Supabase edge-function secret). Rotating it is a deliberate, breaking
# act: every previously issued license verifies against this exact key.
PUBLIC_KEY_HEX = "9ced1248464c8f884d4ff445b49e83089549505e5a49c01e8f33182f02c2ca73"

# Where `pr activate` persists a verified token so `pr serve` can pick it up without an env var.
LICENSE_FILE = Path.home() / ".config" / "provenrail" / "license"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class LicenseInfo:
    """The result of verifying a token. `valid` is the only field a caller must trust; the rest
    are informational and only meaningful when valid is True."""
    valid: bool
    plan: str | None = None
    account: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    reason: str | None = None  # human-readable failure cause when valid is False

    def __bool__(self) -> bool:
        # Without this, `if verify_license(token):` is always True, because a dataclass instance
        # is truthy. A licence check that silently passes for an invalid token is the worst
        # possible default, so truthiness is bound to `valid`.
        return self.valid


def sign_license(payload: dict, private_key_hex: str) -> str:
    """Mint a token. Used by tests and by any Python-side issuance; production issuance happens
    in the Polar webhook (Deno), which must produce byte-identical tokens."""
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    b64payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = sk.sign(b64payload.encode("ascii"))
    return PREFIX + b64payload + "." + _b64url_encode(sig)


def verify_license(token: str | None, *, public_key_hex: str | None = None,
                   now: int | None = None) -> LicenseInfo:
    """Verify a token offline. Returns LicenseInfo(valid=False, reason=...) on any problem
    (wrong prefix, malformed, bad signature, expired); never raises on bad input. The public key
    is resolved at call time (module PUBLIC_KEY_HEX unless overridden), so it stays patchable."""
    pk_hex = public_key_hex or PUBLIC_KEY_HEX
    if not token or not token.startswith(PREFIX):
        return LicenseInfo(False, reason="not a Provenrail license key")
    body = token[len(PREFIX):]
    if body.count(".") != 1:
        return LicenseInfo(False, reason="malformed license key")
    b64payload, b64sig = body.split(".", 1)
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        pub.verify(_b64url_decode(b64sig), b64payload.encode("ascii"))
    except (InvalidSignature, ValueError):
        return LicenseInfo(False, reason="license signature does not verify")
    try:
        payload = json.loads(_b64url_decode(b64payload))
    except (ValueError, json.JSONDecodeError):
        return LicenseInfo(False, reason="license payload is unreadable")
    plan = payload.get("plan")
    exp = payload.get("exp")
    if exp is not None:
        current = now if now is not None else int(datetime.now(UTC).timestamp())
        if current > int(exp):
            return LicenseInfo(False, plan=plan, account=payload.get("account"),
                               issued_at=payload.get("iat"), expires_at=exp,
                               reason="license expired")
    return LicenseInfo(True, plan=plan, account=payload.get("account"),
                       issued_at=payload.get("iat"), expires_at=exp)


def load_license_token() -> str | None:
    """Resolve a license token for the server: the PROVENRAIL_LICENSE env var first, then the
    file written by `pr activate`. Returns None if neither is present."""
    env = os.environ.get("PROVENRAIL_LICENSE", "").strip()
    if env:
        return env
    try:
        text = LICENSE_FILE.read_text(encoding="utf-8").strip()
        return text or None
    except OSError:
        return None


def save_license_token(token: str) -> Path:
    """Persist a token for `pr serve` to load later. Returns the path written."""
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_FILE.write_text(token.strip() + "\n", encoding="utf-8")
    LICENSE_FILE.chmod(0o600)
    return LICENSE_FILE
