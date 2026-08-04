"""Device signing identity (Ed25519).

Honesty note: this is a static device key, NOT a forward-secure key. Forward security
(past records stay unforgeable after key theft) is a Tier-2 / managed-topology property
and is intentionally out of scope for the Provenrail MVP. The MVP's teeth come from
the off-box append-only server receipt chain (see server/storage.py), not from this key.
The client signature lets a verifier confirm records were produced by the holder of this
device key and were not altered in flight before reaching the sink.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class SigningKey:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: str | Path) -> SigningKey:
        p = Path(path)
        _warn_if_world_readable(p)
        data = p.read_bytes()
        return cls(serialization.load_pem_private_key(data, password=None))

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_bytes(self.to_pem().encode("utf-8"))
        p.chmod(0o600)

    def to_pem(self) -> str:
        """Serialize the private key as a PKCS8 PEM string (for at-rest persistence)."""
        return self._sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @classmethod
    def from_pem(cls, pem: str) -> SigningKey:
        return cls(serialization.load_pem_private_key(pem.encode("utf-8"), password=None))

    def sign(self, data: bytes) -> str:
        return self._sk.sign(data).hex()

    def public_key_hex(self) -> str:
        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()


def _warn_if_world_readable(path: Path) -> None:
    """Warn if the device key is readable by group/other. The key is the agent's identity;
    anyone who can read it can sign records as this agent, so loose permissions are a real
    weakness. Best-effort and POSIX-only; silently skipped where mode bits do not apply."""
    import os
    import stat
    import warnings
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if not hasattr(os, "geteuid"):  # non-POSIX (Windows): mode bits are not meaningful
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.warn(
            f"signing key {path} is accessible to group/other (mode {oct(mode & 0o777)}); "
            f"anyone who can read it can forge this agent's signature. Run: chmod 600 {path}",
            stacklevel=3,
        )


def verify_signature(public_key_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False
