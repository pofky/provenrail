"""Selective-disclosure redaction: commit now, disclose or erase later.

The tension this resolves: an audit trail must be immutable, but privacy law (GDPR Art. 17
right to erasure, HIPAA minimum-necessary) requires that specific personal data be removable or
withheld. A plain immutable log cannot do both. This module lets a field be recorded as a
salted cryptographic commitment instead of cleartext:

  - the signed, hash-chained record commits to the field (binding: you cannot later claim it
    held a different value), but contains NO cleartext;
  - the opening (the value plus a high-entropy secret salt) lives in an operator-held keystore
    that is NEVER sent to the sink;
  - to DISCLOSE the field to an auditor, the operator reveals its opening and anyone recomputes
    the commitment and confirms it matches the immutable record;
  - to ERASE the field (right to erasure), the operator destroys the opening. The commitment
    remains in the record so the trail stays complete and verifiable, but the value is
    permanently unrecoverable: the secret salt makes the commitment non-reversible even for a
    low-entropy value.

Scheme: commit = SHA-256( salt_bytes || canonicalize(value) ), salt = 32 random bytes. This is a
standard hiding+binding hash commitment. Canonicalization is the same JCS+NFC used everywhere, so
the Python and JavaScript verifiers agree byte for byte.

Honest boundary: erasure is cryptographic, not a guarantee that no copy was ever made elsewhere
(a discloser who already saw the value still knows it). It guarantees the SINK never held the
cleartext and that, once the opening is destroyed, the record itself no longer reveals it.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from .canonical import canonicalize

MARKER = "__fr_redacted__"
ALG = "sha256"
SCHEMA_V = 1


class Redactable:
    """A wrapper marking a value to be recorded as a commitment, not cleartext. Use
    `provenrail.redactable(value)` anywhere in a recorded request/response/args/result."""

    __slots__ = ("value",)

    def __init__(self, value: Any):
        self.value = value

    def __repr__(self) -> str:  # never leak the value in logs/reprs
        return "Redactable(<hidden>)"


def redactable(value: Any) -> Redactable:
    return Redactable(value)


def new_salt() -> str:
    return secrets.token_bytes(32).hex()


def commit(value: Any, salt_hex: str) -> str:
    """commit = SHA-256(salt || canonicalize(value)). Raises if value is not canonicalizable."""
    return hashlib.sha256(bytes.fromhex(salt_hex) + canonicalize(value)).hexdigest()


def commitment_obj(commit_hex: str) -> dict[str, Any]:
    return {MARKER: {"v": SCHEMA_V, "alg": ALG, "commit": commit_hex}}


def is_commitment(obj: Any) -> bool:
    return (isinstance(obj, dict) and set(obj.keys()) == {MARKER}
            and isinstance(obj[MARKER], dict) and isinstance(obj[MARKER].get("commit"), str))


def commit_of(obj: Any) -> str:
    return obj[MARKER]["commit"]


def verify_opening(commit_hex: str, value: Any, salt_hex: str) -> bool:
    try:
        return commit(value, salt_hex) == commit_hex
    except Exception:
        return False


def extract(value: Any, openings: dict[str, Any]) -> Any:
    """Return a copy of value with every Redactable replaced by its commitment object, recording
    each opening in `openings` keyed by the commitment hash. Commitment hashes are unique (salted),
    so the key needs no path or record id. Non-Redactable values pass through unchanged."""
    if isinstance(value, Redactable):
        salt = new_salt()
        c = commit(value.value, salt)
        openings[c] = {"alg": ALG, "salt": salt, "value": value.value}
        return commitment_obj(c)
    if isinstance(value, dict):
        return {k: extract(v, openings) for k, v in value.items()}
    if isinstance(value, list):
        return [extract(v, openings) for v in value]
    return value


def contains_commitment(value: Any) -> bool:
    if is_commitment(value):
        return True
    if isinstance(value, dict):
        return any(contains_commitment(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_commitment(v) for v in value)
    return False


def redacted_skeleton(value: Any) -> Any:
    """Keep the structure and every commitment in place, but drop non-redacted leaf content
    (replace with None). Used so a redactable field's commitment is retained in the stored record
    even under store-hash-not-content, WITHOUT leaking the non-redacted siblings as cleartext. The
    record hash is still computed over the full value, so a later disclosure still verifies."""
    if is_commitment(value):
        return value
    if isinstance(value, dict):
        return {k: redacted_skeleton(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redacted_skeleton(v) for v in value]
    return None


def walk_commitments(payload: Any) -> list[str]:
    """Return every commitment hash present anywhere in a payload."""
    found: list[str] = []

    def rec(o: Any) -> None:
        if is_commitment(o):
            found.append(commit_of(o))
            return
        if isinstance(o, dict):
            for v in o.values():
                rec(v)
        elif isinstance(o, list):
            for v in o:
                rec(v)

    rec(payload)
    return found


def disclose(payload: Any, openings: dict[str, Any]) -> Any:
    """Return a copy of payload with each commitment replaced by its disclosed value when a
    valid opening is supplied, or by a {"__withheld__": <commit prefix>} marker when it is not
    (redacted or erased). A supplied-but-invalid opening is left withheld, never substituted."""
    def rec(o: Any) -> Any:
        if is_commitment(o):
            c = commit_of(o)
            op = openings.get(c)
            if op is not None and verify_opening(c, op.get("value"), op.get("salt", "")):
                return op["value"]
            return {"__withheld__": c[:16]}
        if isinstance(o, dict):
            return {k: rec(v) for k, v in o.items()}
        if isinstance(o, list):
            return [rec(v) for v in o]
        return o

    return rec(payload)
