"""Deterministic canonicalization for hashing and signing.

JCS-compatible (RFC 8785) for the constrained record schema this product uses:
  - object keys sorted (ASCII field names only, so code-point order == UTF-16 order)
  - compact separators, no insignificant whitespace
  - non-ASCII string *values* preserved as raw UTF-8 (JCS does not escape them)

Red-team hardening:
  - floats are REJECTED (IEEE-754 serialization differs across language verifiers).
  - integers outside the JS safe range must be passed as strings (callers do this for
    ids/tokens). Small control integers (e.g. seq) are exact in every JSON impl.
  - all strings (object keys and values) are Unicode NFC-normalized before serialization.
    RFC 8785 assumes already-normalized input; we enforce it so the same logical text
    (e.g. precomposed vs decomposed accents) cannot hash two different ways across
    producers. Producer and verifier share this module, so the form is always consistent.
Any value that cannot be canonicalized deterministically raises CanonicalError, so a
record can never be silently hashed two different ways.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

JS_SAFE_INT_MAX = 2**53 - 1


def _nfc(value: Any) -> Any:
    """Recursively NFC-normalize every string (keys and values). Non-strings pass through."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", k) if isinstance(k, str) else k: _nfc(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_nfc(v) for v in value]
    return value


class CanonicalError(ValueError):
    """Raised when a value cannot be canonicalized deterministically."""


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool):  # bool before int (bool is a subclass of int)
        return
    if isinstance(value, float):
        raise CanonicalError(
            f"float at {path}: floats are not allowed in records "
            f"(use a string for exact cross-verifier hashing)"
        )
    if isinstance(value, int):
        if abs(value) > JS_SAFE_INT_MAX:
            raise CanonicalError(
                f"integer {value} at {path} exceeds the JS-safe range; "
                f"pass it as a string for portable hashing"
            )
        return
    if value is None or isinstance(value, str):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"non-string key at {path}: {k!r}")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalError(f"unsupported type {type(value).__name__} at {path}")


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 byte serialization of a JSON-compatible value."""
    _check(value)
    value = _nfc(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value: Any) -> str:
    """Canonicalize then SHA-256, returning hex digest."""
    return sha256_hex(canonicalize(value))
