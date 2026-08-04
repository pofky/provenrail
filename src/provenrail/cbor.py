"""Minimal, dependency-free canonical CBOR (RFC 8949) codec.

Only the subset Provenrail needs for COSE_Sign1 SCITT receipts: unsigned/negative
integers, byte strings, text strings, arrays, definite-length maps, null, and CBOR tags.
Encoding follows RFC 8949 section 4.2.1 "Core Deterministic Encoding": shortest-form
integers/lengths, definite lengths, and map keys sorted by their encoded byte
representation. The codec is deliberately small so it can be audited and is proven
byte-for-byte against the reference `cbor2` library in the test suite (tests/test_cbor.py).

We hand-roll this rather than depend on cbor2 at runtime so the verifier stays
dependency-light (stdlib + cryptography only) and the on-wire bytes are fully under our
control and frozen in SPEC.md.
"""

from __future__ import annotations

from typing import Any


class CBORTag:
    """A CBOR tagged value (major type 6). `tag` is the tag number, `value` the content."""

    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value: Any) -> None:
        self.tag = tag
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CBORTag) and other.tag == self.tag and other.value == self.value

    def __repr__(self) -> str:
        return f"CBORTag({self.tag}, {self.value!r})"


def _head(major: int, n: int) -> bytes:
    """Encode an initial byte + argument for major type `major` and unsigned value `n`."""
    mt = major << 5
    if n < 24:
        return bytes([mt | n])
    if n < 0x100:
        return bytes([mt | 24, n])
    if n < 0x10000:
        return bytes([mt | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([mt | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([mt | 27]) + n.to_bytes(8, "big")
    raise ValueError("integer too large for CBOR")


def encode(value: Any) -> bytes:
    """Canonical-CBOR encode a Python value. bool is rejected (ambiguous with int here)."""
    if value is None:
        return b"\xf6"  # null
    if value is True or value is False:
        raise TypeError("encode bools explicitly via CBOR simple values if ever needed")
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)  # negative int: argument is -1-n
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(value, list):
        out = _head(4, len(value))
        for item in value:
            out += encode(item)
        return out
    if isinstance(value, dict):
        items = [(encode(k), encode(v)) for k, v in value.items()]
        # Core deterministic ordering: sort by the encoded key bytes (RFC 8949 4.2.1).
        items.sort(key=lambda kv: kv[0])
        out = _head(5, len(items))
        for ek, ev in items:
            out += ek + ev
        return out
    if isinstance(value, CBORTag):
        return _head(6, value.tag) + encode(value.value)
    raise TypeError(f"unsupported CBOR type: {type(value).__name__}")


# Hard cap on nesting depth. A hostile receipt could otherwise nest arrays/maps
# thousands deep and exhaust the Python C stack (RecursionError, or a hard crash on
# interpreters without the recursion guard). Real SCITT receipts nest only a handful of
# levels; 64 is far above any legitimate document and well below the interpreter limit.
_MAX_DEPTH = 64


def _need(data: bytes, i: int, n: int) -> None:
    """Raise unless `n` bytes remain at offset `i`. Prevents Python's silent slice
    truncation (data[i:i+n] returns fewer bytes than asked) from yielding a wrong value."""
    if i + n > len(data):
        raise ValueError("truncated CBOR")


def _decode(data: bytes, i: int, depth: int = 0) -> tuple[Any, int]:
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    if i >= len(data):
        raise ValueError("truncated CBOR")
    ib = data[i]
    major = ib >> 5
    ai = ib & 0x1F
    i += 1
    if ai < 24:
        arg = ai
    elif ai == 24:
        _need(data, i, 1)
        arg = data[i]
        i += 1
    elif ai == 25:
        _need(data, i, 2)
        arg = int.from_bytes(data[i:i + 2], "big")
        i += 2
    elif ai == 26:
        _need(data, i, 4)
        arg = int.from_bytes(data[i:i + 4], "big")
        i += 4
    elif ai == 27:
        _need(data, i, 8)
        arg = int.from_bytes(data[i:i + 8], "big")
        i += 8
    else:
        # 28..30 reserved, 31 indefinite-length: not part of the canonical subset.
        raise ValueError(f"unsupported CBOR additional info {ai}")

    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major == 2:
        _need(data, i, arg)
        return data[i:i + arg], i + arg
    if major == 3:
        _need(data, i, arg)
        return data[i:i + arg].decode("utf-8"), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = _decode(data, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            k, i = _decode(data, i, depth + 1)
            v, i = _decode(data, i, depth + 1)
            out[k] = v
        return out, i
    if major == 6:
        v, i = _decode(data, i, depth + 1)
        return CBORTag(arg, v), i
    if major == 7:
        if arg == 22:
            return None, i
        raise ValueError(f"unsupported CBOR simple value {arg}")
    raise ValueError(f"unsupported CBOR major type {major}")


def decode(data: bytes) -> Any:
    """Decode a single CBOR item. Raises if there are trailing bytes."""
    value, i = _decode(data, 0)
    if i != len(data):
        raise ValueError("trailing bytes after CBOR item")
    return value
