"""OpenTimestamps (Bitcoin) proof parsing and offline verification.

An OpenTimestamps proof (`.ots`) is a chain of operations that transforms a starting digest
(the SHA-256 of the data you timestamped) through appends, prepends, and hashes until it reaches
the Merkle root of a Bitcoin block, attested by a "Bitcoin block header attestation" that records
the block height. Verifying it offline is purely mechanical:

  1. replay the operations from your data digest;
  2. at each Bitcoin attestation, the value you have reached IS the claimed Merkle root of that
     block height;
  3. confirm that Merkle root against a Bitcoin block header you trust (your own node, or a header
     you pin). If it matches, your data provably existed before that block was mined, anchored in
     the most expensive-to-rewrite ledger in existence and depending on no party we control.

This module parses the C2SP/OpenTimestamps binary format faithfully (the serialization is frozen
upstream and cross-checked against the reference `opentimestamps` library in tests/test_ots.py)
and verifies it with the standard library only, so the verifier stays dependency-light. It does
NOT fetch Bitcoin headers or talk to calendar servers; that is the job of the (network) anchoring
path. Verification here is the part that must be reproducible offline, and it is.

What an OTS proof does and does not prove: it proves the data digest existed before a Bitcoin
block was mined (proof of existence / anti-backdating). It says nothing about completeness, and a
proof that only carries "pending" calendar attestations is not yet confirmed in Bitcoin.
"""

from __future__ import annotations

import hashlib
from typing import Any

# The 31-byte magic that opens every detached .ots file.
HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
_MAJOR_VERSION = 1

# Attestation type tags (8 bytes each).
_TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
_TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
_TAG_LITECOIN = bytes.fromhex("06869a0d73d71b45")
_ATTESTATION_TAG_SIZE = 8

# Operation tags.
_OP_SHA1 = 0x02
_OP_RIPEMD160 = 0x03
_OP_SHA256 = 0x08
_OP_KECCAK256 = 0x67
_OP_APPEND = 0xF0
_OP_PREPEND = 0xF1
_OP_REVERSE = 0xF2
_OP_HEXLIFY = 0xF3

_CRYPT_DIGEST_LEN = {_OP_SHA1: 20, _OP_RIPEMD160: 20, _OP_SHA256: 32, _OP_KECCAK256: 32}
_MAX_RESULT_LENGTH = 4096
_MAX_PAYLOAD_SIZE = 8192
_RECURSION_LIMIT = 256


class OtsError(Exception):
    """Raised on a malformed proof. Verification fails closed; it never trusts partial input."""


class _Reader:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes) -> None:
        self.b = b
        self.i = 0

    def read(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise OtsError("truncated OTS proof")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def varuint(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self.read(1)[0]
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return value
            shift += 7
            if shift > 63:
                raise OtsError("varuint too large")

    def varbytes(self, max_len: int, min_len: int = 0) -> bytes:
        n = self.varuint()
        if n > max_len:
            raise OtsError("varbytes too long")
        if n < min_len:
            raise OtsError("varbytes too short")
        return self.read(n)

    def at_eof(self) -> bool:
        return self.i >= len(self.b)


def _apply_crypt(tag: int, msg: bytes) -> bytes:
    if tag == _OP_SHA256:
        return hashlib.sha256(msg).digest()
    if tag == _OP_SHA1:
        return hashlib.sha1(msg).digest()
    if tag == _OP_RIPEMD160:
        try:
            return hashlib.new("ripemd160", msg).digest()
        except Exception as e:  # noqa: BLE001 - some OpenSSL builds disable ripemd160
            raise OtsError("ripemd160 unavailable in this build") from e
    raise OtsError(f"unsupported crypto op 0x{tag:02x}")


class _Acc:
    """Accumulates the attestations a walk reaches, each bound to the digest reached at its node."""

    def __init__(self) -> None:
        self.bitcoin: list[dict[str, Any]] = []
        self.pending: list[str] = []
        self.litecoin: list[dict[str, Any]] = []


def _parse_attestation(reader: _Reader, msg: bytes, acc: _Acc) -> None:
    tag = reader.read(_ATTESTATION_TAG_SIZE)
    payload = reader.varbytes(_MAX_PAYLOAD_SIZE)
    pr = _Reader(payload)
    if tag == _TAG_BITCOIN:
        height = pr.varuint()
        # The digest reached at this node is the block's Merkle root (internal byte order).
        acc.bitcoin.append({"height": height, "merkle_root_hex": msg.hex()})
    elif tag == _TAG_LITECOIN:
        height = pr.varuint()
        acc.litecoin.append({"height": height, "merkle_root_hex": msg.hex()})
    elif tag == _TAG_PENDING:
        uri = pr.varbytes(_MAX_PAYLOAD_SIZE).decode("utf-8", "replace")
        acc.pending.append(uri)
    # Unknown attestation types are ignored (forward-compatible), exactly like the reference lib.


def _walk(reader: _Reader, msg: bytes, acc: _Acc, depth: int) -> None:
    """Mirror of opentimestamps Timestamp.deserialize: a tree of ops, attestations at the leaves."""
    if depth <= 0:
        raise OtsError("OTS recursion limit reached")

    def step(tag_byte: int) -> None:
        if tag_byte == 0x00:
            _parse_attestation(reader, msg, acc)
            return
        # An operation tag: compute the new message, then recurse on the child timestamp.
        if tag_byte in _CRYPT_DIGEST_LEN or tag_byte in (_OP_SHA1, _OP_RIPEMD160, _OP_SHA256):
            new_msg = _apply_crypt(tag_byte, msg)
        elif tag_byte == _OP_APPEND:
            new_msg = msg + reader.varbytes(_MAX_RESULT_LENGTH, min_len=1)
        elif tag_byte == _OP_PREPEND:
            new_msg = reader.varbytes(_MAX_RESULT_LENGTH, min_len=1) + msg
        elif tag_byte == _OP_REVERSE:
            new_msg = msg[::-1]
        elif tag_byte == _OP_HEXLIFY:
            new_msg = msg.hex().encode("ascii")
        else:
            raise OtsError(f"unsupported op 0x{tag_byte:02x}")
        if len(new_msg) > _MAX_RESULT_LENGTH:
            raise OtsError("op result too long")
        _walk(reader, new_msg, acc, depth - 1)

    tag = reader.read(1)[0]
    while tag == 0xFF:
        step(reader.read(1)[0])
        tag = reader.read(1)[0]
    step(tag)


def parse_ots(ots_bytes: bytes) -> dict[str, Any]:
    """Parse a detached .ots proof. Returns the file digest and every attestation reached.

    Raises OtsError on any malformation. Does not require network or a Bitcoin node."""
    reader = _Reader(ots_bytes)
    if reader.read(len(HEADER_MAGIC)) != HEADER_MAGIC:
        raise OtsError("not an OpenTimestamps proof (bad magic)")
    major = reader.varuint()
    if major != _MAJOR_VERSION:
        raise OtsError(f"unsupported OTS major version {major}")
    file_op = reader.read(1)[0]
    if file_op not in _CRYPT_DIGEST_LEN:
        raise OtsError(f"unsupported file hash op 0x{file_op:02x}")
    file_digest = reader.read(_CRYPT_DIGEST_LEN[file_op])
    acc = _Acc()
    _walk(reader, file_digest, acc, _RECURSION_LIMIT)
    if not reader.at_eof():
        raise OtsError("trailing bytes after OTS proof")
    return {
        "file_digest_hex": file_digest.hex(),
        "file_hash_op": file_op,
        "bitcoin": acc.bitcoin,
        "litecoin": acc.litecoin,
        "pending": acc.pending,
    }


def _root_matches(computed_hex: str, trusted_hex: str) -> bool:
    """A Bitcoin block header stores the Merkle root in internal (little-endian) byte order; block
    explorers display it reversed. Accept either so a caller can pass whichever they have."""
    c = computed_hex.lower()
    t = trusted_hex.lower()
    if c == t:
        return True
    return bytes.fromhex(c)[::-1].hex() == t


def verify_ots(ots_bytes: bytes, data_hex: str, *,
               bitcoin_block_merkle_roots: dict[int, str] | None = None) -> dict[str, Any]:
    """Verify an OTS proof offline against the data it should commit to.

    `data_hex` is the SHA-256 of the data you timestamped (it must equal the proof's file digest).
    `bitcoin_block_merkle_roots` optionally maps block height -> that block's Merkle root (from a
    Bitcoin node or a pinned header); when supplied, a Bitcoin attestation is *confirmed* only if
    the replayed root matches the trusted root for its height.

    Returns a verdict dict. `ok` is True only when the data matches and at least one Bitcoin
    attestation is confirmed against a supplied trusted header. With no headers supplied, the proof
    can still be reported as structurally valid and Bitcoin-attested (the caller then checks the
    reported root against the chain) but `ok` stays False, because we will not assert a Bitcoin
    fact we did not check."""
    verdict: dict[str, Any] = {
        "ok": False, "structurally_valid": False, "data_matches": False,
        "file_digest_hex": None, "bitcoin_attested": False, "bitcoin": [],
        "pending": [], "error": None,
    }
    try:
        parsed = parse_ots(ots_bytes)
    except OtsError as e:
        verdict["error"] = str(e)
        return verdict
    verdict["structurally_valid"] = True
    verdict["file_digest_hex"] = parsed["file_digest_hex"]
    verdict["data_matches"] = parsed["file_digest_hex"].lower() == (data_hex or "").lower()
    verdict["pending"] = parsed["pending"]

    roots = bitcoin_block_merkle_roots or {}
    confirmed_any = False
    for att in parsed["bitcoin"]:
        height = att["height"]
        trusted = roots.get(height)
        confirmed = None
        if trusted is not None:
            confirmed = _root_matches(att["merkle_root_hex"], trusted)
            confirmed_any = confirmed_any or confirmed
        verdict["bitcoin"].append({
            "height": height,
            "merkle_root_hex": att["merkle_root_hex"],
            "confirmed": confirmed,
        })
    verdict["bitcoin_attested"] = bool(parsed["bitcoin"])
    verdict["ok"] = bool(verdict["data_matches"] and confirmed_any)
    return verdict
