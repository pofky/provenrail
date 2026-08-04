"""External anchoring of the server receipt-chain head.

Anchoring bounds the tamper window: anything anchored cannot be rewritten without
the anchor failing to verify. We anchor a Merkle root over a batch of receipt hashes.

Two backends:
  - RFC3161Anchor: real trusted timestamp from a TSA (FreeTSA by default). The TSA
    genTime is authoritative wall-clock; the verifier flags client ts_utc that trails it.
  - LocalAnchor: offline/dev anchor signed by a separate "anchor key". Carries NO
    third-party trust; used for tests and air-gapped runs. Clearly labelled in output.

Merkle construction follows RFC 6962 domain separation (0x00 leaf / 0x01 node) so the
inclusion proofs are interoperable with standard transparency tooling.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def merkle_root(leaves_hex: list[str]) -> str:
    if not leaves_hex:
        return "0" * 64
    level = [_leaf(bytes.fromhex(h)) for h in leaves_hex]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote odd leaf (RFC 6962)
        level = nxt
    return level[0].hex()


@dataclass
class AnchorReceipt:
    kind: str            # "rfc3161" | "local"
    merkle_root: str
    gen_time: str        # ISO UTC, authoritative wall-clock upper bound
    token_b64: str | None = None   # RFC3161 token (base64) when kind == rfc3161
    signature: str | None = None   # local anchor signature when kind == local
    anchor_pubkey: str | None = None
    tsa_url: str | None = None


class Anchor(Protocol):
    def anchor(self, leaves_hex: list[str]) -> AnchorReceipt: ...


class LocalAnchor:
    """Offline anchor signed by a dedicated key held outside the agent process."""

    def __init__(self, signing_key=None):
        from .keys import SigningKey  # local import to avoid hard dep at module load
        self._key = signing_key or SigningKey.generate()

    def anchor(self, leaves_hex: list[str]) -> AnchorReceipt:
        root = merkle_root(leaves_hex)
        gen_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        sig = self._key.sign((root + "|" + gen_time).encode("utf-8"))
        return AnchorReceipt(
            kind="local",
            merkle_root=root,
            gen_time=gen_time,
            signature=sig,
            anchor_pubkey=self._key.public_key_hex(),
        )


class RFC3161Anchor:
    """Trusted timestamp anchor. Defaults to FreeTSA; any RFC 3161 TSA URL works."""

    def __init__(self, tsa_url: str = "https://freetsa.org/tsr", timeout: float = 10.0):
        self.tsa_url = tsa_url
        self.timeout = timeout

    def anchor(self, leaves_hex: list[str]) -> AnchorReceipt:
        import base64

        import httpx
        from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response

        root = merkle_root(leaves_hex)
        req = TimestampRequestBuilder().data(bytes.fromhex(root)).build()
        resp = httpx.post(
            self.tsa_url,
            content=req.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        tst = decode_timestamp_response(resp.content)
        gen_time = tst.tst_info.gen_time.astimezone(UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        return AnchorReceipt(
            kind="rfc3161",
            merkle_root=root,
            gen_time=gen_time,
            token_b64=base64.b64encode(resp.content).decode("ascii"),
            tsa_url=self.tsa_url,
        )


class MultiTSAAnchor:
    """Anchor against a list of TSAs, using the first that responds (availability failover).

    This is robustness, not multi-proof: each receipt still carries one RFC 3161 token, and the
    verifier still validates exactly one trusted timestamp. What it buys is that a single TSA
    being down, rate-limiting, or rotating its root no longer stalls anchoring, since the next
    TSA in the list takes over. If every TSA fails, the last error is raised so the caller can
    fall back to a LocalAnchor (amber) or retry later.

    True multi-token cross-TSA anchoring (a quorum of independent timestamps per anchor) is a
    larger change to the receipt and commitment format and is intentionally not bundled here.
    """

    def __init__(self, tsa_urls: list[str], timeout: float = 10.0, _factory=None):
        if not tsa_urls:
            raise ValueError("MultiTSAAnchor needs at least one TSA URL")
        self.tsa_urls = list(tsa_urls)
        # _factory(url) -> an object with .anchor(leaves_hex); injectable for tests.
        self._factory = _factory or (lambda url: RFC3161Anchor(url, timeout))

    def anchor(self, leaves_hex: list[str]) -> AnchorReceipt:
        last_error: Exception | None = None
        for url in self.tsa_urls:
            try:
                return self._factory(url).anchor(leaves_hex)
            except Exception as e:  # try the next TSA; only the final failure propagates
                last_error = e
        raise RuntimeError(
            f"all {len(self.tsa_urls)} TSAs failed to timestamp; last error: {last_error}")
