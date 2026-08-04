"""Client-side hash chain over agent activity records.

Each record links to the previous via ``prev_hash`` (the previous record's
``record_hash``), carries a monotonic ``seq``, and is signed with the device key.
A session opens with a genesis record (prev_hash = GENESIS) and closes with a seal
record carrying ``session_hash`` = hash of the ordered list of all record hashes.

This chain detects in-flight tampering and reordering *by the client*. It is the
first of two chains; the server independently re-chains records on arrival
(server/storage.py) so a hostile agent cannot delete or reorder what already landed.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import GENESIS_PREV_HASH
from .canonical import canonicalize, sha256_hex
from .keys import SigningKey, verify_signature

SCHEMA_VERSION = "1"

# action types
GENESIS = "lifecycle.session_start"
SEAL = "lifecycle.session_end"
HEARTBEAT = "lifecycle.heartbeat"
MODEL_CALL = "model_call"
TOOL_CALL = "tool_call"
MCP_CALL = "mcp_call"
DECISION = "decision"
DATA_ACCESS = "data_access"
HUMAN_OVERSIGHT = "human_oversight"
POLICY_DECISION = "policy.decision"


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record_content(rec: dict[str, Any]) -> dict[str, Any]:
    """The signed/hashed subset: everything except the derived hash and signature."""
    return {k: v for k, v in rec.items() if k not in ("record_hash", "record_sig")}


def compute_record_hash(rec: dict[str, Any]) -> str:
    return sha256_hex(canonicalize(record_content(rec)))


@dataclass
class Chain:
    stream_id: str
    key: SigningKey
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    _seq: int = 0
    _last_hash: str = GENESIS_PREV_HASH
    _hashes: list[str] = field(default_factory=list)
    _open: bool = False
    _clock: Callable[[], str] = _utc_now_iso
    _idgen: Callable[[], str] = lambda: str(uuid.uuid4())

    def _emit(self, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        content = {
            "v": SCHEMA_VERSION,
            "stream_id": self.stream_id,
            "session_id": self.session_id,
            "record_id": self._idgen(),
            "seq": self._seq,
            "prev_hash": self._last_hash,
            "ts_utc": self._clock(),
            "pubkey": self.key.public_key_hex(),
            "action_type": action_type,
            "payload": payload,
        }
        canon = canonicalize(content)
        rec = dict(content)
        rec["record_hash"] = sha256_hex(canon)
        rec["record_sig"] = self.key.sign(canon)
        self._seq += 1
        self._last_hash = rec["record_hash"]
        self._hashes.append(rec["record_hash"])
        return rec

    def start(self, meta: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._open or self._seq != 0:
            raise RuntimeError("session already started")
        self._open = True
        return self._emit(GENESIS, {"meta": meta or {}})

    def append(self, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._open:
            raise RuntimeError("session not started")
        if action_type in (GENESIS, SEAL):
            raise ValueError(f"{action_type} is emitted by start()/seal(), not append()")
        return self._emit(action_type, payload)

    def heartbeat(self) -> dict[str, Any]:
        if not self._open:
            raise RuntimeError("session not started")
        return self._emit(HEARTBEAT, {})

    def seal(self, outcome: str = "success", trigger: str = "normal") -> dict[str, Any]:
        if not self._open:
            raise RuntimeError("session not started")
        # session_hash covers every record hash emitted so far, in order.
        session_hash = sha256_hex(canonicalize(self._hashes))
        rec = self._emit(
            SEAL,
            {"outcome": outcome, "trigger": trigger, "count": str(self._seq), "session_hash": session_hash},
        )
        self._open = False
        return rec


# ---- verification helpers (used by the standalone verifier) ----


@dataclass
class ChainIssue:
    seq: int | None
    record_id: str | None
    code: str
    detail: str


def verify_client_chain(records: list[dict[str, Any]]) -> list[ChainIssue]:
    """Verify a full ordered list of client records. Returns a list of issues (empty == valid)."""
    issues: list[ChainIssue] = []
    if not records:
        return [ChainIssue(None, None, "empty", "no records")]

    expected_prev = GENESIS_PREV_HASH
    expected_seq = 0
    pubkey0 = records[0].get("pubkey")

    for rec in records:
        seq = rec.get("seq")
        rid = rec.get("record_id")

        # recompute hash
        recomputed = compute_record_hash(rec)
        if recomputed != rec.get("record_hash"):
            issues.append(ChainIssue(seq, rid, "hash_mismatch",
                                     "record_hash does not match content (record altered)"))
        # signature
        if not verify_signature(rec.get("pubkey", ""), canonicalize(record_content(rec)),
                                rec.get("record_sig", "")):
            issues.append(ChainIssue(seq, rid, "bad_signature", "signature invalid"))
        # key continuity (all records in a session share one device key)
        if rec.get("pubkey") != pubkey0:
            issues.append(ChainIssue(seq, rid, "key_changed", "device pubkey changed mid-stream"))
        # sequence continuity (gap detection)
        if seq != expected_seq:
            issues.append(ChainIssue(seq, rid, "seq_gap",
                                     f"expected seq {expected_seq}, got {seq} (missing/reordered records)"))
        # link continuity
        if rec.get("prev_hash") != expected_prev:
            issues.append(ChainIssue(seq, rid, "broken_link",
                                     "prev_hash does not match previous record_hash (deletion/insertion)"))

        expected_prev = rec.get("record_hash")
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1

    # lifecycle sanity
    if records[0].get("action_type") != GENESIS:
        issues.append(ChainIssue(0, records[0].get("record_id"), "no_genesis",
                                 "first record is not a session_start"))
    # seal must cover exactly the hashes of every record emitted before it, in order.
    seals = [r for r in records if r.get("action_type") == SEAL]
    if seals:
        seal = seals[-1]
        seal_seq = seal.get("seq")
        if isinstance(seal_seq, int):
            covered = [r.get("record_hash") for r in records if isinstance(r.get("seq"), int)
                       and r.get("seq") < seal_seq]
            expect = sha256_hex(canonicalize(covered))
            if seal.get("payload", {}).get("session_hash") != expect:
                issues.append(ChainIssue(seal_seq, seal.get("record_id"), "bad_session_hash",
                                         "seal session_hash does not cover the record set (truncation)"))
    return issues
