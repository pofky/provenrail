"""Append-only sink with an independent server-side receipt chain.

The server re-chains every record on arrival, in arrival order, keyed only by data it
controls (its own recv_seq, recv_ts, and the bytes it received). This is the component
that gives Provenrail its teeth: even though the device key lives on the agent's
machine, once a record is accepted here a hostile agent cannot delete it, reorder it,
or back-date it without breaking the receipt chain, which the standalone verifier checks.

Append-only is enforced three ways: no UPDATE/DELETE routes exist in the API, write
tokens have no delete scope, and SQLite triggers abort UPDATE/DELETE. (Triggers are
defence-in-depth only; an attacker with the raw DB file can drop them. True immutability
against the host is the Audit Trail tier's cross-account WORM, out of scope for MVP.)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from typing import Any

from .. import GENESIS_PREV_HASH
from ..canonical import canonicalize, sha256_hex

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id    TEXT PRIMARY KEY,
    api_key_hash  TEXT NOT NULL UNIQUE,
    plan          TEXT NOT NULL DEFAULT 'free',
    created_at    TEXT NOT NULL,
    label         TEXT
);
CREATE TABLE IF NOT EXISTS streams (
    stream_id      TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    label          TEXT,
    owner_account  TEXT,
    last_anchor_seq INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS records (
    stream_id          TEXT NOT NULL,
    recv_seq           INTEGER NOT NULL,
    recv_ts            TEXT NOT NULL,
    recv_hash          TEXT NOT NULL,   -- sha256 of exact received record bytes
    server_prev_hash   TEXT NOT NULL,
    server_record_hash TEXT NOT NULL,   -- receipt-chain link
    client_record      TEXT NOT NULL,   -- full received record (JSON)
    PRIMARY KEY (stream_id, recv_seq)
);
CREATE TABLE IF NOT EXISTS anchors (
    stream_id     TEXT NOT NULL,
    anchor_seq    INTEGER NOT NULL,
    covers_up_to  INTEGER NOT NULL,   -- recv_seq of last record covered
    receipt       TEXT NOT NULL,      -- AnchorReceipt JSON
    PRIMARY KEY (stream_id, anchor_seq)
);
CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id    TEXT PRIMARY KEY,
    account_id    TEXT,
    url           TEXT NOT NULL,
    secret        TEXT NOT NULL,      -- HMAC signing secret (shown to operator once)
    events        TEXT NOT NULL,      -- comma-separated event types, '*' for all
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_state (
    stream_id        TEXT PRIMARY KEY,
    integrity_state  TEXT,            -- last observed verdict state (verified/amber/tampered)
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tlog_leaves (
    log_origin        TEXT NOT NULL,      -- per-account log shard the leaf belongs to
    leaf_index        INTEGER NOT NULL,   -- 0-based position within that shard
    anchor_stream_id  TEXT NOT NULL,
    anchor_seq        INTEGER NOT NULL,
    covers_up_to      INTEGER NOT NULL,
    anchor_commit     TEXT NOT NULL,      -- hex SHA-256 commitment to the anchor receipt
    leaf_hash         TEXT NOT NULL,      -- hex RFC 6962 leaf hash (with tlog domain label)
    added_at          TEXT NOT NULL,
    PRIMARY KEY (log_origin, leaf_index),
    UNIQUE (anchor_stream_id, anchor_seq)
);
CREATE TABLE IF NOT EXISTS tlog_checkpoints (
    log_origin         TEXT NOT NULL,
    tree_size          INTEGER NOT NULL,
    merkle_root        TEXT NOT NULL,     -- hex
    signed_note        TEXT NOT NULL,     -- full C2SP signed note (log sig + any cosigs)
    consistency_proof  TEXT,              -- JSON proof from the previous checkpoint size
    witnessed          INTEGER NOT NULL DEFAULT 0,  -- count of verified witness cosignatures
    status             TEXT NOT NULL DEFAULT 'final', -- final | pending_witness | witness_failed
    created_at         TEXT NOT NULL,
    PRIMARY KEY (log_origin, tree_size)
);
CREATE TABLE IF NOT EXISTS tlog_witness_state (
    witness_url        TEXT NOT NULL,
    log_origin         TEXT NOT NULL,
    last_cosigned_size INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (witness_url, log_origin)
);
CREATE TABLE IF NOT EXISTS server_meta (
    k             TEXT PRIMARY KEY,     -- e.g. tlog_log_key_pem, registry_key_pem
    v             TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
    account_id    TEXT NOT NULL,
    period        TEXT NOT NULL,        -- billing period, e.g. '2026-06' (UTC month)
    events        INTEGER NOT NULL DEFAULT 0,   -- records ingested this period
    anchors       INTEGER NOT NULL DEFAULT 0,   -- anchors taken this period
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (account_id, period)
);
CREATE TABLE IF NOT EXISTS oidc_config (
    account_id    TEXT PRIMARY KEY,
    issuer        TEXT NOT NULL,
    audience      TEXT NOT NULL,
    jwks          TEXT NOT NULL,        -- JSON JWKS, pinned out of band
    default_role  TEXT NOT NULL DEFAULT 'member',
    email_domain  TEXT,                 -- optional: only emails on this domain may log in
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_keys (
    account_id    TEXT NOT NULL,
    agent_id      TEXT NOT NULL,        -- stable agent name within the org
    pubkey        TEXT NOT NULL,        -- hex Ed25519 device public key
    status        TEXT NOT NULL DEFAULT 'active',  -- active | revoked
    registered_at TEXT NOT NULL,
    revoked_at    TEXT,
    PRIMARY KEY (account_id, agent_id, pubkey)
);
CREATE TABLE IF NOT EXISTS members (
    member_id     TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL,        -- the org this member belongs to
    api_key_hash  TEXT NOT NULL UNIQUE, -- the member's own key (sha-256 only)
    role          TEXT NOT NULL,        -- owner | admin | member | viewer
    label         TEXT,
    email         TEXT,
    status        TEXT NOT NULL DEFAULT 'active',  -- active | disabled
    created_at    TEXT NOT NULL,
    UNIQUE (account_id, email)
);
CREATE TABLE IF NOT EXISTS meta_audit (
    audit_seq     INTEGER NOT NULL,     -- per-account monotonic sequence
    account_id    TEXT NOT NULL,
    ts            TEXT NOT NULL,
    actor         TEXT NOT NULL,        -- member_id, or 'account_key' for the root key
    actor_role    TEXT,
    action        TEXT NOT NULL,        -- e.g. stream.export, member.invite, audit.read
    resource_type TEXT,
    resource_id   TEXT,
    detail        TEXT,                 -- JSON
    prev_hash     TEXT NOT NULL,        -- hash-chained so the access log is tamper-evident
    entry_hash    TEXT NOT NULL,
    PRIMARY KEY (account_id, audit_seq)
);
CREATE TRIGGER IF NOT EXISTS no_update_meta_audit BEFORE UPDATE ON meta_audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_meta_audit BEFORE DELETE ON meta_audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_update_records BEFORE UPDATE ON records
    BEGIN SELECT RAISE(ABORT, 'records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_records BEFORE DELETE ON records
    BEGIN SELECT RAISE(ABORT, 'records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_update_anchors BEFORE UPDATE ON anchors
    BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_anchors BEFORE DELETE ON anchors
    BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_update_tlog_leaves BEFORE UPDATE ON tlog_leaves
    BEGIN SELECT RAISE(ABORT, 'tlog leaves are append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_tlog_leaves BEFORE DELETE ON tlog_leaves
    BEGIN SELECT RAISE(ABORT, 'tlog leaves are append-only'); END;
CREATE INDEX IF NOT EXISTS idx_records_recv_hash ON records(stream_id, recv_hash);
"""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Storage:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        if path != ":memory:":
            # WAL improves read/write concurrency for the background anchor thread.
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---- accounts ----
    def create_account(self, account_id: str, api_key_hash: str, plan: str = "free",
                       label: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO accounts(account_id, api_key_hash, plan, created_at, label) "
                "VALUES (?,?,?,?,?)",
                (account_id, api_key_hash, plan, _now(), label),
            )
            self._db.commit()

    def resolve_account(self, api_key_hash: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT account_id, plan FROM accounts WHERE api_key_hash=?", (api_key_hash,)
        )
        row = cur.fetchone()
        return None if row is None else {"account_id": row["account_id"], "plan": row["plan"]}

    def account_plan(self, account_id: str) -> str | None:
        cur = self._db.execute("SELECT plan FROM accounts WHERE account_id=?", (account_id,))
        row = cur.fetchone()
        return None if row is None else row["plan"]

    def set_account_plan(self, account_id: str, plan: str) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE accounts SET plan=? WHERE account_id=?",
                                   (plan, account_id))
            self._db.commit()
            return cur.rowcount > 0

    # ---- server identity (persisted so a restart keeps the same tlog / registry pubkeys) ----
    def get_meta(self, key: str) -> str | None:
        cur = self._db.execute("SELECT v FROM server_meta WHERE k=?", (key,))
        row = cur.fetchone()
        return None if row is None else row["v"]

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO server_meta(k, v, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at",
                (key, value, _now()),
            )
            self._db.commit()

    def get_or_create_signing_key(self, key_name: str):
        """Return a persisted SigningKey, generating and storing one on first use. This makes
        the transparency-log and KYA-registry public keys stable across restarts, which is a
        hard requirement for hosting: a rotated log key would make every prior witnessed
        checkpoint unverifiable and a rotated registry key would void every embedded assertion."""
        from ..keys import SigningKey
        pem = self.get_meta(key_name)
        if pem is not None:
            return SigningKey.from_pem(pem)
        key = SigningKey.generate()
        self.set_meta(key_name, key.to_pem())
        return key

    # ---- usage metering (the billing surface) ----
    def bump_usage(self, account_id: str, *, events: int = 0, anchors: int = 0,
                   period: str | None = None) -> None:
        period = period or _now()[:7]  # 'YYYY-MM'
        with self._lock:
            self._db.execute(
                "INSERT INTO usage(account_id, period, events, anchors, updated_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(account_id, period) DO UPDATE SET "
                "events=events+excluded.events, anchors=anchors+excluded.anchors, "
                "updated_at=excluded.updated_at",
                (account_id, period, events, anchors, _now()),
            )
            self._db.commit()

    def get_usage(self, account_id: str, period: str | None = None) -> dict[str, int]:
        period = period or _now()[:7]
        cur = self._db.execute(
            "SELECT events, anchors FROM usage WHERE account_id=? AND period=?",
            (account_id, period),
        )
        row = cur.fetchone()
        events = 0 if row is None else row["events"]
        anchors = 0 if row is None else row["anchors"]
        return {"period": period, "events": events, "anchors": anchors,
                "streams": self.count_streams(account_id)}

    def count_streams(self, account_id: str) -> int:
        cur = self._db.execute(
            "SELECT COUNT(*) AS n FROM streams WHERE owner_account=?", (account_id,))
        return cur.fetchone()["n"]

    def list_streams(self, account_id: str | None) -> list[dict[str, Any]]:
        """Streams owned by account_id. Pass None to list every stream (dev/open mode)."""
        base = (
            "SELECT s.stream_id, s.created_at, s.label, s.last_anchor_seq, "
            "(SELECT COUNT(*) FROM records r WHERE r.stream_id=s.stream_id) AS records, "
            "(SELECT MAX(recv_ts) FROM records r WHERE r.stream_id=s.stream_id) AS last_activity "
            "FROM streams s "
        )
        if account_id is None:
            cur = self._db.execute(base + "ORDER BY created_at DESC")
        else:
            cur = self._db.execute(base + "WHERE owner_account=? ORDER BY created_at DESC",
                                   (account_id,))
        return [dict(r) for r in cur.fetchall()]

    def get_stream(self, stream_id: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT stream_id, created_at, label, owner_account, last_anchor_seq "
            "FROM streams WHERE stream_id=?", (stream_id,))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def stream_owner(self, stream_id: str) -> str | None:
        cur = self._db.execute("SELECT owner_account FROM streams WHERE stream_id=?", (stream_id,))
        row = cur.fetchone()
        return None if row is None else row["owner_account"]

    def set_last_anchor_seq(self, stream_id: str, anchor_seq: int) -> None:
        with self._lock:
            self._db.execute("UPDATE streams SET last_anchor_seq=? WHERE stream_id=?",
                             (anchor_seq, stream_id))
            self._db.commit()

    def streams_needing_anchor(self) -> list[str]:
        """Streams whose newest record is past their last anchor cursor."""
        cur = self._db.execute(
            "SELECT s.stream_id FROM streams s WHERE EXISTS ("
            "  SELECT 1 FROM records r WHERE r.stream_id=s.stream_id AND r.recv_seq > s.last_anchor_seq)"
        )
        return [r["stream_id"] for r in cur.fetchall()]

    def close(self) -> None:
        self._db.close()

    def create_stream(self, stream_id: str, label: str | None = None,
                      owner_account: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO streams(stream_id, created_at, label, owner_account) VALUES (?,?,?,?)",
                (stream_id, _now(), label, owner_account),
            )
            self._db.commit()

    def stream_exists(self, stream_id: str) -> bool:
        cur = self._db.execute("SELECT 1 FROM streams WHERE stream_id=?", (stream_id,))
        return cur.fetchone() is not None

    def count_records(self, stream_id: str) -> int:
        cur = self._db.execute("SELECT COUNT(*) AS n FROM records WHERE stream_id=?", (stream_id,))
        return cur.fetchone()["n"]

    def append_record(self, stream_id: str, record: dict[str, Any]) -> dict[str, Any]:
        """Append one received record, extending the receipt chain. Returns the receipt.

        Idempotent: re-sending identical bytes returns the original receipt instead of
        appending a duplicate (replay / retry protection).
        """
        with self._lock:
            recv_hash = sha256_hex(canonicalize(record))
            dup = self._db.execute(
                "SELECT recv_seq, recv_ts, server_prev_hash, server_record_hash FROM records "
                "WHERE stream_id=? AND recv_hash=? LIMIT 1",
                (stream_id, recv_hash),
            ).fetchone()
            if dup is not None:
                return {
                    "recv_seq": dup["recv_seq"], "recv_ts": dup["recv_ts"],
                    "recv_hash": recv_hash, "server_prev_hash": dup["server_prev_hash"],
                    "server_record_hash": dup["server_record_hash"], "duplicate": True,
                }
            cur = self._db.execute(
                "SELECT recv_seq, server_record_hash FROM records "
                "WHERE stream_id=? ORDER BY recv_seq DESC LIMIT 1",
                (stream_id,),
            )
            row = cur.fetchone()
            recv_seq = 0 if row is None else row["recv_seq"] + 1
            server_prev = GENESIS_PREV_HASH if row is None else row["server_record_hash"]
            recv_ts = _now()
            server_record_hash = sha256_hex(
                canonicalize(
                    {
                        "recv_seq": recv_seq,
                        "recv_ts": recv_ts,
                        "recv_hash": recv_hash,
                        "server_prev_hash": server_prev,
                    }
                )
            )
            self._db.execute(
                "INSERT INTO records(stream_id, recv_seq, recv_ts, recv_hash, "
                "server_prev_hash, server_record_hash, client_record) VALUES (?,?,?,?,?,?,?)",
                (stream_id, recv_seq, recv_ts, recv_hash, server_prev,
                 server_record_hash, json.dumps(record, ensure_ascii=False)),
            )
            self._db.commit()
            return {
                "recv_seq": recv_seq,
                "recv_ts": recv_ts,
                "recv_hash": recv_hash,
                "server_prev_hash": server_prev,
                "server_record_hash": server_record_hash,
            }

    def get_records(self, stream_id: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM records WHERE stream_id=? ORDER BY recv_seq ASC", (stream_id,)
        )
        out = []
        for r in cur.fetchall():
            out.append(
                {
                    "recv_seq": r["recv_seq"],
                    "recv_ts": r["recv_ts"],
                    "recv_hash": r["recv_hash"],
                    "server_prev_hash": r["server_prev_hash"],
                    "server_record_hash": r["server_record_hash"],
                    "record": json.loads(r["client_record"]),
                }
            )
        return out

    def head(self, stream_id: str) -> dict[str, Any]:
        cur = self._db.execute(
            "SELECT recv_seq, server_record_hash FROM records "
            "WHERE stream_id=? ORDER BY recv_seq DESC LIMIT 1",
            (stream_id,),
        )
        row = cur.fetchone()
        if row is None:
            return {"recv_seq": -1, "server_record_hash": GENESIS_PREV_HASH}
        return {"recv_seq": row["recv_seq"], "server_record_hash": row["server_record_hash"]}

    def origin_for_stream(self, stream_id: str, origin_prefix: str) -> str:
        """The per-account transparency-log shard origin a stream's anchors belong to."""
        owner = self.stream_owner(stream_id)
        return f"{origin_prefix}/{owner or 'shared'}"

    def store_anchor(self, stream_id: str, receipt: dict[str, Any], covers_up_to: int,
                     origin_prefix: str | None = None) -> int:
        """Append an anchor receipt AND its transparency-log leaf in one transaction.

        The anchor row and its tlog leaf are committed together (or not at all), so a crash
        can never leave an anchor that is missing from the log it is supposed to be in."""
        from ..tlog import DEFAULT_ORIGIN_PREFIX, compute_anchor_commit, compute_leaf_hash
        prefix = origin_prefix or DEFAULT_ORIGIN_PREFIX
        with self._lock:
            try:
                row = self._db.execute(
                    "SELECT anchor_seq FROM anchors WHERE stream_id=? "
                    "ORDER BY anchor_seq DESC LIMIT 1", (stream_id,),
                ).fetchone()
                anchor_seq = 0 if row is None else row["anchor_seq"] + 1
                self._db.execute(
                    "INSERT INTO anchors(stream_id, anchor_seq, covers_up_to, receipt) "
                    "VALUES (?,?,?,?)",
                    (stream_id, anchor_seq, covers_up_to,
                     json.dumps(receipt, ensure_ascii=False)),
                )
                # Append the tlog leaf in the same transaction (no intervening commit).
                origin = self.origin_for_stream(stream_id, prefix)
                token_or_sig = (receipt.get("token_b64") if receipt.get("kind") == "rfc3161"
                                else receipt.get("signature")) or ""
                commit = compute_anchor_commit(
                    stream_id, anchor_seq, covers_up_to, receipt.get("merkle_root", ""),
                    receipt.get("gen_time", ""), receipt.get("kind", ""), token_or_sig,
                ).hex()
                leaf_hash = compute_leaf_hash(bytes.fromhex(commit))
                nrow = self._db.execute(
                    "SELECT leaf_index FROM tlog_leaves WHERE log_origin=? "
                    "ORDER BY leaf_index DESC LIMIT 1", (origin,),
                ).fetchone()
                leaf_index = 0 if nrow is None else nrow["leaf_index"] + 1
                self._db.execute(
                    "INSERT INTO tlog_leaves(log_origin, leaf_index, anchor_stream_id, "
                    "anchor_seq, covers_up_to, anchor_commit, leaf_hash, added_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (origin, leaf_index, stream_id, anchor_seq, covers_up_to,
                     commit, leaf_hash, _now()),
                )
                self._db.commit()
                return anchor_seq
            except Exception:
                self._db.rollback()
                raise

    # ---- transparency log ----
    def get_tlog_leaf_hashes(self, origin: str, from_index: int = 0,
                             to_index: int | None = None) -> list[str]:
        """Ordered leaf hashes (hex) for one log shard, [from_index, to_index)."""
        if to_index is None:
            cur = self._db.execute(
                "SELECT leaf_hash FROM tlog_leaves WHERE log_origin=? AND leaf_index>=? "
                "ORDER BY leaf_index ASC", (origin, from_index))
        else:
            cur = self._db.execute(
                "SELECT leaf_hash FROM tlog_leaves WHERE log_origin=? AND leaf_index>=? "
                "AND leaf_index<? ORDER BY leaf_index ASC", (origin, from_index, to_index))
        return [r["leaf_hash"] for r in cur.fetchall()]

    def get_tlog_leaves(self, origin: str, from_index: int = 0,
                        to_index: int | None = None) -> list[dict[str, Any]]:
        if to_index is None:
            cur = self._db.execute(
                "SELECT * FROM tlog_leaves WHERE log_origin=? AND leaf_index>=? "
                "ORDER BY leaf_index ASC", (origin, from_index))
        else:
            cur = self._db.execute(
                "SELECT * FROM tlog_leaves WHERE log_origin=? AND leaf_index>=? "
                "AND leaf_index<? ORDER BY leaf_index ASC", (origin, from_index, to_index))
        return [dict(r) for r in cur.fetchall()]

    def tlog_size(self, origin: str) -> int:
        cur = self._db.execute(
            "SELECT COUNT(*) AS n FROM tlog_leaves WHERE log_origin=?", (origin,))
        return cur.fetchone()["n"]

    def find_tlog_leaf(self, origin: str, stream_id: str, anchor_seq: int) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT * FROM tlog_leaves WHERE log_origin=? AND anchor_stream_id=? AND anchor_seq=?",
            (origin, stream_id, anchor_seq))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def list_tlog_origins(self) -> list[str]:
        cur = self._db.execute("SELECT DISTINCT log_origin FROM tlog_leaves")
        return [r["log_origin"] for r in cur.fetchall()]

    def store_tlog_checkpoint(self, origin: str, tree_size: int, merkle_root: str,
                              signed_note: str, consistency_proof: str | None = None,
                              witnessed: int = 0, status: str = "final") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO tlog_checkpoints(log_origin, tree_size, merkle_root, signed_note, "
                "consistency_proof, witnessed, status, created_at) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(log_origin, tree_size) DO UPDATE SET "
                "signed_note=excluded.signed_note, witnessed=excluded.witnessed, "
                "status=excluded.status",
                (origin, tree_size, merkle_root, signed_note, consistency_proof,
                 witnessed, status, _now()),
            )
            self._db.commit()

    def get_latest_tlog_checkpoint(self, origin: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT * FROM tlog_checkpoints WHERE log_origin=? ORDER BY tree_size DESC LIMIT 1",
            (origin,))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def get_latest_witnessed_checkpoint(self, origin: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT * FROM tlog_checkpoints WHERE log_origin=? AND witnessed>=1 "
            "ORDER BY tree_size DESC LIMIT 1", (origin,))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def get_tlog_checkpoint_by_size(self, origin: str, size: int) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT * FROM tlog_checkpoints WHERE log_origin=? AND tree_size=?", (origin, size))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def get_tlog_checkpoints(self, origin: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM tlog_checkpoints WHERE log_origin=? ORDER BY tree_size ASC", (origin,))
        return [dict(r) for r in cur.fetchall()]

    def get_pending_witness_checkpoints(self, origin: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM tlog_checkpoints WHERE log_origin=? AND status='pending_witness' "
            "ORDER BY tree_size ASC", (origin,))
        return [dict(r) for r in cur.fetchall()]

    def get_tlog_witness_state(self, witness_url: str, origin: str) -> int:
        cur = self._db.execute(
            "SELECT last_cosigned_size FROM tlog_witness_state WHERE witness_url=? AND log_origin=?",
            (witness_url, origin))
        row = cur.fetchone()
        return 0 if row is None else row["last_cosigned_size"]

    def update_tlog_witness_state(self, witness_url: str, origin: str, last_cosigned_size: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO tlog_witness_state(witness_url, log_origin, last_cosigned_size, "
                "updated_at) VALUES (?,?,?,?) ON CONFLICT(witness_url, log_origin) DO UPDATE SET "
                "last_cosigned_size=excluded.last_cosigned_size, updated_at=excluded.updated_at",
                (witness_url, origin, last_cosigned_size, _now()),
            )
            self._db.commit()

    # ---- members (RBAC) ----
    def create_member(self, member_id: str, account_id: str, api_key_hash: str, role: str,
                      label: str | None = None, email: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO members(member_id, account_id, api_key_hash, role, label, email, "
                "created_at) VALUES (?,?,?,?,?,?,?)",
                (member_id, account_id, api_key_hash, role, label, email, _now()),
            )
            self._db.commit()

    def resolve_member(self, api_key_hash: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT member_id, account_id, role, status FROM members WHERE api_key_hash=?",
            (api_key_hash,))
        row = cur.fetchone()
        if row is None or row["status"] != "active":
            return None
        return dict(row)

    def list_members(self, account_id: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT member_id, role, label, email, status, created_at FROM members "
            "WHERE account_id=? ORDER BY created_at ASC", (account_id,))
        return [dict(r) for r in cur.fetchall()]

    def get_member(self, account_id: str, member_id: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT member_id, account_id, role, label, email, status FROM members "
            "WHERE account_id=? AND member_id=?", (account_id, member_id))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def set_member_role(self, account_id: str, member_id: str, role: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE members SET role=? WHERE account_id=? AND member_id=?",
                (role, account_id, member_id))
            self._db.commit()
            return cur.rowcount > 0

    def set_member_status(self, account_id: str, member_id: str, status: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE members SET status=? WHERE account_id=? AND member_id=?",
                (status, account_id, member_id))
            self._db.commit()
            return cur.rowcount > 0

    def find_member_by_email(self, account_id: str, email: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT member_id, account_id, role, status FROM members "
            "WHERE account_id=? AND email=?", (account_id, email))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def set_member_key(self, account_id: str, member_id: str, api_key_hash: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE members SET api_key_hash=? WHERE account_id=? AND member_id=?",
                (api_key_hash, account_id, member_id))
            self._db.commit()

    # ---- OIDC SSO config ----
    def set_oidc_config(self, account_id: str, issuer: str, audience: str, jwks: str,
                        default_role: str = "member", email_domain: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO oidc_config(account_id, issuer, audience, jwks, default_role, "
                "email_domain, updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(account_id) DO UPDATE SET issuer=excluded.issuer, "
                "audience=excluded.audience, jwks=excluded.jwks, "
                "default_role=excluded.default_role, email_domain=excluded.email_domain, "
                "updated_at=excluded.updated_at",
                (account_id, issuer, audience, jwks, default_role, email_domain, _now()))
            self._db.commit()

    def get_oidc_config(self, account_id: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT account_id, issuer, audience, jwks, default_role, email_domain "
            "FROM oidc_config WHERE account_id=?", (account_id,))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def find_account_by_issuer(self, issuer: str, audience: str) -> str | None:
        cur = self._db.execute(
            "SELECT account_id FROM oidc_config WHERE issuer=? AND audience=?",
            (issuer, audience))
        row = cur.fetchone()
        return None if row is None else row["account_id"]

    def count_owners(self, account_id: str) -> int:
        cur = self._db.execute(
            "SELECT COUNT(*) AS n FROM members WHERE account_id=? AND role='owner' AND status='active'",
            (account_id,))
        return cur.fetchone()["n"]

    # ---- agent identity registry (KYA) ----
    def register_agent_key(self, account_id: str, agent_id: str, pubkey: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO agent_keys(account_id, agent_id, pubkey, registered_at) "
                "VALUES (?,?,?,?)", (account_id, agent_id, pubkey, _now()))
            self._db.commit()

    def rotate_agent_key(self, account_id: str, agent_id: str, old_pubkey: str,
                         new_pubkey: str) -> None:
        """Register a new key for an agent and revoke the old one. Records signed by the old
        key stay verifiable (its assertion is kept with revoked_at), but new records must use
        the new key. Both rows are retained so historical evidence still resolves."""
        with self._lock:
            self._db.execute(
                "UPDATE agent_keys SET status='revoked', revoked_at=? "
                "WHERE account_id=? AND agent_id=? AND pubkey=?",
                (_now(), account_id, agent_id, old_pubkey))
            self._db.execute(
                "INSERT OR IGNORE INTO agent_keys(account_id, agent_id, pubkey, registered_at) "
                "VALUES (?,?,?,?)", (account_id, agent_id, new_pubkey, _now()))
            self._db.commit()

    def revoke_agent_key(self, account_id: str, agent_id: str, pubkey: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE agent_keys SET status='revoked', revoked_at=? "
                "WHERE account_id=? AND agent_id=? AND pubkey=? AND status='active'",
                (_now(), account_id, agent_id, pubkey))
            self._db.commit()
            return cur.rowcount > 0

    def list_agent_keys(self, account_id: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT agent_id, pubkey, status, registered_at, revoked_at FROM agent_keys "
            "WHERE account_id=? ORDER BY registered_at ASC", (account_id,))
        return [dict(r) for r in cur.fetchall()]

    def find_agent_by_pubkey(self, account_id: str, pubkey: str) -> dict[str, Any] | None:
        cur = self._db.execute(
            "SELECT agent_id, pubkey, status, registered_at, revoked_at FROM agent_keys "
            "WHERE account_id=? AND pubkey=?", (account_id, pubkey))
        row = cur.fetchone()
        return None if row is None else dict(row)

    # ---- meta audit (tamper-evident access log, audit-of-the-audit) ----
    def append_audit(self, account_id: str, actor: str, actor_role: str | None, action: str,
                     resource_type: str | None = None, resource_id: str | None = None,
                     detail: dict[str, Any] | None = None) -> int:
        """Append a hash-chained access-log entry. Returns its per-account audit_seq.

        The chain makes the access log itself tamper-evident: an admin (or the host) cannot
        quietly remove evidence that a record was viewed or exported, which is exactly what a
        HIPAA 164.312(b) audit control or an EU AI Act access trail is meant to provide."""
        with self._lock:
            row = self._db.execute(
                "SELECT audit_seq, entry_hash FROM meta_audit WHERE account_id=? "
                "ORDER BY audit_seq DESC LIMIT 1", (account_id,)).fetchone()
            seq = 0 if row is None else row["audit_seq"] + 1
            prev = GENESIS_PREV_HASH if row is None else row["entry_hash"]
            ts = _now()
            detail_json = json.dumps(detail, ensure_ascii=False, sort_keys=True) if detail else None
            entry_hash = sha256_hex(canonicalize({
                "audit_seq": seq, "account_id": account_id, "ts": ts, "actor": actor,
                "actor_role": actor_role, "action": action, "resource_type": resource_type,
                "resource_id": resource_id, "detail": detail_json, "prev_hash": prev,
            }))
            self._db.execute(
                "INSERT INTO meta_audit(audit_seq, account_id, ts, actor, actor_role, action, "
                "resource_type, resource_id, detail, prev_hash, entry_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (seq, account_id, ts, actor, actor_role, action, resource_type, resource_id,
                 detail_json, prev, entry_hash),
            )
            self._db.commit()
            return seq

    def get_audit_log(self, account_id: str, limit: int = 500) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT audit_seq, ts, actor, actor_role, action, resource_type, resource_id, "
            "detail, prev_hash, entry_hash FROM meta_audit WHERE account_id=? "
            "ORDER BY audit_seq DESC LIMIT ?", (account_id, limit))
        out = []
        for r in cur.fetchall():
            d = dict(r)
            if d.get("detail"):
                d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def verify_audit_chain(self, account_id: str) -> bool:
        """Recompute the access-log hash chain from scratch; False if any link is broken."""
        cur = self._db.execute(
            "SELECT audit_seq, ts, actor, actor_role, action, resource_type, resource_id, "
            "detail, prev_hash, entry_hash FROM meta_audit WHERE account_id=? "
            "ORDER BY audit_seq ASC", (account_id,))
        prev = GENESIS_PREV_HASH
        for i, r in enumerate(cur.fetchall()):
            if r["audit_seq"] != i or r["prev_hash"] != prev:
                return False
            expect = sha256_hex(canonicalize({
                "audit_seq": r["audit_seq"], "account_id": account_id, "ts": r["ts"],
                "actor": r["actor"], "actor_role": r["actor_role"], "action": r["action"],
                "resource_type": r["resource_type"], "resource_id": r["resource_id"],
                "detail": r["detail"], "prev_hash": prev,
            }))
            if expect != r["entry_hash"]:
                return False
            prev = r["entry_hash"]
        return True

    # ---- webhooks ----
    def create_webhook(self, webhook_id: str, account_id: str | None, url: str,
                       secret: str, events: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO webhooks(webhook_id, account_id, url, secret, events, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (webhook_id, account_id, url, secret, events, _now()),
            )
            self._db.commit()

    def list_webhooks(self, account_id: str | None) -> list[dict[str, Any]]:
        if account_id is None:
            cur = self._db.execute(
                "SELECT webhook_id, url, events, created_at FROM webhooks "
                "WHERE account_id IS NULL ORDER BY created_at DESC")
        else:
            cur = self._db.execute(
                "SELECT webhook_id, url, events, created_at FROM webhooks "
                "WHERE account_id=? ORDER BY created_at DESC", (account_id,))
        return [dict(r) for r in cur.fetchall()]

    def webhooks_for_delivery(self, account_id: str | None) -> list[dict[str, Any]]:
        if account_id is None:
            cur = self._db.execute(
                "SELECT webhook_id, url, secret, events FROM webhooks WHERE account_id IS NULL")
        else:
            cur = self._db.execute(
                "SELECT webhook_id, url, secret, events FROM webhooks WHERE account_id=?",
                (account_id,))
        return [dict(r) for r in cur.fetchall()]

    def delete_webhook(self, webhook_id: str, account_id: str | None) -> bool:
        with self._lock:
            if account_id is None:
                cur = self._db.execute(
                    "DELETE FROM webhooks WHERE webhook_id=? AND account_id IS NULL", (webhook_id,))
            else:
                cur = self._db.execute(
                    "DELETE FROM webhooks WHERE webhook_id=? AND account_id=?",
                    (webhook_id, account_id))
            self._db.commit()
            return cur.rowcount > 0

    # ---- per-stream integrity state (for alert transition detection) ----
    def get_stream_state(self, stream_id: str) -> str | None:
        cur = self._db.execute(
            "SELECT integrity_state FROM stream_state WHERE stream_id=?", (stream_id,))
        row = cur.fetchone()
        return None if row is None else row["integrity_state"]

    def set_stream_state(self, stream_id: str, state: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO stream_state(stream_id, integrity_state, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(stream_id) DO UPDATE SET integrity_state=excluded.integrity_state, "
                "updated_at=excluded.updated_at",
                (stream_id, state, _now()),
            )
            self._db.commit()

    def get_anchors(self, stream_id: str) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT anchor_seq, covers_up_to, receipt FROM anchors "
            "WHERE stream_id=? ORDER BY anchor_seq ASC",
            (stream_id,),
        )
        return [
            {"anchor_seq": r["anchor_seq"], "covers_up_to": r["covers_up_to"],
             "receipt": json.loads(r["receipt"])}
            for r in cur.fetchall()
        ]
