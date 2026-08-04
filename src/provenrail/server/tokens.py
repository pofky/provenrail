"""Scoped, append-only token model.

Red-team finding (Topology 2): the whole B2C guarantee collapses if a delete-capable
credential ever reaches the agent's environment, or if a write token can also read/delete.
So scopes are strictly partitioned and there is NO delete scope anywhere in the system.

  - write : may ONLY append records to its own stream. Cannot read, cannot share.
  - read  : may read/export its own stream. Cannot write.
  - share : public, read-only view of a single stream (for client-facing proof links).

Tokens are random secrets; only their SHA-256 is stored, so a leaked DB does not leak
usable tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

WRITE = "write"
READ = "read"
SHARE = "share"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token_hash  TEXT PRIMARY KEY,
    stream_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    revoked_at  TEXT
);
"""


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TokenStore:
    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._lock = threading.Lock()
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """Add expiry/revocation columns to a tokens table created by an older version."""
        cols = {r["name"] for r in self._db.execute("PRAGMA table_info(tokens)").fetchall()}
        for col in ("expires_at", "revoked_at"):
            if col not in cols:
                self._db.execute(f"ALTER TABLE tokens ADD COLUMN {col} TEXT")

    def mint(self, stream_id: str, scope: str, ttl_seconds: float | None = None) -> str:
        if scope not in (WRITE, READ, SHARE):
            raise ValueError(f"unknown scope {scope}")
        token = f"pr_{scope}_{secrets.token_urlsafe(32)}"
        expires_at = None
        if ttl_seconds is not None:
            expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ")
        with self._lock:
            self._db.execute(
                "INSERT INTO tokens(token_hash, stream_id, scope, created_at, expires_at) "
                "VALUES (?,?,?,?,?)",
                (_hash(token), stream_id, scope, _now(), expires_at),
            )
            self._db.commit()
        return token

    def resolve(self, token: str) -> tuple[str, str] | None:
        """Return (stream_id, scope) for a live token, else None.

        A token is rejected if it does not exist, has been revoked, or has expired. ISO-8601
        UTC timestamps sort lexically, so a string compare is a correct time comparison."""
        cur = self._db.execute(
            "SELECT stream_id, scope, expires_at, revoked_at FROM tokens WHERE token_hash=?",
            (_hash(token),),
        )
        row = cur.fetchone()
        if row is None or row["revoked_at"] is not None:
            return None
        if row["expires_at"] is not None and row["expires_at"] <= _now():
            return None
        return (row["stream_id"], row["scope"])

    def revoke_stream(self, stream_id: str) -> int:
        """Revoke every token for a stream (e.g. a leaked agent credential). Returns the
        number of live tokens revoked. Append-only in spirit: nothing is deleted, the token
        is marked dead so it can never authenticate again."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE tokens SET revoked_at=? WHERE stream_id=? AND revoked_at IS NULL",
                (_now(), stream_id),
            )
            self._db.commit()
            return cur.rowcount

    def revoke_token(self, token: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (_now(), _hash(token)),
            )
            self._db.commit()
            return cur.rowcount > 0
