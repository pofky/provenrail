"""Out-of-band human approval for agents with no human at the keyboard.

`require_oversight` already works where a human is present: inside Claude Code the rule maps
to the permission prompt, and the person answering it IS the oversight. A headless agent, a
cron job, or a container has no such prompt, so today the same rule can only deny. That turns
the most useful guardrail into a blocker, and a blocker gets switched off within a day.

This is the missing half: the agent pauses, a human gets a link, and their answer becomes a
`human_oversight` record in the same signed chain as everything else. The approval is
evidence, not a notification that scrolled past in a channel.

Design decisions that matter, each one a way this could go wrong:

**Fail closed.** A request that is never answered expires and the action stays denied. A
timeout, an unreachable notifier, or a crashed sink can never turn a pending approval into an
allow. The waiting agent gets `expired`, never `approved`.

**The link is the capability, and it is single-use.** There is no login on the approve page:
requiring one would mean provisioning accounts for the person who happens to be on call.
Instead each request carries a high-entropy token, stored only as a SHA-256, that decides
exactly one request exactly once. A replayed link shows the decision that was already made
rather than making a second one.

**Approve and deny are different tokens.** One token with an `?action=` parameter is one
mangled link, one over-eager link prefetcher, or one email scanner away from an accidental
approval. Two unrelated secrets mean a fetch of the deny URL can never approve.

**The decision is recorded by the agent, not by the sink.** The sink stores the answer; the
agent's own recorder writes the `human_oversight` record into its chain and signs it. The
sink never holds the signing key, so it can never manufacture an approval that verifies.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"

#: How long a request stays answerable. Long enough for a human to come back from lunch,
#: short enough that a stale link in an old email cannot approve anything.
DEFAULT_TTL_SECONDS = 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    request_id    TEXT PRIMARY KEY,
    stream_id     TEXT NOT NULL,
    session_id    TEXT,
    account_id    TEXT,
    rule          TEXT,
    event_type    TEXT,
    target        TEXT,
    reason        TEXT,
    status        TEXT NOT NULL,
    approve_hash  TEXT NOT NULL UNIQUE,
    deny_hash     TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    decided_at    TEXT,
    decided_by    TEXT,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS approvals_by_stream ON approvals(stream_id, status);
"""


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ApprovalStore:
    """Pending human decisions. Plain storage: the evidence lives in the agent's chain."""

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._lock = threading.Lock()
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def create(self, stream_id: str, *, session_id: str | None = None,
               account_id: str | None = None, rule: str | None = None,
               event_type: str | None = None, target: str | None = None,
               reason: str = "", ttl_seconds: int = DEFAULT_TTL_SECONDS,
               now: datetime | None = None) -> dict[str, Any]:
        """Open a request and return it WITH the two raw tokens, once.

        The raw tokens are returned here and never again: only their hashes are stored, so a
        leaked database cannot be used to approve anything.
        """
        stamp = now or _now()
        approve_token = secrets.token_urlsafe(32)
        deny_token = secrets.token_urlsafe(32)
        request_id = secrets.token_urlsafe(12)
        expires = stamp + timedelta(seconds=max(1, int(ttl_seconds)))
        with self._lock:
            self._db.execute(
                "INSERT INTO approvals(request_id, stream_id, session_id, account_id, rule, "
                "event_type, target, reason, status, approve_hash, deny_hash, created_at, "
                "expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (request_id, stream_id, session_id, account_id, rule, event_type, target,
                 reason, PENDING, _hash(approve_token), _hash(deny_token), _stamp(stamp),
                 _stamp(expires)))
            self._db.commit()
        return {"request_id": request_id, "status": PENDING, "stream_id": stream_id,
                "session_id": session_id, "rule": rule, "event_type": event_type,
                "target": target, "reason": reason, "created_at": _stamp(stamp),
                "expires_at": _stamp(expires),
                "approve_token": approve_token, "deny_token": deny_token}

    def _row(self, request_id: str) -> dict[str, Any] | None:
        cur = self._db.execute("SELECT * FROM approvals WHERE request_id=?", (request_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get(self, request_id: str, now: datetime | None = None) -> dict[str, Any] | None:
        """The request, with a pending-but-past-expiry request reported as expired.

        Expiry is evaluated on read rather than by a sweeper: a request whose deadline passed
        while nothing was running must still come back `expired`, never `pending`, or a
        waiting agent could be released by a clock that simply had not been checked yet.
        """
        row = self._row(request_id)
        if row is None:
            return None
        if row["status"] == PENDING and _stamp(now or _now()) > row["expires_at"]:
            row["status"] = EXPIRED
        return self._public(row)

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        """The view callers get: never the token hashes."""
        return {k: v for k, v in row.items() if k not in ("approve_hash", "deny_hash")}

    def decide_by_token(self, token: str, decision: str, decided_by: str = "",
                        note: str = "", now: datetime | None = None) -> dict[str, Any]:
        """Answer a request using one of its links.

        Returns `{"ok": bool, "reason": str, "request": {...}|None}`. A replayed link is not
        an error: it returns the decision that was already made, so a human who clicks twice
        sees a consistent answer instead of a scary failure.
        """
        column = "approve_hash" if decision == APPROVED else "deny_hash"
        stamp = now or _now()
        with self._lock:
            cur = self._db.execute(f"SELECT * FROM approvals WHERE {column}=?", (_hash(token),))
            row = cur.fetchone()
            if row is None:
                return {"ok": False, "reason": "unknown or already-rotated link",
                        "request": None}
            row = dict(row)
            if row["status"] != PENDING:
                return {"ok": False, "reason": f"already {row['status']}",
                        "request": self._public(row)}
            if _stamp(stamp) > row["expires_at"]:
                self._db.execute("UPDATE approvals SET status=? WHERE request_id=?",
                                 (EXPIRED, row["request_id"]))
                self._db.commit()
                row["status"] = EXPIRED
                return {"ok": False, "reason": "this request expired before it was answered",
                        "request": self._public(row)}
            self._db.execute(
                "UPDATE approvals SET status=?, decided_at=?, decided_by=?, note=? "
                "WHERE request_id=?",
                (decision, _stamp(stamp), decided_by or "link", note, row["request_id"]))
            self._db.commit()
            row.update(status=decision, decided_at=_stamp(stamp),
                       decided_by=decided_by or "link", note=note)
        return {"ok": True, "reason": "", "request": self._public(row)}

    def list_pending(self, account_id: str | None, now: datetime | None = None
                     ) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM approvals WHERE status=? AND (account_id IS ? OR account_id=?) "
            "ORDER BY created_at DESC", (PENDING, account_id, account_id))
        stamp = _stamp(now or _now())
        out = []
        for row in cur.fetchall():
            row = dict(row)
            if stamp > row["expires_at"]:
                continue   # expired requests are not actionable, so they are not "pending"
            out.append(self._public(row))
        return out

    def decision_page(self, headline: str, body: str) -> str:
        """Wrap a decision result in the same visual language as the rest of the product.

        Mobile-first and self-contained: this page is opened from a phone, from a Slack
        message, at whatever hour the agent needed an answer, so it must render correctly with
        no layout shift and without depending on a stylesheet that might not load.
        """
        return _PAGE.replace("{{headline}}", headline).replace("{{body}}", body)

    def list_for_stream(self, stream_id: str, limit: int = 100) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM approvals WHERE stream_id=? ORDER BY created_at DESC LIMIT ?",
            (stream_id, limit))
        return [self._public(dict(r)) for r in cur.fetchall()]


# The decision page is deliberately one self-contained document with no external requests:
# it is opened on a phone, from a chat message, often on a bad connection, and a stylesheet
# that fails to load must not turn "Approved" into unstyled ambiguity.
_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{{headline}} | Provenrail human oversight</title>
<style>
:root{--bg:#0a0b0e;--bg-3:#14171c;--border:#20242c;--accent:#2ee6a6;--red:#f06a5d;
--text-hi:#f3f5f7;--text-mid:#99a2af;--text-lo:#5a626e;
--font-mono:'DM Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
--font-body:system-ui,-apple-system,'Segoe UI',sans-serif}
@media(prefers-color-scheme:light){:root{--bg:#fbfcfd;--bg-3:#ffffff;--border:#e4e8ee;
--accent:#07a06a;--text-hi:#0c0f14;--text-mid:#515b67;--text-lo:#97a0ab}}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font-body);background:var(--bg);color:var(--text-hi);line-height:1.55;
min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.25rem}
main{width:100%;max-width:34rem;background:var(--bg-3);border:1px solid var(--border);
border-radius:14px;padding:clamp(1.5rem,5vw,2.25rem)}
.eyebrow{font-family:var(--font-mono);font-size:.7rem;letter-spacing:.14em;
text-transform:uppercase;color:var(--text-lo);margin-bottom:.9rem}
h1{font-family:var(--font-mono);font-size:clamp(1.5rem,6vw,2rem);font-weight:500;
letter-spacing:-.02em;margin-bottom:.6rem}
h1.ok{color:var(--accent)}
h1.no{color:var(--red)}
p{color:var(--text-mid);margin-bottom:1.1rem}
table{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:1.1rem}
th,td{text-align:left;padding:.5rem .25rem;border-bottom:1px solid var(--border);
vertical-align:top}
th{font-family:var(--font-mono);font-weight:400;color:var(--text-lo);width:9rem;
font-size:.78rem}
td{font-family:var(--font-mono);color:var(--text-hi);word-break:break-word}
.fine{font-size:.8rem;color:var(--text-lo);margin:0}
</style></head><body>{{body}}</body></html>"""
