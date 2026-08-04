"""Local spend ledger: the memory a cross-session budget needs.

A session budget lives in one process and is exact. A `day` or `total` budget has to survive
process exit, because the failure it exists to prevent, an agent that runs all night across
hundreds of short sessions and is discovered when the invoice arrives, happens entirely
*between* processes. This module is that memory: a small append-in-place JSON file holding
estimated spend per agent, bucketed by UTC day.

Three deliberate properties:

**It is a convenience, never evidence.** The file is local, plain, and editable. Nothing here
is signed or hashed, and the verifier never reads it. Editing it can loosen a local budget, in
exactly the same way as editing the policy file itself, which is why an operator who needs a
cap the agent's own host cannot lift enforces it at the sink instead. Saying so plainly is the
honest framing; pretending a local JSON file is tamper-proof would not survive an auditor.

**Its numbers are estimates.** They come from `pricing.py` list prices applied to reported
token usage. They are labelled as estimates wherever they surface and are reconciled against
the provider's invoice separately.

**A ledger failure must never break recording.** Every read and write degrades to "no prior
spend known" rather than raising, and the caller reports `prior_known=False` so a cross-session
budget is never displayed as authoritative when its history was unavailable.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

LEDGER_FILENAME = ".provenrail-spend.json"

#: Day buckets older than this are dropped on write. Long enough for a monthly view, short
#: enough that the file stays small and cheap to rewrite on every model call.
RETAIN_DAYS = 45


def ledger_path() -> Path:
    env = os.environ.get("PROVENRAIL_SPEND_LEDGER")
    return Path(env) if env else Path.cwd() / LEDGER_FILENAME


def _today(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m-%d")


def _read(path: Path | None = None) -> dict[str, Any]:
    target = path or ledger_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".spend-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, path)
    except OSError:
        Path(tmp).unlink(missing_ok=True)


def _prune(days: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    cutoff = ((now or datetime.now(UTC)) - timedelta(days=RETAIN_DAYS)).strftime("%Y-%m-%d")
    return {d: v for d, v in days.items() if d >= cutoff}


def prior_spend(agent_id: str = "default", path: Path | None = None,
                now: datetime | None = None) -> tuple[float, float, bool]:
    """Estimated spend already recorded for this agent: (today, lifetime, known).

    `known` is False when no ledger exists yet, so the caller can distinguish "nothing spent"
    from "no history available" and refuse to present a cross-session budget as authoritative.
    """
    target = path or ledger_path()
    if not target.is_file():
        return 0.0, 0.0, False
    entry = _read(target).get("agents", {}).get(agent_id)
    if not isinstance(entry, dict):
        return 0.0, 0.0, True   # ledger exists; this agent simply has no spend yet
    days = entry.get("days", {})
    today = float(days.get(_today(now), 0.0) or 0.0) if isinstance(days, dict) else 0.0
    total = float(entry.get("total_usd", 0.0) or 0.0)
    return today, total, True


def add_spend(amount_usd: float, agent_id: str = "default", path: Path | None = None,
              now: datetime | None = None) -> None:
    """Add one call's estimated cost to the ledger. Silently a no-op on any I/O failure."""
    if amount_usd <= 0:
        return
    target = path or ledger_path()
    data = _read(target)
    agents = data.setdefault("agents", {}) if isinstance(data.get("agents", {}), dict) else {}
    entry = agents.get(agent_id)
    if not isinstance(entry, dict):
        entry = {"days": {}, "total_usd": 0.0}
    days = entry.get("days") if isinstance(entry.get("days"), dict) else {}
    day = _today(now)
    days[day] = round(float(days.get(day, 0.0) or 0.0) + amount_usd, 6)
    entry["days"] = _prune(days, now)
    entry["total_usd"] = round(float(entry.get("total_usd", 0.0) or 0.0) + amount_usd, 6)
    entry["updated"] = (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
    agents[agent_id] = entry
    data["agents"] = agents
    data["version"] = 1
    _write_atomic(target, data)


def report(agent_id: str | None = None, path: Path | None = None,
           now: datetime | None = None) -> dict[str, Any]:
    """A finance-shaped view of the ledger: per agent, today / 7d / 30d / lifetime."""
    data = _read(path or ledger_path())
    agents = data.get("agents", {})
    if not isinstance(agents, dict):
        return {"agents": [], "total_usd": 0.0}
    stamp = now or datetime.now(UTC)
    today = _today(stamp)
    since_7 = (stamp - timedelta(days=7)).strftime("%Y-%m-%d")
    since_30 = (stamp - timedelta(days=30)).strftime("%Y-%m-%d")
    rows: list[dict[str, Any]] = []
    for aid, entry in sorted(agents.items()):
        if agent_id is not None and aid != agent_id:
            continue
        days = entry.get("days", {}) if isinstance(entry, dict) else {}
        days = days if isinstance(days, dict) else {}
        rows.append({
            "agent_id": aid,
            "today_usd": round(float(days.get(today, 0.0) or 0.0), 6),
            "last_7d_usd": round(sum(float(v or 0.0) for d, v in days.items() if d > since_7), 6),
            "last_30d_usd": round(sum(float(v or 0.0) for d, v in days.items() if d > since_30), 6),
            "total_usd": round(float(entry.get("total_usd", 0.0) or 0.0), 6),
            "days": dict(sorted(days.items())),
        })
    return {"agents": rows, "total_usd": round(sum(r["total_usd"] for r in rows), 6),
            "estimated": True}


def reset(agent_id: str | None = None, path: Path | None = None) -> None:
    target = path or ledger_path()
    if agent_id is None:
        target.unlink(missing_ok=True)
        return
    data = _read(target)
    agents = data.get("agents", {})
    if isinstance(agents, dict) and agents.pop(agent_id, None) is not None:
        data["agents"] = agents
        _write_atomic(target, data)
