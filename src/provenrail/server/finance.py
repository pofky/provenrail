"""Finance rollups: estimated spend grouped the way a budget owner asks for it.

The dashboard already answers "what did this run cost?". Finance asks a different question,
and it is always one of five: **which agent, which project, which team, which model, which
day**. Answering it needs no new ingest API and no schema change, because the answer is
already in the signed record: the session-start record carries the operator's own session
metadata, and that is where agent, project, and team live.

Two properties this module is careful about, both of which are the difference between a
number someone can act on and a number that quietly misleads:

**Unattributed spend is shown, never hidden.** A session whose metadata carries no `project`
rolls up under `(unattributed)` rather than being dropped. A rollup whose totals do not equal
the account total is worse than useless: it makes an underspend look real.

**Unpriced calls are counted separately.** A model with no verified rate contributes $0.00 to
the total, so a row with `unpriced_calls > 0` is a FLOOR, not a cost. Every output carries
that count, and the CSV has a column for it, so a spreadsheet cannot lose it.

Everything here is an estimate derived from reported token usage and a dated price table.
Reconciliation against the provider's invoice is `reconcile.py`, deliberately separate: an
estimate and an invoice are different kinds of fact and merging them silently would be the
same mistake as hiding the unpriced calls.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from ..chain import GENESIS, MODEL_CALL
from ..pricing import cost_for, is_stale, load_price_table, table_as_of

#: The dimensions a rollup can group by. `agent`, `project`, and `team` are read from session
#: metadata; `model` and `day` from the model-call records themselves; `stream` from the sink.
DIMENSIONS = ("agent", "project", "team", "model", "day", "stream", "session")

UNATTRIBUTED = "(unattributed)"

#: Session-metadata keys accepted for each dimension, in priority order. Operators name these
#: fields themselves, so a rollup that only understood one spelling would report every session
#: as unattributed and look like a product bug.
_META_KEYS: dict[str, tuple[str, ...]] = {
    "agent": ("agent", "agent_id", "agent_name"),
    "project": ("project", "project_id", "project_name", "repo"),
    "team": ("team", "team_id", "team_name", "squad", "department"),
}


def _meta_of(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """session_id -> the session-start metadata the operator supplied."""
    out: dict[str, dict[str, Any]] = {}
    for r in records:
        rec = r.get("record", r) or {}
        if rec.get("action_type") != GENESIS:
            continue
        meta = (rec.get("payload", {}) or {}).get("meta", {}) or {}
        out[str(rec.get("session_id", ""))] = meta if isinstance(meta, dict) else {}
    return out


def _dimension_value(dimension: str, rec: dict[str, Any], meta: dict[str, Any],
                     stream_id: str) -> str:
    if dimension in _META_KEYS:
        for key in _META_KEYS[dimension]:
            value = meta.get(key)
            if value not in (None, ""):
                return str(value)
        return UNATTRIBUTED
    if dimension == "model":
        return str((rec.get("payload", {}) or {}).get("model") or UNATTRIBUTED)
    if dimension == "day":
        return str(rec.get("ts_utc") or "")[:10] or UNATTRIBUTED
    if dimension == "session":
        return str(rec.get("session_id") or UNATTRIBUTED)
    return stream_id or UNATTRIBUTED


def _in_window(rec: dict[str, Any], since: str | None, until: str | None) -> bool:
    """UTC date window, inclusive at both ends. A record with no timestamp is kept: dropping
    it would silently shrink a total."""
    day = str(rec.get("ts_utc") or "")[:10]
    if not day:
        return True
    if since and day < since:
        return False
    return not (until and day > until)


def rollup(streams: list[tuple[str, list[dict[str, Any]]]], group_by: str = "agent",
           since: str | None = None, until: str | None = None,
           table: dict[str, Any] | None = None) -> dict[str, Any]:
    """Estimated spend across many streams, grouped by one dimension.

    `streams` is a list of `(stream_id, records)`, where records are in the sink's stored
    shape (`{"record": {...}}`) or the raw record. Returns rows sorted by cost, descending,
    plus totals and the price-table provenance every caller must display alongside them.
    """
    if group_by not in DIMENSIONS:
        raise ValueError(f"group_by must be one of {DIMENSIONS}, got {group_by!r}")
    table = table if table is not None else load_price_table()

    rows: dict[str, dict[str, Any]] = {}
    sessions_seen: dict[str, set[str]] = {}
    for stream_id, records in streams:
        meta_by_session = _meta_of(records)
        for r in records:
            rec = r.get("record", r) or {}
            if rec.get("action_type") != MODEL_CALL or not _in_window(rec, since, until):
                continue
            session_id = str(rec.get("session_id", ""))
            meta = meta_by_session.get(session_id, {})
            key = _dimension_value(group_by, rec, meta, stream_id)
            payload = rec.get("payload", {}) or {}
            cost = cost_for(payload.get("model", ""), payload.get("usage"), table)
            row = rows.setdefault(key, {
                group_by: key, "cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0,
                "tokens_cache_read": 0, "model_calls": 0, "unpriced_calls": 0, "sessions": 0,
            })
            row["cost_usd"] = round(row["cost_usd"] + cost["cost_usd"], 6)
            row["tokens_in"] += cost["tokens_in"]
            row["tokens_out"] += cost["tokens_out"]
            row["tokens_cache_read"] += cost.get("tokens_cache_read", 0)
            row["model_calls"] += 1
            if not cost["priced"]:
                row["unpriced_calls"] += 1
            sessions_seen.setdefault(key, set()).add(f"{stream_id}:{session_id}")

    for key, row in rows.items():
        row["sessions"] = len(sessions_seen.get(key, ()))

    ordered = sorted(rows.values(), key=lambda r: (-r["cost_usd"], r[group_by]))
    totals = {
        "cost_usd": round(sum(r["cost_usd"] for r in ordered), 6),
        "tokens_in": sum(r["tokens_in"] for r in ordered),
        "tokens_out": sum(r["tokens_out"] for r in ordered),
        "model_calls": sum(r["model_calls"] for r in ordered),
        "unpriced_calls": sum(r["unpriced_calls"] for r in ordered),
        "groups": len(ordered),
    }
    return {
        "group_by": group_by,
        "from": since,
        "to": until,
        "rows": ordered,
        "totals": totals,
        # Provenance travels with the number. A cost with no price date attached is a number
        # nobody can check, and the first question finance asks is "as of when?".
        "estimated": True,
        "prices_as_of": table_as_of(table),
        "prices_stale": is_stale(table),
    }


#: Characters that make a spreadsheet treat a cell as a formula rather than as text.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _sanitize(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in an exported cell.

    The dimension column of this export is agent-supplied session metadata, and the agent is
    this product's primary adversary. `csv.writer` quotes correctly, but quoting is undone by
    the spreadsheet on open: a cell that begins `=`, `+`, `-` or `@` is then evaluated, so an
    agent that names itself `=DDE("cmd","/c calc","x")` attacks the finance person who opens
    the report about that agent. Prefixing with an apostrophe makes the cell literal text in
    Excel, LibreOffice and Sheets, and is the standard mitigation.

    Numbers are passed through untouched: they are computed here, never attacker-supplied, and
    quoting them would break the arithmetic the file exists for.
    """
    if isinstance(value, (int, float)) or value is None:
        return value
    text = str(value)
    return "'" + text if text[:1] in _FORMULA_LEAD else text


def to_csv(result: dict[str, Any]) -> str:
    """The rollup as CSV, for the spreadsheet the conversation actually happens in.

    The header carries the estimate caveat and the price date as comment lines, because a CSV
    gets forwarded without its context and a bare cost column reads as an invoice.
    """
    group_by = result["group_by"]
    buf = io.StringIO()
    buf.write("# Provenrail estimated spend. Estimates from recorded token usage and a public "
              "price table, NOT an invoice.\n")
    buf.write(f"# prices_as_of={result.get('prices_as_of') or 'undated'}"
              f" stale={str(result.get('prices_stale', False)).lower()}"
              f" from={result.get('from') or 'all'} to={result.get('to') or 'all'}\n")
    buf.write("# Rows with unpriced_calls > 0 are a FLOOR: those calls contributed $0.00.\n")
    writer = csv.writer(buf)
    columns = [group_by, "cost_usd", "model_calls", "tokens_in", "tokens_out",
               "tokens_cache_read", "sessions", "unpriced_calls"]
    writer.writerow(columns)
    for row in result["rows"]:
        writer.writerow([_sanitize(row.get(c, "")) for c in columns])
    totals = result["totals"]
    writer.writerow(["TOTAL", totals["cost_usd"], totals["model_calls"], totals["tokens_in"],
                     totals["tokens_out"],
                     sum(r.get("tokens_cache_read", 0) for r in result["rows"]),
                     sum(r.get("sessions", 0) for r in result["rows"]),
                     totals["unpriced_calls"]])
    return buf.getvalue()
