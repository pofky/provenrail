"""Coherence and anomaly signals over a recorded run.

These are HEURISTICS, not proofs. The cryptographic checks (hash chain, server receipt chain,
anchors, transparency log) decide whether a record is authentic and untampered; nothing here can
promote or demote that verdict. What this module does is surface structural oddities a human
reviewer or a dashboard should look at: clock skew, suspicious gaps, missing token usage, a run
with no human governance, a self-inconsistent seal. Every signal is "warn" or "info", never a
hard fail, and the language is careful to say "look at this", never "this is tampering".

This is the honest complement to the completeness boundary: we cannot prove a hostile agent
logged everything, but we CAN point at the seams where something looks off.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# A consecutive wall-clock gap larger than this is surfaced as a possible un-instrumented window.
GAP_SECONDS = 3600.0
# Backwards clock movement beyond this between consecutive records is flagged (sub-second jitter
# from batching/formatting is normal and ignored).
BACKWARDS_TOLERANCE_S = 1.0


def _parse(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, TypeError):
        return None


def detect(ordered: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return a list of {severity, code, detail} signals for an emission-ordered record list."""
    out: list[dict[str, str]] = []
    if not ordered:
        return out

    def add(severity: str, code: str, detail: str) -> None:
        out.append({"severity": severity, "code": code, "detail": detail})

    # 1 + 2. timestamp monotonicity and large gaps
    prev_ts: datetime | None = None
    prev_seq: Any = None
    for rec in ordered:
        ts = _parse(rec.get("ts_utc", ""))
        seq = rec.get("seq")
        if ts is not None and prev_ts is not None:
            delta = (ts - prev_ts).total_seconds()
            if delta < -BACKWARDS_TOLERANCE_S:
                add("warn", "nonmonotonic_ts",
                    f"seq {seq}: timestamp {rec.get('ts_utc')} is earlier than the previous "
                    f"record's (seq {prev_seq}); clock skew or reordering (hashes still intact)")
            elif delta > GAP_SECONDS:
                add("info", "time_gap",
                    f"seq {prev_seq} to {seq}: {int(delta)}s passed between consecutive records; "
                    f"a long quiet window worth confirming was not an un-instrumented period")
        prev_ts, prev_seq = ts or prev_ts, seq

    # 3. duplicate record ids
    seen: dict[str, int] = {}
    for rec in ordered:
        rid = rec.get("record_id")
        if rid is None:
            continue
        if rid in seen:
            add("warn", "duplicate_record_id",
                f"record_id {rid} appears at seq {seen[rid]} and {rec.get('seq')}")
        else:
            seen[rid] = rec.get("seq")

    # 4. model calls without token usage (cannot cost or spend-cap them)
    missing_usage = sum(1 for r in ordered if r.get("action_type") == "model_call"
                        and not (r.get("payload", {}) or {}).get("usage"))
    if missing_usage:
        add("info", "usage_missing",
            f"{missing_usage} model call(s) recorded no token usage; cost and spend-cap "
            f"accounting cannot be reconstructed for them")

    # 5. a run that touched a model but recorded no human governance at all
    actions = [r.get("action_type") for r in ordered]
    if "model_call" in actions and not ({"decision", "human_oversight"} & set(actions)):
        add("info", "no_governance",
            "the session made model calls but recorded no decision or human-oversight event; "
            "fine for an autonomous job, notable for one expected to be supervised")

    # 6. self-inconsistent seal: the seal's own count should equal its sequence position
    for rec in ordered:
        if rec.get("action_type") != "lifecycle.session_end":
            continue
        payload = rec.get("payload", {}) or {}
        stated = payload.get("count")
        try:
            stated_int = int(stated)
        except (TypeError, ValueError):
            continue
        if stated_int != rec.get("seq"):
            add("warn", "seal_count_mismatch",
                f"seal claims {stated_int} prior records but sits at seq {rec.get('seq')}")

    return out
