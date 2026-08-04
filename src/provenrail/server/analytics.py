"""Read-only analytics over a stream's stored records.

Turns the raw receipt-chain records into the things a dashboard shows: per-session summaries,
event timelines, token/cost rollups, and a compact integrity verdict. None of this is signed
or hashed; it is a presentation layer derived from the immutable records. Cost is an estimate
(see pricing.py) and is labelled as such.
"""

from __future__ import annotations

from typing import Any

from ..chain import (
    DATA_ACCESS,
    DECISION,
    GENESIS,
    HEARTBEAT,
    HUMAN_OVERSIGHT,
    MODEL_CALL,
    POLICY_DECISION,
    SEAL,
    TOOL_CALL,
)
from ..pricing import cost_for

ACTION_LABEL = {
    GENESIS: "Session started",
    SEAL: "Session sealed",
    HEARTBEAT: "Heartbeat",
    MODEL_CALL: "Model call",
    TOOL_CALL: "Tool call",
    "mcp_call": "MCP call",
    DECISION: "Decision",
    DATA_ACCESS: "Data access",
    HUMAN_OVERSIGHT: "Human oversight",
    POLICY_DECISION: "Policy decision",
}


def _ts_delta_seconds(a: str, b: str) -> float | None:
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    try:
        return (datetime.strptime(a, fmt) - datetime.strptime(b, fmt)).total_seconds()
    except (ValueError, TypeError):
        return None


def _event_summary(action_type: str, payload: dict[str, Any]) -> str:
    """One short human line describing an event, without leaking hashed content."""
    p = payload or {}
    if action_type == MODEL_CALL:
        return f"{p.get('provider', '?')} / {p.get('model', '?')}"
    if action_type in (TOOL_CALL, "mcp_call"):
        return f"{p.get('tool', '?')} -> {p.get('outcome', 'success')}"
    if action_type == DECISION:
        return str(p.get("summary", ""))[:140]
    if action_type == DATA_ACCESS:
        return f"{p.get('op', '?')} {p.get('resource', '?')}"
    if action_type == HUMAN_OVERSIGHT:
        return str(p.get("action", ""))[:140]
    if action_type == GENESIS:
        meta = p.get("meta") or {}
        return ", ".join(f"{k}={v}" for k, v in meta.items())[:140] if meta else "new session"
    if action_type == SEAL:
        return f"{p.get('outcome', '?')} ({p.get('count', '?')} records, trigger={p.get('trigger', '?')})"
    if action_type == POLICY_DECISION:
        # These are the events a security reviewer opens the timeline FOR, so a blank
        # summary here is worse than for any other type: a blocked wire transfer rendered
        # as an empty line in the dashboard and in the SIEM export.
        effect = str(p.get("effect", "?")).upper()
        target = p.get("target") or p.get("event_type") or "?"
        reason = str(p.get("reason", ""))[:90]
        rule = p.get("rule") or "no rule"
        return f"{effect} {target} [{rule}]" + (f": {reason}" if reason else "")
    return ""


def session_timeline(records: list[dict[str, Any]], session_id: str) -> dict[str, Any]:
    """Full event list for one session, ordered by client seq, with per-call cost."""
    rows = [r for r in records if r["record"].get("session_id") == session_id]
    rows.sort(key=lambda r: r["record"].get("seq", 1 << 30))
    events = []
    for r in rows:
        rec = r["record"]
        at = rec.get("action_type", "")
        payload = rec.get("payload", {}) or {}
        ev: dict[str, Any] = {
            "seq": rec.get("seq"),
            "recv_seq": r.get("recv_seq"),
            "ts_utc": rec.get("ts_utc"),
            "recv_ts": r.get("recv_ts"),
            "action_type": at,
            "label": ACTION_LABEL.get(at, at),
            "summary": _event_summary(at, payload),
            "record_hash": rec.get("record_hash", ""),
        }
        if at == MODEL_CALL:
            c = cost_for(payload.get("model", ""), payload.get("usage"))
            ev["cost"] = c
            ev["provider"] = payload.get("provider")
            ev["model"] = payload.get("model")
        events.append(ev)
    summary = next((s for s in summarize(records)["sessions"] if s["session_id"] == session_id), None)
    return {"session_id": session_id, "summary": summary, "events": events}


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Group records into sessions and roll up totals, tokens, and cost."""
    sessions: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for r in records:
        rec = r["record"]
        sid = rec.get("session_id", "?")
        if sid not in sessions:
            sessions[sid] = {
                "session_id": sid,
                "started_at": None,
                "ended_at": None,
                "sealed": False,
                "outcome": None,
                "events": 0,
                "model_calls": 0,
                "tool_calls": 0,
                "decisions": 0,
                "policy_denials": 0,
                "policy_allows": 0,
                "denied_rules": [],
                "tokens_in": 0,
                "tokens_out": 0,
                "cost_usd": 0.0,
                "unpriced_calls": 0,
                "models": [],
                "action_counts": {},
                "first_recv_seq": r.get("recv_seq"),
                "last_recv_seq": r.get("recv_seq"),
                "agent_key": (rec.get("pubkey") or "")[:16],
                "meta": {},
            }
            order.append(sid)
        s = sessions[sid]
        at = rec.get("action_type", "")
        payload = rec.get("payload", {}) or {}
        s["events"] += 1
        s["action_counts"][at] = s["action_counts"].get(at, 0) + 1
        s["last_recv_seq"] = r.get("recv_seq")
        ts = rec.get("ts_utc")
        if at == GENESIS:
            s["started_at"] = ts
            s["meta"] = payload.get("meta") or {}
        if s["started_at"] is None:
            s["started_at"] = ts
        if at == SEAL:
            s["sealed"] = True
            s["ended_at"] = ts
            s["outcome"] = payload.get("outcome")
        s["ended_at"] = ts if s["ended_at"] is None or at == SEAL else max_ts(s["ended_at"], ts)
        if at == MODEL_CALL:
            s["model_calls"] += 1
            model = payload.get("model", "")
            if model and model not in s["models"]:
                s["models"].append(model)
            c = cost_for(model, payload.get("usage"))
            s["tokens_in"] += c["tokens_in"]
            s["tokens_out"] += c["tokens_out"]
            s["cost_usd"] = round(s["cost_usd"] + c["cost_usd"], 6)
            if not c["priced"]:
                s["unpriced_calls"] += 1
        elif at in (TOOL_CALL, "mcp_call"):
            s["tool_calls"] += 1
        elif at == DECISION:
            s["decisions"] += 1
        elif at == POLICY_DECISION:
            # A denial is the single most important thing a reviewer wants surfaced, so it
            # gets its own counter rather than being buried in action_counts.
            if str(payload.get("effect", "")).lower() == "deny":
                s["policy_denials"] += 1
                rule = payload.get("rule")
                if rule and rule not in s["denied_rules"]:
                    s["denied_rules"].append(rule)
            else:
                s["policy_allows"] += 1

    session_list = []
    for sid in order:
        s = sessions[sid]
        s["duration_s"] = (_ts_delta_seconds(s["ended_at"], s["started_at"])
                           if s["started_at"] and s["ended_at"] else None)
        session_list.append(s)
    session_list.sort(key=lambda s: s["started_at"] or "", reverse=True)

    totals = {
        "sessions": len(session_list),
        "events": sum(s["events"] for s in session_list),
        "model_calls": sum(s["model_calls"] for s in session_list),
        "tool_calls": sum(s["tool_calls"] for s in session_list),
        "tokens_in": sum(s["tokens_in"] for s in session_list),
        "tokens_out": sum(s["tokens_out"] for s in session_list),
        "cost_usd": round(sum(s["cost_usd"] for s in session_list), 6),
        "unpriced_calls": sum(s["unpriced_calls"] for s in session_list),
        "open_sessions": sum(1 for s in session_list if not s["sealed"]),
        "policy_denials": sum(s["policy_denials"] for s in session_list),
        "policy_allows": sum(s["policy_allows"] for s in session_list),
    }
    return {"totals": totals, "sessions": session_list}


def max_ts(a: str, b: str | None) -> str:
    if not b:
        return a
    return a if a >= b else b


def verdict(bundle: dict[str, Any], tlog_log_key: str | None = None,
            witness_pubkeys: dict[str, str] | None = None) -> dict[str, Any]:
    """Run the standalone verifier and compress it to a dashboard badge state.

    Two orthogonal strength axes: a trusted RFC 3161 timestamp (trusted external time) and a
    witnessed transparency-log inclusion (independent anti-equivocation). Witnessing is the
    strongest signal so it takes the headline; a trusted timestamp without witnessing keeps
    the existing 'verified' green; proofs present but unwitnessed is amber-proofs."""
    from ..verifier.verify import verify_bundle
    rep = verify_bundle(bundle, tlog_log_key=tlog_log_key, witness_pubkeys=witness_pubkeys or {})
    fails = sum(1 for f in rep.findings if f.severity == "fail")
    warns = sum(1 for f in rep.findings if f.severity == "warn")
    codes = {f.code for f in rep.findings}
    anchors = bundle.get("anchors", [])
    witness_count = sum(1 for f in rep.findings if f.code == "tlog_cosig_valid")
    no_trusted_time = not anchors or bool(codes & {"local_anchor_only", "no_anchor"})
    if not rep.ok:
        state = "tampered"
    elif "tlog_inclusion_witnessed_ok" in codes:
        state = "witnessed"
    elif no_trusted_time:
        state = "amber-proofs" if "tlog_inclusion_unwitnessed" in codes else "amber"
    else:
        state = "verified"
    headline = {
        "witnessed": (f"Integrity verified, witnessed by {witness_count} independent "
                      f"part{'y' if witness_count == 1 else 'ies'}"),
        "verified": "Integrity verified",
        "amber-proofs": "Integrity verified, append-only proofs present, not witnessed",
        "amber": "Integrity verified, no trusted timestamp",
        "tampered": "Tampering detected",
    }[state]
    # Heuristic coherence + governance signals (never change `state`; they are review prompts).
    signal_codes = {"nonmonotonic_ts", "time_gap", "duplicate_record_id", "usage_missing",
                    "no_governance", "seal_count_mismatch", "policy_not_enforced"}
    signals = [{"severity": f.severity, "code": f.code, "detail": f.detail}
               for f in rep.findings if f.code in signal_codes]
    policy = {
        "committed": bool(codes & {"policy_verified", "policy_commit_mismatch", "policy_not_enforced"}),
        "verified": "policy_verified" in codes,
        "tampered": "policy_commit_mismatch" in codes,
        "unenforced": "policy_not_enforced" in codes,
    }
    return {
        "ok": rep.ok,
        "state": state,
        "fails": fails,
        "warns": warns,
        "anchors": len(anchors),
        "witness_count": witness_count,
        "headline": headline,
        "signals": signals,
        "policy": policy,
    }
