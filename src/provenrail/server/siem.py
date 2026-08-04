"""SIEM-friendly newline-delimited JSON export.

Compliance and security teams want agent activity in the pipeline they already run (Splunk,
Elastic, Datadog), not only as a downloadable bundle. This flattens each record into one
self-describing JSON line with the fields a SIEM indexes on: identity, action, target,
outcome, timestamps, and the cryptographic hashes that tie the line back to the verifiable
bundle. The line carries hashes, not raw content (content stays hash-only unless the stream
was configured to capture it), so piping to a SIEM does not leak prompts by default.
"""

from __future__ import annotations

import json
from typing import Any

from .analytics import _event_summary


def _flatten(server_record: dict[str, Any], stream_id: str) -> dict[str, Any]:
    rec = server_record.get("record", {})
    payload = rec.get("payload", {}) or {}
    at = rec.get("action_type", "")
    line: dict[str, Any] = {
        "ts": rec.get("ts_utc"),
        "received_ts": server_record.get("recv_ts"),
        "stream_id": stream_id,
        "session_id": rec.get("session_id"),
        "seq": rec.get("seq"),
        "recv_seq": server_record.get("recv_seq"),
        "action": at,
        "summary": _event_summary(at, payload),
        "record_hash": rec.get("record_hash"),
        "server_record_hash": server_record.get("server_record_hash"),
        "agent_key": rec.get("pubkey"),
    }
    # promote the indexable, non-sensitive payload fields per action type
    for k in ("provider", "model", "tool", "outcome", "resource", "op", "action",
              "approver", "confidence", "summary"):
        if k in payload and k not in line:
            line[f"payload_{k}" if k in ("summary", "action") else k] = payload[k]
    if at == "model_call" and isinstance(payload.get("usage"), dict):
        line["usage"] = payload["usage"]
    return line


def bundle_to_ndjson(bundle: dict[str, Any]) -> str:
    """Return one compact JSON object per line for every record in the bundle."""
    stream_id = bundle.get("stream_id")
    out = []
    for sr in bundle.get("records", []):
        out.append(json.dumps(_flatten(sr, stream_id), separators=(",", ":"),
                              ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")
