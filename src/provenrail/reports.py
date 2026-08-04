"""Regime evidence reports: map a verified evidence bundle to a regulatory regime.

Deliberately NOT called an attestation report in anything a customer reads. In assurance
that phrase names a formal opinion issued by a licensed practitioner under a standard such
as ISAE 3000, and nobody here is one. This states which recorded evidence exists and which
requirement it corresponds to. Drawing a conclusion from that is the regulated entity's
job, and their auditor's.

Positioning is load-bearing and legally deliberate: this produces EVIDENCE, it does not
certify compliance. The regulated entity (provider/deployer/covered entity) certifies
compliance using this evidence. Every report states this plainly.

Supported regimes:
  - eu-ai-act : Article 12 record-keeping (automatic logging of events over the lifetime)
  - hipaa     : 45 CFR 164.312(b) audit controls
  - generic   : a plain integrity summary with no regime mapping
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .verifier.verify import verify_bundle

DISCLAIMER = (
    "This document is a technical evidence record. It is NOT a certification, an audit "
    "opinion, or legal advice, and it does not state or imply that any legal or regulatory "
    "requirement is met. 'Evidence present' means only that Provenrail captured records of the "
    "indicated kind; whether those records satisfy any obligation is a determination that rests "
    "solely with the regulated entity (provider, deployer, or covered entity) and its qualified "
    "auditors and counsel. Recorded times are independently reliable only where an RFC 3161 (or "
    "equivalent) trusted-time anchor is present; without one, times are self-asserted by the sink "
    "operator. Append-only integrity and tamper-evidence are attested cryptographically; "
    "COMPLETENESS (that no event was withheld before it was recorded) is NOT attested and cannot "
    "be guaranteed from within the agent's trust domain. Provided as-is, without warranty of any "
    "kind."
)

# Status vocabulary is deliberately technical, never a legal conclusion.
_PRESENT = "evidence present"
_ABSENT = "no evidence captured"
_TIME_GAP = "gap: time is self-asserted (no RFC 3161 trusted timestamp)"
_INTEGRITY_FAIL = "FAILED: integrity check did not pass (possible tampering)"

_RETENTION = {
    "eu-ai-act": ("Art. 19/26 state at least 6 months, or longer where Union or national law "
                  "requires. Whether and how it applies to you is your determination"),
    "hipaa": ("45 CFR 164.316(b)(2)(i) states 6 years from creation or last-in-effect date. "
              "Whether and how it applies to you is your determination"),
    "generic": "whatever your own retention policy requires; nothing is asserted here",
}


def _summary(bundle: dict[str, Any]) -> dict[str, Any]:
    records = bundle.get("records", [])
    client = [r["record"] for r in records]
    by_action = Counter(r.get("action_type", "unknown") for r in client)
    recv_ts = [r.get("recv_ts") for r in records if r.get("recv_ts")]
    anchors = bundle.get("anchors", [])
    trusted_times = [
        a["receipt"].get("gen_time") for a in anchors
        if a.get("receipt", {}).get("kind") == "rfc3161"
    ]
    return {
        "stream_id": bundle.get("stream_id"),
        "record_count": len(records),
        "events_by_type": dict(by_action),
        "first_received": min(recv_ts) if recv_ts else None,
        "last_received": max(recv_ts) if recv_ts else None,
        "anchors": len(anchors),
        "trusted_timestamps": trusted_times,
    }


def generate_attestation(bundle: dict[str, Any], regime: str = "generic",
                         pin: dict[str, Any] | None = None) -> dict[str, Any]:
    regime = regime.lower()
    if regime not in _RETENTION:
        raise ValueError(f"unknown regime {regime!r}; choose eu-ai-act, hipaa, or generic")
    rep = verify_bundle(bundle, pin=pin)
    summary = _summary(bundle)
    verified = rep.ok
    trusted_time = bool(summary["trusted_timestamps"])

    if not verified:
        strength = "INTEGRITY CHECK FAILED: tampering detected, this evidence cannot be relied on"
    elif not trusted_time:
        strength = ("tamper-evident only: recorded times are self-asserted by the sink operator "
                    "(no RFC 3161 trusted timestamp). Anchor with trusted time before relying on "
                    "this for an audit.")
    else:
        strength = "tamper-evident and independently timed"

    integrity = {
        "verified": verified,
        "independently_timed": trusted_time,
        "trusted_timestamp_count": len(summary["trusted_timestamps"]),
        "method": "Ed25519-signed client hash chain + independent server receipt chain"
                  + (", Merkle-anchored to RFC 3161 trusted timestamps" if trusted_time
                     else " (no RFC 3161 trusted timestamp on this bundle)")
                  + "; verified by the open-source pr-verify tool, which trusts neither the agent "
                    "nor the sink.",
        "findings": rep.to_dict(),
        "time_caveat": ("Recorded times carry an independent RFC 3161 trusted-time anchor."
                        if trusted_time else
                        "No trusted-time anchor: an auditor may treat every recorded time as "
                        "self-asserted by the sink operator. Run the sink with "
                        "`pr serve --anchor rfc3161` to anchor trusted time."),
        "completeness_caveat": "Tamper-evidence and immutability of recorded events are "
                               "attested. Completeness (that no event was withheld before "
                               "recording) is NOT attested and is not technically possible to "
                               "guarantee from within the agent's trust domain.",
    }

    mapping = _regime_mapping(regime, summary, verified=verified, trusted_time=trusted_time)
    return {
        "format": "flightrecorder.attestation/1",
        "regime": regime,
        "generated_for_stream": summary["stream_id"],
        "evidence_strength": strength,
        "summary": summary,
        "integrity": integrity,
        "regime_mapping": mapping,
        "retention_requirement": _RETENTION[regime],
        "disclaimer": DISCLAIMER,
    }


def _regime_mapping(regime: str, summary: dict[str, Any], *, verified: bool,
                    trusted_time: bool) -> list[dict[str, str]]:
    et = summary["events_by_type"]
    has = lambda *types: any(t in et for t in types)  # noqa: E731
    st = lambda b: _PRESENT if b else _ABSENT  # noqa: E731
    has_records = summary["record_count"] > 0
    n_ts = len(summary["trusted_timestamps"])
    # Integrity-with-time control: fail on tampering, gap when time is self-asserted.
    integrity_time = _INTEGRITY_FAIL if not verified else (_PRESENT if trusted_time else _TIME_GAP)
    integrity_only = _INTEGRITY_FAIL if not verified else _PRESENT

    if regime == "eu-ai-act":
        return [
            {"requirement": "Art. 12(1): automatic recording of events (logs) over the lifetime",
             "evidence": f"{summary['record_count']} events automatically recorded with a "
                         f"genesis and seal per session", "status": st(has_records)},
            {"requirement": "Art. 12(2)(a): events relevant to identifying risk situations",
             "evidence": "model calls, tool calls, decisions and data-access events recorded",
             "status": st(has("model_call", "tool_call", "decision", "data_access"))},
            {"requirement": "Art. 12(2)(c) / Art. 26(5): events enabling deployer monitoring",
             "evidence": "per-event actor, action, target and outcome recorded",
             "status": st(has_records)},
            {"requirement": "Record integrity and reliable time",
             "evidence": f"tamper-evident dual hash chain; {n_ts} RFC 3161 trusted timestamp(s)",
             "status": integrity_time},
            {"requirement": "Human oversight actions (Art. 14) recorded where applicable",
             "evidence": "human_oversight events recorded when emitted",
             "status": st(has("human_oversight"))},
        ]
    if regime == "hipaa":
        return [
            {"requirement": "164.312(b): mechanisms that record and examine activity in systems "
                            "that contain or use ePHI",
             "evidence": f"{summary['record_count']} activity records with actor, action, target, "
                         f"timestamp and outcome", "status": st(has_records)},
            {"requirement": "Record integrity (tamper detection)",
             "evidence": "Ed25519-signed hash chain plus independent server receipt chain",
             "status": integrity_only},
            {"requirement": "Reliable timestamps",
             "evidence": f"{n_ts} RFC 3161 trusted timestamp(s)",
             "status": _PRESENT if trusted_time else _TIME_GAP},
            {"requirement": "Data-access events on ePHI captured",
             "evidence": "data_access events recorded when emitted",
             "status": st(has("data_access"))},
        ]
    return [
        {"requirement": "Integrity of recorded events",
         "evidence": "tamper-evident dual hash chain, externally anchored",
         "status": integrity_time},
    ]


def render_markdown(att: dict[str, Any]) -> str:
    s = att["summary"]
    integ = att["integrity"]
    n_ts = len(s["trusted_timestamps"])
    timed = (f"YES ({n_ts} RFC 3161 trusted timestamp{'' if n_ts == 1 else 's'})"
             if integ["independently_timed"] else "NO, recorded times are self-asserted")
    lines = [
        f"# Provenrail evidence record: {att['regime']}",
        "",
        "_Evidence record, not a certification. See the disclaimer at the end._",
        "",
        f"Stream: `{s['stream_id']}`",
        f"Records: {s['record_count']}  |  Anchors: {s['anchors']}  |  "
        f"Trusted timestamps: {n_ts}",
        f"Window: {s['first_received']} to {s['last_received']}",
        "",
        f"Integrity verified: {'YES' if integ['verified'] else 'NO, TAMPERING DETECTED'}",
        f"Independently timed: {timed}",
        f"Evidence strength: {att['evidence_strength']}",
        "",
    ]
    if not integ["verified"]:
        lines += ["> WARNING: integrity verification FAILED. The recorded events may have been "
                  "altered; do not rely on this evidence.", ""]
    elif not integ["independently_timed"]:
        lines += ["> WARNING: no trusted timestamp. An auditor may treat every recorded time as "
                  "self-asserted by the sink operator. Anchor the sink with RFC 3161 trusted time "
                  "(`pr serve --anchor rfc3161`) before relying on this report for an audit.", ""]
    lines += ["## Events by type"]
    for k, v in sorted(s["events_by_type"].items()):
        lines.append(f"- {k}: {v}")
    lines += ["", "## Regime mapping", ""]
    for m in att["regime_mapping"]:
        lines += [f"### {m['requirement']}", f"- Status: {m['status']}",
                  f"- Evidence: {m['evidence']}", ""]
    lines += [f"Retention requirement: {att['retention_requirement']}", "",
              "## Integrity method", att["integrity"]["method"], "",
              "## Completeness caveat", att["integrity"]["completeness_caveat"], "",
              "---", att["disclaimer"]]
    return "\n".join(lines)
