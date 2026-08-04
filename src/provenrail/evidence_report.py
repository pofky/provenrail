"""Full verification report (printable HTML).

The regime cover (pack.render_cover_html) maps a run to a compliance regime. This module
produces the companion an auditor or lawyer actually reads end to end: the full verification
verdict, every finding grouped by severity, the trusted-time and witness status, the committed
policy result, heuristic coherence signals, and a chronological timeline of what the agent did.

It runs the SAME standalone verifier as `pr verify`, so the report states only what the
verifier proved, in the verifier's own words, and never more. Re-running the verifier on the
enclosed bundle reproduces the verdict, trusting neither the agent, the sink, nor us.
"""

from __future__ import annotations

import html
from typing import Any

from .reports import DISCLAIMER

_EVENT_LABEL = {
    "lifecycle.session_start": "Session start",
    "lifecycle.session_end": "Session end",
    "lifecycle.heartbeat": "Heartbeat",
    "model_call": "Model call",
    "tool_call": "Tool call",
    "mcp_call": "MCP tool call",
    "decision": "Decision",
    "data_access": "Data access",
    "human_oversight": "Human oversight",
    "policy.decision": "Policy decision",
}


def _primary(action: str, payload: dict[str, Any]) -> str:
    p = payload or {}
    if action == "model_call":
        return f"{p.get('provider', '?')} / {p.get('model', '?')}"
    if action in ("tool_call", "mcp_call"):
        return f"{p.get('tool', '?')} -> {p.get('outcome', 'success')}"
    if action == "decision":
        return str(p.get("summary", ""))[:120]
    if action == "data_access":
        return f"{p.get('op', '?')} {p.get('resource', '?')}"
    if action == "human_oversight":
        return f"{p.get('action', '?')} by {p.get('approver', '?')}"
    if action == "policy.decision":
        return f"{p.get('effect', '?')} [{p.get('rule', '?')}] {p.get('reason', '')}"[:120]
    if action == "lifecycle.session_start":
        meta = p.get("meta", {}) or {}
        pol = " (policy committed)" if meta.get("policy_sha256") else ""
        return (", ".join(f"{k}={v}" for k, v in meta.items()
                          if k not in ("policy", "policy_sha256"))[:90] or "new session") + pol
    if action == "lifecycle.session_end":
        return f"{p.get('outcome', '?')} ({p.get('count', '?')} records)"
    return ""


def render_report_html(bundle: dict[str, Any], *, tlog_log_key: str | None = None,
                       witness_pubkeys: dict[str, str] | None = None,
                       pin: dict[str, Any] | None = None) -> str:
    from .server.analytics import verdict as _verdict
    from .verifier.verify import verify_bundle

    rep = verify_bundle(bundle, pin=pin, tlog_log_key=tlog_log_key,
                        witness_pubkeys=witness_pubkeys or {}).to_dict()
    v = _verdict(bundle, tlog_log_key=tlog_log_key, witness_pubkeys=witness_pubkeys or {})
    state = v["state"]
    color = {"witnessed": "#07a06a", "verified": "#07a06a", "amber-proofs": "#b7791f",
             "amber": "#b7791f", "tampered": "#d93a3a"}.get(state, "#b7791f")

    records = [sr.get("record", {}) for sr in bundle.get("records", [])]
    ordered = sorted(records, key=lambda r: r.get("seq", 1 << 30))

    def esc(x: Any) -> str:
        return html.escape(str(x))

    # findings grouped by severity
    def _findings_block(sev: str, title: str) -> str:
        items = [f for f in rep["findings"] if f["severity"] == sev]
        if not items:
            return ""
        lis = "".join(f"<li><code>{esc(f['code'])}</code><span>{esc(f['detail'])}</span></li>"
                      for f in items)
        return f"<h2>{esc(title)} ({len(items)})</h2><ul class='findings {sev}'>{lis}</ul>"

    # timeline
    trows = "".join(
        f"<tr><td class='seq'>{esc(r.get('seq'))}</td>"
        f"<td class='ts'>{esc(str(r.get('ts_utc', ''))[:19])}</td>"
        f"<td class='ev'>{esc(_EVENT_LABEL.get(r.get('action_type'), r.get('action_type')))}</td>"
        f"<td class='pr'>{esc(_primary(r.get('action_type', ''), r.get('payload', {})))}</td></tr>"
        for r in ordered)

    # policy panel
    pol = v.get("policy", {})
    if pol.get("committed"):
        if pol.get("tampered"):
            ptext = "Committed policy was ALTERED after the session started (tampering)."
        elif pol.get("unenforced"):
            ptext = "Committed policy was present but an executed action it denies was recorded."
        elif pol.get("verified"):
            ptext = ("Committed policy verified: the recorded run is consistent with the "
                     "guardrails that were in force, for every re-verifiable rule.")
        else:
            ptext = "A policy was committed for this session."
        policy_panel = f"<h2>Active guardrails</h2><p class='panel'>{esc(ptext)}</p>"
    else:
        policy_panel = ""

    # coherence signals
    signals = v.get("signals", [])
    if signals:
        sl = "".join(f"<li><code>{esc(s['code'])}</code><span>{esc(s['detail'])}</span></li>"
                     for s in signals)
        signal_panel = (f"<h2>Coherence signals ({len(signals)})</h2>"
                        f"<p class='fine'>Heuristic review prompts only. They do not change the "
                        f"cryptographic verdict above.</p><ul class='findings info'>{sl}</ul>")
    else:
        signal_panel = ""

    witness_line = (f"Witnessed by {v['witness_count']} independent "
                    f"part{'y' if v['witness_count'] == 1 else 'ies'}."
                    if v["witness_count"] else "No independent witness cosignature present.")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verification report: {esc(bundle.get('stream_id', ''))[:18]}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap" rel="stylesheet">
<style>
@page{{margin:16mm}}
*{{box-sizing:border-box}}
body{{font:14px/1.6 'DM Sans',-apple-system,Segoe UI,Roboto,sans-serif;color:#0c0f14;max-width:820px;margin:2rem auto;padding:0 1.25rem}}
.eyebrow{{font:600 11px/1 'DM Mono',ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:#07a06a;margin-bottom:.6rem}}
h1{{font-size:1.6rem;margin:0 0 .25rem;letter-spacing:-.02em}}
.sub{{color:#555;margin-bottom:1.25rem}}
.verdict{{display:inline-block;font:600 13px/1 'DM Mono',ui-monospace,monospace;color:#fff;background:{color};padding:.55rem .85rem;border-radius:6px;margin-bottom:.4rem}}
.headline{{color:#333;margin:.3rem 0 1.4rem}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:.3rem 1.5rem;border:1px solid #e2e2e2;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.5rem}}
.grid div{{display:flex;justify-content:space-between;border-bottom:1px solid #f0f0f0;padding:.25rem 0}}
.grid b{{font-family:'DM Mono',ui-monospace,monospace}}
h2{{font-size:1rem;margin:1.6rem 0 .5rem;border-bottom:2px solid #111;padding-bottom:.25rem}}
ul.findings{{list-style:none;padding:0;margin:0}}
ul.findings li{{display:flex;gap:.75rem;padding:.4rem 0;border-bottom:1px solid #f0f0f0;break-inside:avoid}}
ul.findings code{{flex:0 0 200px;font:12px/1.5 'DM Mono',ui-monospace,monospace}}
ul.findings.fail code{{color:#d93a3a}}
ul.findings.warn code{{color:#b7791f}}
ul.findings.info code{{color:#07a06a}}
ul.findings span{{color:#333;font-size:13px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:.4rem}}
th{{text-align:left;border-bottom:2px solid #111;padding:.4rem .4rem;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#666}}
td{{padding:.4rem .4rem;border-bottom:1px solid #eee;vertical-align:top}}
td.seq{{font-family:'DM Mono',ui-monospace,monospace;color:#999;width:3rem}}
td.ts{{font-family:'DM Mono',ui-monospace,monospace;color:#666;white-space:nowrap}}
td.ev{{font-weight:600;white-space:nowrap}}
td.pr{{font-family:'DM Mono',ui-monospace,monospace;color:#333}}
.panel{{background:#f7f7f5;border:1px solid #ececec;border-radius:8px;padding:.7rem .9rem;font-size:13px}}
.fine{{font-size:12px;color:#888;margin:.3rem 0}}
.disc{{margin-top:2rem;padding-top:1rem;border-top:1px solid #e2e2e2;font-size:12px;color:#666}}
</style></head><body>
<div class="eyebrow">Provenrail verification report</div>
<h1>AI agent activity record</h1>
<p class="sub">Stream <code>{esc(bundle.get('stream_id', ''))[:24]}</code>. Re-verify with
<code>pr verify bundle.json</code> or the hosted verifier; this report only restates what that
verifier proves.</p>
<div class="verdict">{esc(v['headline'])}</div>
<p class="headline">{esc(witness_line)}</p>
<div class="grid">
<div><span>Records</span><b>{len(records)}</b></div>
<div><span>Anchors</span><b>{v['anchors']}</b></div>
<div><span>Failures</span><b>{rep['fail']}</b></div>
<div><span>Warnings</span><b>{rep['warn']}</b></div>
<div><span>Witnesses</span><b>{v['witness_count']}</b></div>
<div><span>Badge state</span><b>{esc(state)}</b></div>
</div>
{policy_panel}
{_findings_block("fail", "Failures")}
{_findings_block("warn", "Warnings")}
{_findings_block("info", "Checks performed")}
{signal_panel}
<h2>Activity timeline</h2>
<table><thead><tr><th>#</th><th>Time (UTC)</th><th>Event</th><th>Detail</th></tr></thead>
<tbody>{trows}</tbody></table>
<div class="disc">{esc(DISCLAIMER)}</div>
</body></html>"""
