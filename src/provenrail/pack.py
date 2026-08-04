"""One-click evidence pack.

Produces a single self-contained ZIP a compliance owner can hand to an auditor or regulator
with no engineering involvement: the verifiable bundle, a regime attestation in JSON and
Markdown, the optional client pin, a plain-text verification guide, and a manifest listing the
SHA-256 of every file. The pack is self-verifying: the auditor reruns `pr verify` (or the
hosted verifier) on the enclosed bundle and gets the same result, trusting neither the agent,
the sink, nor us. Nothing in the pack is a certification of compliance; it is evidence.
"""

from __future__ import annotations

import html
import io
import json
import zipfile
from typing import Any

from .canonical import sha256_hex
from .reports import DISCLAIMER, generate_attestation, render_markdown

_GUIDE = """How to verify this evidence pack
=================================

This pack contains a tamper-evident record of what an AI agent did, plus an attestation
mapping it to a regulatory regime. You do not have to trust the party who produced it.

1. Install the open-source verifier:
       pip install provenrail

2. Verify the record, trusting neither the agent nor the sink that stored it:
       pr verify bundle.json{pin_arg}

   A clean result means every record is signed, hash-chained, and (when a trusted
   timestamp is present) bound to an RFC 3161 time, with nothing altered, reordered,
   deleted, or back-dated. Any tampering is reported.

3. Or verify in a browser with no install: open https://provenrail.com/verify and drop in
   bundle.json (and pin.json if present). The file is checked locally in your browser and is
   never uploaded.

4. Cross-check file integrity against MANIFEST.json (SHA-256 of each file).

5. If the record stores fingerprints of prompts/responses rather than their text (the privacy
   default), and you were given the actual transcript separately, prove it is authentic:
       pr verify-content bundle.json --file the-transcript.json
   A MATCH means that exact content is what the record committed to; NO MATCH means it differs.

What this proves, and what it does not
--------------------------------------
Proven: the recorded events are tamper-evident and, once received by the off-box sink,
immutable and independently verifiable. NOT proven: completeness. A record cannot prove
that nothing was withheld before it was recorded.

Legal notice
------------
{disclaimer}
"""


def render_cover_html(attestation: dict[str, Any]) -> str:
    """A self-contained, print-to-PDF cover page for the evidence pack."""
    s = attestation["summary"]
    verified = attestation["integrity"]["verified"]
    has_trusted_time = bool(s["trusted_timestamps"])
    if not verified:
        state, color = "TAMPERING DETECTED", "#d93a3a"
    elif not has_trusted_time:
        # consistent with the proof page and badge: integrity holds, but no third-party time
        state, color = "VERIFIED, NO TRUSTED TIMESTAMP", "#b7791f"
    else:
        state, color = "VERIFIED", "#07a06a"
    def _stcolor(status: str) -> str:
        if status.startswith("FAILED"):
            return "#d93a3a"
        if status == "evidence present":
            return "#07a06a"
        return "#b7791f"  # gap / no evidence

    rows = "".join(
        f"<tr><td>{html.escape(m['requirement'])}</td>"
        f"<td class='st' style='color:{_stcolor(m['status'])}'>{html.escape(m['status'])}</td></tr>"
        for m in attestation["regime_mapping"]
    )
    events = "".join(
        f"<li><span>{html.escape(k)}</span><b>{v}</b></li>"
        for k, v in sorted(s["events_by_type"].items())
    )
    ts = len(s["trusted_timestamps"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Evidence pack: {html.escape(attestation['regime'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap" rel="stylesheet">
<style>
@page{{margin:18mm}}
*{{box-sizing:border-box}}
body{{font:14px/1.6 'DM Sans',-apple-system,Segoe UI,Roboto,sans-serif;color:#0c0f14;max-width:760px;margin:2rem auto;padding:0 1.25rem}}
.eyebrow{{font:600 11px/1 'DM Mono',ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:#07a06a;margin-bottom:.6rem}}
h1{{font-size:1.7rem;margin:0 0 .25rem;letter-spacing:-.02em}}
.sub{{color:#555;margin-bottom:1.5rem}}
.verdict{{display:inline-block;font:600 13px/1 'DM Mono',ui-monospace,monospace;color:#fff;background:{color};padding:.5rem .8rem;border-radius:6px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:.4rem 1.5rem;border:1px solid #e2e2e2;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.5rem}}
.grid div{{display:flex;justify-content:space-between;border-bottom:1px solid #f0f0f0;padding:.25rem 0}}
.grid b{{font-family:'DM Mono',ui-monospace,monospace}}
h2{{font-size:1rem;margin:1.5rem 0 .5rem;border-bottom:2px solid #111;padding-bottom:.25rem}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td{{padding:.5rem .4rem;border-bottom:1px solid #eee;vertical-align:top}}
.st{{white-space:nowrap;color:#07a06a;font-family:'DM Mono',ui-monospace,monospace;font-size:12px}}
ul{{list-style:none;padding:0;columns:2;font-family:'DM Mono',ui-monospace,monospace;font-size:13px}}
ul li{{display:flex;justify-content:space-between;border-bottom:1px solid #f0f0f0;padding:.2rem 0;break-inside:avoid}}
.method{{font-size:13px;color:#333}}
.disc{{margin-top:2rem;padding-top:1rem;border-top:1px solid #e2e2e2;font-size:12px;color:#666}}
.fine{{font-size:12px;color:#888;margin-top:.5rem}}
</style></head><body>
<div class="eyebrow">Provenrail evidence pack</div>
<h1>AI agent activity, {html.escape(attestation['regime'])}</h1>
<p class="sub">Tamper-evident, independently verifiable record. Re-verify with <code>pr verify bundle.json</code> or in your browser at <a href="https://provenrail.com/verify">provenrail.com/verify</a>.</p>
<div class="verdict">Integrity: {state}</div>
<p class="fine">Evidence strength: {html.escape(attestation['evidence_strength'])}</p>
<div class="grid">
<div><span>Stream</span><b>{html.escape(str(s['stream_id'])[:18])}</b></div>
<div><span>Records</span><b>{s['record_count']}</b></div>
<div><span>Window from</span><b>{html.escape(str(s['first_received'])[:19])}</b></div>
<div><span>Window to</span><b>{html.escape(str(s['last_received'])[:19])}</b></div>
<div><span>Anchors</span><b>{s['anchors']}</b></div>
<div><span>Trusted timestamps</span><b>{ts}</b></div>
</div>
<h2>Events by type</h2><ul>{events}</ul>
<h2>{html.escape(attestation['regime'])} mapping</h2>
<table><tbody>{rows}</tbody></table>
<h2>Integrity method</h2><p class="method">{html.escape(attestation['integrity']['method'])}</p>
<p class="fine">{html.escape(attestation['integrity']['completeness_caveat'])}</p>
<p class="fine">Retention requirement: {html.escape(attestation['retention_requirement'])}</p>
<div class="disc">{html.escape(DISCLAIMER)}</div>
</body></html>"""


def build_pack(bundle: dict[str, Any], regime: str = "generic",
               pin: dict[str, Any] | None = None, tlog_log_key: str | None = None,
               witness_pubkeys: dict[str, str] | None = None) -> bytes:
    """Return the bytes of a ZIP evidence pack for the given bundle and regime."""
    from .evidence_report import render_report_html

    attestation = generate_attestation(bundle, regime=regime, pin=pin)
    markdown = render_markdown(attestation)
    cover = render_cover_html(attestation)
    report = render_report_html(bundle, tlog_log_key=tlog_log_key,
                                witness_pubkeys=witness_pubkeys, pin=pin)
    guide = _GUIDE.format(
        pin_arg=" --pin pin.json" if pin else "",
        disclaimer=DISCLAIMER,
    )

    files: dict[str, bytes] = {
        "bundle.json": json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8"),
        f"attestation-{regime}.json": json.dumps(attestation, indent=2,
                                                 ensure_ascii=False).encode("utf-8"),
        f"attestation-{regime}.md": markdown.encode("utf-8"),
        "cover.html": cover.encode("utf-8"),
        "report.html": report.encode("utf-8"),
        "VERIFY.txt": guide.encode("utf-8"),
    }
    if pin is not None:
        files["pin.json"] = json.dumps(pin, indent=2, ensure_ascii=False).encode("utf-8")

    manifest = {
        "format": "flightrecorder.evidence-pack/1",
        "regime": regime,
        "stream_id": bundle.get("stream_id"),
        "integrity_verified": attestation["integrity"]["verified"],
        "independently_timed": attestation["integrity"]["independently_timed"],
        "evidence_strength": attestation["evidence_strength"],
        "files": {name: {"sha256": sha256_hex(data), "bytes": len(data)}
                  for name, data in files.items()},
        "disclaimer": DISCLAIMER,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    buf = io.BytesIO()
    # Fixed timestamp so identical inputs produce byte-identical packs (reproducible evidence).
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[name])
    return buf.getvalue()
