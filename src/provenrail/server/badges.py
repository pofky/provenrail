"""Embeddable SVG integrity badges.

A badge is a live, self-verifying trust signal: a customer drops
`<img src=".../badge/<share_token>.svg">` into a README, a status page, or a vendor
security page, and it renders the result of the standalone verifier run against the current
record set. Green only when a third-party trusted timestamp covers the records; amber when
integrity holds but no trusted time is present; red when tampering is detected. The badge is
the marketing flywheel: every embed is a checkable claim, not an asserted logo.
"""

from __future__ import annotations

import html

# state -> (right-segment colour, right-segment text)
_STATES = {
    "witnessed": ("#07a06a", "verified + witnessed"),
    "verified": ("#07a06a", "integrity verified"),
    "amber-proofs": ("#b7791f", "proofs, not witnessed"),
    "amber": ("#b7791f", "verified, no timestamp"),
    "tampered": ("#d93a3a", "tampering detected"),
    "empty": ("#5a626e", "no records"),
    "unknown": ("#5a626e", "unknown"),
}

_LABEL = "flight recorder"
# approximate average glyph advance for the 11px sans used below
_CHAR_W = 6.2
_PAD = 9.0


def _seg_width(text: str, extra: float = 0.0) -> float:
    return len(text) * _CHAR_W + _PAD * 2 + extra


def render_badge(state: str) -> str:
    color, status = _STATES.get(state, _STATES["unknown"])
    lw = _seg_width(_LABEL, extra=12.0)  # extra room for the status dot
    rw = _seg_width(status)
    w = lw + rw
    h = 20.0
    label = html.escape(_LABEL)
    stat = html.escape(status)
    dot_cx = 11.0
    label_x = (lw + 8) / 2 + 4  # nudge right of the dot
    status_x = lw + rw / 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" '
        f'role="img" aria-label="{label}: {stat}">'
        f'<title>{label}: {stat}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#fff" stop-opacity=".10"/>'
        f'<stop offset="1" stop-opacity=".10"/></linearGradient>'
        f'<clipPath id="r"><rect width="{w:.0f}" height="{h:.0f}" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw:.0f}" height="{h:.0f}" fill="#14171c"/>'
        f'<rect x="{lw:.0f}" width="{rw:.0f}" height="{h:.0f}" fill="{color}"/>'
        f'<rect width="{w:.0f}" height="{h:.0f}" fill="url(#s)"/>'
        f'</g>'
        f'<circle cx="{dot_cx:.0f}" cy="10" r="3.2" fill="#2ee6a6"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{label_x:.0f}" y="15" fill="#010101" fill-opacity=".3">{label}</text>'
        f'<text x="{label_x:.0f}" y="14" fill="#e7e7e7">{label}</text>'
        f'<text x="{status_x:.0f}" y="15" fill="#010101" fill-opacity=".3">{stat}</text>'
        f'<text x="{status_x:.0f}" y="14">{stat}</text>'
        f'</g></svg>'
    )
