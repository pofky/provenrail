"""Every server-rendered JavaScript blob must actually parse.

This exists because `/verify`, the page the whole product funnels strangers to, was dead in
released code: an unescaped apostrophe in `operator's` inside a single-quoted JS string threw
`SyntaxError: Unexpected identifier 's'`, so the entire <script> block never parsed and no
handler was ever installed. Drag-and-drop, the file picker and paste-verify all silently did
nothing, and no Python test noticed because the page still returned 200 with the right bytes.

A page that serves perfectly and runs nothing is the worst failure mode a static-rendered app
has, so the JS is extracted and handed to node for a real parse.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)


def _blocks(html: str) -> list[str]:
    """Inline script bodies, skipping JSON-LD and other non-JS script types."""
    out = []
    for match in re.finditer(r"<script([^>]*)>(.*?)</script>", html, re.S):
        attrs, body = match.group(1), match.group(2)
        if "src=" in attrs:
            continue
        if "type=" in attrs and "javascript" not in attrs and "module" not in attrs:
            continue   # application/ld+json and friends
        if body.strip():
            out.append(body)
    return out


def _page_sources() -> list[tuple[str, str]]:
    from provenrail.server import dashboard, verify_page
    pages: list[tuple[str, str]] = []
    for module in (verify_page, dashboard):
        for name, value in vars(module).items():
            if isinstance(value, str) and "<script" in value:
                pages.append((f"{module.__name__}.{name}", value))
    return pages


def test_every_server_rendered_page_has_parseable_javascript(tmp_path):
    sources = _page_sources()
    assert sources, "found no server-rendered HTML to check; the discovery above is wrong"
    checked = 0
    for label, html in sources:
        for i, body in enumerate(_blocks(html)):
            path = tmp_path / f"{label.replace('.', '_')}_{i}.mjs"
            path.write_text(body, encoding="utf-8")
            result = subprocess.run(["node", "--check", str(path)],
                                    capture_output=True, text=True)
            assert result.returncode == 0, (
                f"{label} block {i} is not valid JavaScript, so the whole block is dead in the "
                f"browser:\n{result.stderr}")
            checked += 1
    assert checked >= 2, f"only checked {checked} script blocks; expected the verify page and app"


def test_the_verify_page_apostrophe_regression_specifically(tmp_path):
    """The exact bug: a raw apostrophe inside a single-quoted JS string literal."""
    from provenrail.server import verify_page
    html = next(v for v in vars(verify_page).values()
                if isinstance(v, str) and "verifyPaste" in v)
    for body in _blocks(html):
        assert "operator's" not in body, (
            "a raw apostrophe is back inside the verify page's JavaScript; it terminates the "
            "string literal and kills every handler on the page")
