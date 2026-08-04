"""Homepage live-tamper widget regression guard.

The marketing site's /try-it widget (web/index.html) loads web/demo-bundle.json, verifies it
with the open-source web/verify.js, and on "flip one byte" mutates one server_record_hash and
re-verifies. This test runs the identical flow in Node so that a broken hero demo (a regenerated
fixture, a rotated demo witness key, or a verifier change) fails in CI rather than silently
shipping a widget that can no longer show green-then-red.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).parent
SCRIPT = HERE / "js" / "widget_demo.mjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def test_homepage_widget_demo_green_then_red():
    res = subprocess.run(["node", str(SCRIPT)], capture_output=True, text=True)
    assert res.returncode == 0, (res.stdout + res.stderr)
