"""Shared test fixtures.

Critically: neutralize any ambient commercial license so the suite is deterministic on every
machine. `create_app` falls back to `license.load_license_token()`, which reads the real
PROVENRAIL_LICENSE env var and the developer's ~/.config/provenrail/license file. A developer
who has run `pr activate` would otherwise see free-tier gating tests fail, because the whole
deployment would silently run at the licensed tier. Tests must never depend on the host's
license state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from provenrail import license as license_mod


@pytest.fixture(autouse=True)
def _isolate_ambient_license(monkeypatch, tmp_path):
    monkeypatch.delenv("PROVENRAIL_LICENSE", raising=False)
    # Point the on-disk license file at a path that does not exist, so load_license_token()
    # finds nothing regardless of what is installed on this machine.
    monkeypatch.setattr(license_mod, "LICENSE_FILE", Path(tmp_path) / "no-such-license")
