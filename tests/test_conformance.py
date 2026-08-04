"""Conformance vectors: the verifier must reach the recorded verdict on every frozen bundle.

This locks verification behavior (any drift is caught) and doubles as the public conformance
suite: a third-party verifier should agree with `expect_ok` on every vector, and SHOULD surface
the `defining_code`. See tests/vectors/README.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from provenrail.verifier.verify import verify_bundle

VECTORS = Path(__file__).parent / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))


def _verify_kwargs(spec):
    """Some vectors (witnessed tlog, SCITT, redaction) only verify with context: the log key,
    witness keys, a fixed clock, and disclosure openings. Base-chain vectors carry none."""
    ctx = spec.get("verify")
    if not ctx:
        return {}
    return {
        "tlog_log_key": ctx.get("tlog_log_key"),
        "witness_pubkeys": ctx.get("witness_pubkeys") or {},
        "now_utc": ctx.get("now_utc"),
        "disclosure_openings": ctx.get("openings"),
    }


@pytest.mark.parametrize("name", list(MANIFEST))
def test_vector_matches_manifest(name):
    spec = MANIFEST[name]
    bundle = json.loads((VECTORS / spec["file"]).read_text(encoding="utf-8"))
    rep = verify_bundle(bundle, **_verify_kwargs(spec))
    out = rep.to_dict()
    # The portable contract: every verifier must agree on the pass/fail verdict.
    assert out["ok"] == spec["expect_ok"], (name, out["findings"])
    # The defining signal: our verifier always emits it (a conformant verifier should too).
    if spec["defining_code"] is not None:
        codes = {f["code"] for f in out["findings"]}
        assert spec["defining_code"] in codes, (name, sorted(codes))


def test_manifest_covers_all_vector_files():
    on_disk = {p.name for p in VECTORS.glob("*.json")} - {"manifest.json"}
    referenced = {spec["file"] for spec in MANIFEST.values()}
    assert on_disk == referenced  # no orphan or missing vectors


def test_clean_vector_is_actually_clean():
    bundle = json.loads((VECTORS / "clean.json").read_text(encoding="utf-8"))
    assert verify_bundle(bundle).ok
