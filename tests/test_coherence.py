"""Coherence / anomaly signals. Heuristics only: they surface seams for a human to look at and
never promote or demote the cryptographic verdict. Every signal is warn or info, never fail.
"""

from __future__ import annotations

from provenrail.coherence import detect


def _rec(seq, action="decision", ts="2026-01-01T00:00:00.000000Z", rid=None, payload=None):
    return {"seq": seq, "action_type": action, "ts_utc": ts,
            "record_id": rid or f"r{seq}", "payload": payload or {}}


def _codes(signals):
    return {s["code"] for s in signals}


def test_no_signals_on_clean_run():
    ordered = [
        _rec(0, "lifecycle.session_start", "2026-01-01T00:00:00.000000Z"),
        _rec(1, "model_call", "2026-01-01T00:00:01.000000Z", payload={"usage": {"input": "5"}}),
        _rec(2, "decision", "2026-01-01T00:00:02.000000Z"),
        _rec(3, "lifecycle.session_end", "2026-01-01T00:00:03.000000Z", payload={"count": 3}),
    ]
    assert detect(ordered) == []


def test_nonmonotonic_timestamp_warned():
    ordered = [
        _rec(0, ts="2026-01-01T00:00:05.000000Z"),
        _rec(1, ts="2026-01-01T00:00:01.000000Z"),  # earlier than prior
    ]
    sigs = detect(ordered)
    assert "nonmonotonic_ts" in _codes(sigs)
    assert all(s["severity"] in ("warn", "info") for s in sigs)


def test_large_time_gap_info():
    ordered = [
        _rec(0, ts="2026-01-01T00:00:00.000000Z"),
        _rec(1, ts="2026-01-01T02:00:00.000000Z"),  # 2h later
    ]
    assert "time_gap" in _codes(detect(ordered))


def test_duplicate_record_id_warned():
    ordered = [_rec(0, rid="dup"), _rec(1, rid="dup")]
    assert "duplicate_record_id" in _codes(detect(ordered))


def test_missing_usage_info():
    ordered = [
        _rec(0, "lifecycle.session_start"),
        _rec(1, "model_call", payload={}),  # no usage
        _rec(2, "decision"),
    ]
    assert "usage_missing" in _codes(detect(ordered))


def test_no_governance_info():
    ordered = [
        _rec(0, "lifecycle.session_start"),
        _rec(1, "model_call", payload={"usage": {"input": "1"}}),
    ]
    assert "no_governance" in _codes(detect(ordered))


def test_seal_count_mismatch_warned():
    ordered = [
        _rec(0, "lifecycle.session_start"),
        _rec(1, "decision"),
        _rec(2, "lifecycle.session_end", payload={"count": 99}),  # should be 2
    ]
    assert "seal_count_mismatch" in _codes(detect(ordered))


def test_signals_are_never_fail():
    ordered = [_rec(0, ts="2026-01-01T00:00:05.000000Z"), _rec(1, ts="2026-01-01T00:00:00.000000Z")]
    assert all(s["severity"] != "fail" for s in detect(ordered))


def test_version_matches_pyproject():
    """__version__ drifted from pyproject once and shipped a wrong version to users."""
    import tomllib
    from pathlib import Path

    import provenrail

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert provenrail.__version__ == declared
