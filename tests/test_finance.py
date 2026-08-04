"""Finance rollups: spend grouped by agent, project, team, model, day.

The question finance asks is never "what did this run cost". It is "which agent, which
project, which team, which model, which day". These tests pin the two ways a rollup can
mislead: losing unattributed spend, and letting an unpriced call read as a cheap one.
"""

from __future__ import annotations

import csv
import io

import pytest
from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server import finance
from provenrail.server.app import create_app

MODEL = "claude-sonnet-4-5"   # $3/1M in, $15/1M out


def rec(action_type, session_id, payload, ts="2026-08-04T10:00:00.000000Z"):
    return {"record": {"action_type": action_type, "session_id": session_id,
                       "payload": payload, "ts_utc": ts}}


def model_call(session_id, tokens_in, model=MODEL, ts="2026-08-04T10:00:00.000000Z"):
    return rec("model_call", session_id,
               {"model": model, "provider": "anthropic",
                "usage": {"input_tokens": tokens_in, "output_tokens": 0}}, ts)


def session(session_id, meta, ts="2026-08-04T10:00:00.000000Z"):
    from provenrail.chain import GENESIS
    return rec(GENESIS, session_id, {"meta": meta}, ts)


def test_groups_by_agent_from_session_metadata():
    records = [
        session("s1", {"agent": "billing-agent"}),
        model_call("s1", 1_000_000),           # $3.00
        session("s2", {"agent": "support-agent"}),
        model_call("s2", 500_000),             # $1.50
        model_call("s2", 500_000),             # $1.50
    ]
    out = finance.rollup([("stream-1", records)], group_by="agent")
    rows = {r["agent"]: r for r in out["rows"]}
    assert rows["billing-agent"]["cost_usd"] == pytest.approx(3.0)
    assert rows["support-agent"]["cost_usd"] == pytest.approx(3.0)
    assert rows["support-agent"]["model_calls"] == 2
    assert out["totals"]["cost_usd"] == pytest.approx(6.0)


def test_alternative_metadata_spellings_are_understood():
    """Operators name these fields themselves; only understanding one spelling would report
    every session as unattributed and read as a product bug."""
    records = [session("s1", {"project_name": "atlas", "squad": "platform"}),
               model_call("s1", 1_000_000)]
    assert finance.rollup([("x", records)], group_by="project")["rows"][0]["project"] == "atlas"
    assert finance.rollup([("x", records)], group_by="team")["rows"][0]["team"] == "platform"


def test_unattributed_spend_is_shown_not_dropped():
    """A rollup whose rows do not sum to the account total makes an underspend look real."""
    records = [
        session("s1", {"agent": "a", "project": "atlas"}),
        model_call("s1", 1_000_000),                     # $3.00, attributed
        session("s2", {"agent": "b"}),                    # no project
        model_call("s2", 1_000_000),                     # $3.00, unattributed
    ]
    out = finance.rollup([("x", records)], group_by="project")
    rows = {r["project"]: r["cost_usd"] for r in out["rows"]}
    assert rows[finance.UNATTRIBUTED] == pytest.approx(3.0)
    assert sum(rows.values()) == pytest.approx(out["totals"]["cost_usd"])


def test_unpriced_calls_are_counted_so_a_row_is_never_mistaken_for_complete():
    records = [session("s1", {"agent": "a"}),
               model_call("s1", 1_000_000, model="claude-opus-5")]   # known, deliberately unpriced
    row = finance.rollup([("x", records)], group_by="agent")["rows"][0]
    assert row["cost_usd"] == 0.0
    assert row["unpriced_calls"] == 1


def test_date_window_is_inclusive_at_both_ends():
    records = [
        session("s1", {"agent": "a"}, ts="2026-08-01T00:00:00.000000Z"),
        model_call("s1", 1_000_000, ts="2026-08-01T00:00:00.000000Z"),
        model_call("s1", 1_000_000, ts="2026-08-03T00:00:00.000000Z"),
        model_call("s1", 1_000_000, ts="2026-08-05T00:00:00.000000Z"),
    ]
    out = finance.rollup([("x", records)], group_by="day", since="2026-08-01", until="2026-08-03")
    assert {r["day"] for r in out["rows"]} == {"2026-08-01", "2026-08-03"}
    assert out["totals"]["cost_usd"] == pytest.approx(6.0)


def test_groups_by_model_and_stream():
    records = [session("s1", {}), model_call("s1", 1_000_000),
               model_call("s1", 1_000_000, model="claude-3-haiku")]  # $0.25/1M in
    by_model = {r["model"]: r["cost_usd"] for r in
                finance.rollup([("x", records)], group_by="model")["rows"]}
    assert by_model[MODEL] == pytest.approx(3.0)
    assert by_model["claude-3-haiku"] == pytest.approx(0.25)
    by_stream = finance.rollup([("x", records)], group_by="stream")["rows"]
    assert by_stream[0]["stream"] == "x"


def test_sessions_are_counted_per_group_across_streams():
    records_a = [session("s1", {"team": "platform"}), model_call("s1", 1000)]
    records_b = [session("s1", {"team": "platform"}), model_call("s1", 1000)]
    out = finance.rollup([("stream-a", records_a), ("stream-b", records_b)], group_by="team")
    # same session id in two streams is two sessions, not one
    assert out["rows"][0]["sessions"] == 2


def test_rejects_an_unknown_dimension():
    with pytest.raises(ValueError, match="group_by"):
        finance.rollup([], group_by="colour")


def test_csv_carries_the_estimate_caveat_and_a_total_row():
    records = [session("s1", {"agent": "a"}), model_call("s1", 1_000_000)]
    text = finance.to_csv(finance.rollup([("x", records)], group_by="agent"))
    assert "NOT an invoice" in text
    assert "prices_as_of=" in text
    assert "unpriced_calls" in text.splitlines()[3]
    assert text.strip().splitlines()[-1].startswith("TOTAL,3.0")


# ---------------------------------------------------------------- through the API


def _client_with_run(tmp_path):
    client = TestClient(create_app(":memory:", anchor=LocalAnchor(), require_account=False))
    prov = provision_stream("http://t", http=client)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=client)
    with fr.session({"agent": "billing-agent", "project": "atlas", "team": "platform"}):
        fr.record_model_call("anthropic", MODEL, "hi", "yo",
                             usage={"input_tokens": 1_000_000, "output_tokens": 0})
    return client


def test_spend_endpoint_groups_and_reports_provenance(tmp_path):
    client = _client_with_run(tmp_path)
    body = client.get("/v1/spend?group_by=project").json()
    assert body["rows"][0]["project"] == "atlas"
    assert body["rows"][0]["cost_usd"] == pytest.approx(3.0)
    assert body["estimated"] is True
    assert body["prices_as_of"]


def test_spend_endpoint_serves_csv(tmp_path):
    client = _client_with_run(tmp_path)
    resp = client.get("/v1/spend?group_by=team&format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    assert "platform" in resp.text


def test_spend_endpoint_rejects_a_malformed_window(tmp_path):
    """A bad range that silently matched nothing would report $0.00 as a real total."""
    client = _client_with_run(tmp_path)
    assert client.get("/v1/spend?since=last-tuesday").status_code == 400
    assert client.get("/v1/spend?group_by=colour").status_code == 400


def test_csv_export_neutralises_spreadsheet_formula_injection():
    """The dimension column is agent-supplied metadata, and the agent is this product's
    primary adversary. An unescaped leading `=` turns the finance team's cost report into a
    live formula the moment they open it in Excel."""
    payloads = ['=DDE("cmd","/c calc","x")', "@SUM(1+1)", "+1+1", "-1+1",
                "=HYPERLINK(\"http://evil\",\"click\")"]
    records = [session("s1", {"agent": payloads[0], "project": payloads[1]}),
               model_call("s1", 1000)]
    for group_by in ("agent", "project"):
        text = finance.to_csv(finance.rollup([("x", records)], group_by=group_by))
        cells = [r[0] for r in csv.reader(io.StringIO(
            "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))))]
        for cell in cells[1:]:
            assert cell[:1] not in ("=", "+", "-", "@"), f"formula-active cell exported: {cell!r}"

    # the payload is still readable, just inert, so the report stays useful
    text = finance.to_csv(finance.rollup([("x", records)], group_by="agent"))
    assert "DDE" in text
    # and numeric columns are untouched, or the arithmetic the file exists for would break
    assert "'" not in text.split("\n")[4].split(",")[1]


def test_csv_sanitiser_leaves_numbers_alone():
    assert finance._sanitize(3.5) == 3.5
    assert finance._sanitize(0) == 0
    assert finance._sanitize("atlas") == "atlas"
    assert finance._sanitize("=1+1") == "'=1+1"
