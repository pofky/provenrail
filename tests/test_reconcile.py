"""Estimate vs invoice reconciliation.

The feature exists for one finding: spend on the invoice that no recorded run explains,
which means calls happened outside the recorder. Everything else here defends the ways a
reconciliation can quietly lie, chiefly guessing a column wrong and saying nothing.
"""

from __future__ import annotations

import pytest

from provenrail.chain import GENESIS, MODEL_CALL
from provenrail.reconcile import parse_invoice, reconcile, render_text

MODEL = "claude-sonnet-4-5"   # $3/1M in


def call(model=MODEL, tokens_in=1_000_000, ts="2026-08-04T10:00:00.000000Z"):
    return {"record": {"action_type": MODEL_CALL, "session_id": "s1", "ts_utc": ts,
                       "payload": {"model": model, "provider": "anthropic",
                                   "usage": {"input_tokens": tokens_in, "output_tokens": 0}}}}


def genesis():
    return {"record": {"action_type": GENESIS, "session_id": "s1",
                       "ts_utc": "2026-08-04T09:00:00.000000Z", "payload": {"meta": {}}}}


# ---------------------------------------------------------------- parsing


def test_parses_a_plain_export():
    text = "model,cost\nclaude-sonnet-4-5,12.50\ngpt-4.1,7.25\n"
    out = parse_invoice(text)
    assert out["by_model"]["claude-sonnet-4-5"] == 12.50
    assert out["total_usd"] == 19.75
    assert out["columns"]["cost"] == "cost"


def test_accepts_provider_header_variations_and_reports_what_it_used():
    """A parser that guessed wrong and stayed silent produces a confident wrong answer."""
    text = ('Model Name,Cost (USD),Usage Date\n'
            '"Claude Sonnet 4.5","$1,234.50",2026-08-04\n')
    out = parse_invoice(text)
    assert out["total_usd"] == 1234.50
    assert out["columns"] == {"model": "Model Name", "cost": "Cost (USD)",
                              "date": "Usage Date", "quantity": None}


def test_missing_cost_column_is_a_loud_warning_not_a_zero():
    out = parse_invoice("model,notes\nclaude-sonnet-4-5,hello\n")
    assert out["total_usd"] == 0.0
    assert any("no cost column" in w for w in out["warnings"])


def test_accounting_negatives_and_currency_noise():
    out = parse_invoice("model,amount\na,(5.00)\nb,\"1,000.00 USD\"\n")
    assert out["by_model"]["a"] == -5.0
    assert out["by_model"]["b"] == 1000.0


# ---------------------------------------------------------------- reconciliation


def test_matching_estimate_and_invoice_reports_agreement():
    streams = [("x", [genesis(), call()])]           # $3.00 estimated
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,3.00\n")
    assert out["totals"]["drift_usd"] == pytest.approx(0.0)
    assert any("agree within" in f for f in out["findings"])


def test_invoice_names_are_matched_to_api_model_names():
    streams = [("x", [genesis(), call()])]
    out = reconcile(streams, "model,cost\nClaude Sonnet 4.5 (input),3.00\n")
    assert out["rows"][0]["model"] == MODEL
    assert out["rows"][0]["invoice_line"] == "Claude Sonnet 4.5 (input)"


def test_spend_on_the_invoice_with_no_recorded_run_is_the_headline_finding():
    """The whole point: something is billing that the recorder never saw."""
    streams = [("x", [genesis(), call()])]           # $3.00 recorded
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,3.00\ngpt-4.1,500.00\n")
    assert out["totals"]["unaccounted_on_invoice_usd"] == pytest.approx(500.0)
    assert out["unmatched_invoice_lines"][0]["model"] == "gpt-4.1"
    assert any("did not go through the recorder" in f for f in out["findings"])


def test_estimate_above_invoice_points_at_a_negotiated_rate():
    streams = [("x", [genesis(), call()])]           # $3.00 estimated
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,2.00\n")
    assert out["totals"]["drift_usd"] == pytest.approx(1.0)
    assert any("negotiated" in f for f in out["findings"])


def test_estimate_below_invoice_points_at_uninstrumented_calls():
    streams = [("x", [genesis(), call()])]
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,10.00\n")
    assert any("outside the recorder" in f for f in out["findings"])


def test_unpriced_calls_are_flagged_so_the_estimate_reads_as_a_floor():
    streams = [("x", [genesis(), call(model="grok-4")])]
    out = reconcile(streams, "model,cost\ngrok-4,40.00\n")
    assert any("floor" in f for f in out["findings"])


def test_recorded_model_absent_from_the_invoice_is_reported():
    streams = [("x", [genesis(), call(), call(model="gpt-4.1")])]
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,3.00\n")
    assert out["unmatched_recorded_models"][0]["model"] == "gpt-4.1"
    assert any("do not appear on the invoice" in f for f in out["findings"])


def test_date_window_limits_what_is_reconciled():
    streams = [("x", [genesis(),
                      call(ts="2026-07-01T00:00:00.000000Z"),
                      call(ts="2026-08-04T00:00:00.000000Z")])]
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,3.00\n",
                    since="2026-08-01", until="2026-08-31")
    assert out["totals"]["estimated_usd"] == pytest.approx(3.0)


def test_rendered_report_states_the_invoice_never_amends_the_record():
    streams = [("x", [genesis(), call()])]
    text = render_text(reconcile(streams, "model,cost\nclaude-sonnet-4-5,3.00\n"))
    assert "never to" in text and "amend it" in text
    assert "$3.00" in text


def test_gpt4o_invoice_line_is_not_attributed_to_gpt4o_mini():
    """Substring matching made `gpt4o` match `gpt4omini`, so an invoice line for the expensive
    model was charged against recorded calls to the cheap one, producing a confident -99%
    variance with a plausible but completely false explanation."""
    streams = [("x", [genesis(), call(model="gpt-4o-mini", tokens_in=1_000_000)])]
    out = reconcile(streams, "model,cost\nGPT-4o,500.00\n")
    assert out["rows"] == [], "gpt-4o invoice line was matched to gpt-4o-mini calls"
    assert out["unmatched_invoice_lines"][0]["model"] == "GPT-4o"
    assert out["totals"]["unaccounted_on_invoice_usd"] == pytest.approx(500.0)


def test_the_correct_model_still_matches_including_dated_suffixes():
    """The anchored match must not become so strict that real invoices stop lining up."""
    streams = [("x", [genesis(), call(model="claude-sonnet-4-5-20260101")])]
    out = reconcile(streams, "model,cost\nClaude Sonnet 4.5 (input),3.00\n")
    assert out["rows"] and out["rows"][0]["model"] == "claude-sonnet-4-5-20260101"

    exact = reconcile([("x", [genesis(), call(model="gpt-4o-mini")])],
                      "model,cost\ngpt-4o-mini,0.15\n")
    assert exact["rows"] and exact["rows"][0]["model"] == "gpt-4o-mini"


def test_a_non_usd_invoice_is_refused_not_silently_read_as_zero():
    """Every figure this product produces is in USD. A EUR invoice parsed to $0.00 on every
    line, which zeroed the invoice total, which made drift undefined, which skipped every
    drift finding and left the report concluding "nothing to flag" over a real bill."""
    streams = [("x", [genesis(), call()])]
    out = reconcile(streams, 'model,amount\nclaude-sonnet-4-5,"€1.234,56"\n')
    assert out["invoice"]["currencies"] == ["EUR"]
    assert any("not USD" in w for w in out["warnings"])
    assert any("not USD" in f for f in out["findings"])
    assert not any("Nothing to flag" in f for f in out["findings"])


def test_a_usd_invoice_is_still_reconciled_normally():
    streams = [("x", [genesis(), call()])]
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,$3.00\n")
    assert out["invoice"]["currencies"] == []
    assert not any("not USD" in w for w in out["warnings"])


def test_an_unparseable_cost_cell_is_counted_and_reported():
    streams = [("x", [genesis(), call()])]
    out = reconcile(streams, "model,cost\nclaude-sonnet-4-5,see attached\n")
    assert out["invoice"]["unreadable_cost_cells"] == 1
    assert any("could not be read as a number" in w for w in out["warnings"])
