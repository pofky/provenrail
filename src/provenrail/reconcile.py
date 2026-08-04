"""Reconcile estimated spend against the provider's actual invoice.

Every agent-cost tool on the market reports an estimate and stops there. Finance does not
buy an estimate: the first question after "what did the agents cost?" is "does that match
the bill?", and until something answers it, the number is trivia. This module answers it.

Feed it a provider usage or billing export (CSV) and the runs you recorded. It aligns them by
model and, when the export has a date column, by day, then reports the delta three ways:

  - **drift**: estimate minus actual, per model and in total, with a percentage
  - **missing**: spend on the invoice that no recorded run accounts for, which is the finding
    that matters most. It means calls happened outside the recorder: a shadow agent, a
    forgotten cron, a teammate's laptop, or an integration nobody instrumented.
  - **unrecorded on the invoice**: recorded spend the invoice does not show, usually a
    billing lag or a model priced under a different name.

Deliberate boundaries:

**Nothing here is signed, and nothing feeds the chain.** A vendor CSV is an untrusted input.
It is used to *interpret* the record, never to amend it: a reconciliation result is a report,
and the recorded run remains exactly what it was.

**A large drift is a finding, not an error.** The common causes are a stale price table, a
negotiated rate we do not know about, and calls that bypassed the recorder. The output names
which of those the numbers are consistent with, rather than reporting a single scary
percentage the reader has to interpret alone.

**Column names are guessed, but never silently.** Provider exports disagree about headers, so
the parser accepts a range of spellings and reports exactly which columns it used. A parser
that guessed wrong and said nothing would produce a confident, wrong reconciliation.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from .chain import MODEL_CALL
from .pricing import cost_for, load_price_table, table_as_of

#: Accepted header spellings, lowercased and stripped, in priority order.
_MODEL_COLUMNS = ("model", "model_name", "model id", "model_id", "sku", "product", "line_item",
                  "description", "usage_type")
_COST_COLUMNS = ("cost", "cost_usd", "amount", "amount_usd", "total", "total_cost", "charge",
                 "spend", "usd")
_DATE_COLUMNS = ("date", "day", "usage_date", "timestamp", "invoice_date", "period", "created_at")
_QTY_COLUMNS = ("tokens", "quantity", "usage", "units", "total_tokens")

#: Drift beyond this fraction is called out as material. Below it, list-price rounding and
#: partial-day billing windows explain the difference on their own.
MATERIAL_DRIFT = 0.05


def _norm(name: str) -> str:
    return (name or "").strip().lower().replace("-", "_").replace(" ", "_")


def _pick_column(headers: list[str], candidates: tuple[str, ...],
                 taken: set[str] | None = None) -> str | None:
    """Resolve one logical column, skipping headers already claimed by another.

    The substring fallback is what makes "Cost (USD)" resolve, but unguarded it also lets
    "Usage Date" answer to the quantity candidate "usage". Excluding claimed headers keeps a
    loose match from stealing a column that was already matched exactly.
    """
    taken = taken or set()
    available = {_norm(h): h for h in headers if h not in taken}
    for candidate in candidates:
        key = _norm(candidate)
        if key in available:
            return available[key]
    for candidate in candidates:
        key = _norm(candidate)
        for norm_header, original in available.items():
            if key in norm_header:
                return original
    return None


#: Currency marks that are NOT US dollars. Every estimate in this product is in USD, so a
#: figure carrying one of these cannot be compared with one without converting it, and this
#: module has no rate to convert with and no business inventing one.
_FOREIGN_CURRENCY = {
    "€": "EUR", "£": "GBP", "¥": "JPY", "₹": "INR", "₩": "KRW", "₽": "RUB", "R$": "BRL",
    "EUR": "EUR", "GBP": "GBP", "JPY": "JPY", "INR": "INR", "CAD": "CAD", "AUD": "AUD",
    "CHF": "CHF", "SEK": "SEK", "PLN": "PLN", "DKK": "DKK", "NOK": "NOK",
}


def _currency_of(value: Any) -> str | None:
    """The non-USD currency this cell is denominated in, or None."""
    text = str(value or "").strip().upper()
    for mark, code in _FOREIGN_CURRENCY.items():
        if mark.upper() in text:
            return code
    return None


def _to_float(value: Any) -> float:
    """Parse a money cell, or return 0.0 when it is not a number this module can read.

    A cell in another currency parses to 0.0 here, which is why `parse_invoice` checks the
    currency BEFORE relying on this. An unnoticed 0.0 is the dangerous case: it makes the
    invoice total zero, which makes drift undefined, which suppresses every drift finding and
    leaves the report saying "nothing to flag" over an invoice full of real money.
    """
    text = str(value or "").strip().replace("$", "").replace(",", "").replace("USD", "").strip()
    if text.startswith("(") and text.endswith(")"):   # accounting negative
        text = "-" + text[1:-1]
    try:
        return float(text)
    except ValueError:
        return 0.0


def parse_invoice(text: str) -> dict[str, Any]:
    """Parse a provider usage/billing CSV into per-model actual cost.

    Returns the rows, the totals, and, importantly, the column names that were used, so a
    caller can show the operator what was interpreted as what.
    """
    reader = csv.DictReader(io.StringIO(text))
    headers = [h for h in (reader.fieldnames or []) if h]
    if not headers:
        return {"rows": [], "by_model": {}, "total_usd": 0.0, "columns": {},
                "warnings": ["the file has no header row, so nothing could be read"]}

    # Order matters: cost and model are the columns a wrong guess ruins, so they claim first
    # and the looser quantity match cannot take a header one of them already owns.
    taken: set[str] = set()

    def claim(candidates: tuple[str, ...]) -> str | None:
        column = _pick_column(headers, candidates, taken)
        if column:
            taken.add(column)
        return column

    cost_col = claim(_COST_COLUMNS)
    model_col = claim(_MODEL_COLUMNS)
    date_col = claim(_DATE_COLUMNS)
    qty_col = claim(_QTY_COLUMNS)

    warnings: list[str] = []
    if cost_col is None:
        warnings.append("no cost column found; expected one of " + ", ".join(_COST_COLUMNS))
    if model_col is None:
        warnings.append("no model column found, so every line is attributed to '(all models)'")

    by_model: dict[str, float] = {}
    rows: list[dict[str, Any]] = []
    currencies: set[str] = set()
    unreadable = 0
    for raw in reader:
        cell = raw.get(cost_col) if cost_col else None
        currency = _currency_of(cell) if cost_col else None
        if currency:
            currencies.add(currency)
        cost = _to_float(cell) if cost_col else 0.0
        if cost_col and not currency and cost == 0.0 and str(cell or "").strip() not in (
                "", "0", "0.0", "0.00", "$0", "$0.00"):
            unreadable += 1
        model = str(raw.get(model_col) or "").strip() if model_col else "(all models)"
        row = {"model": model or "(all models)", "cost_usd": round(cost, 6),
               "date": str(raw.get(date_col) or "")[:10] if date_col else "",
               "quantity": _to_float(raw.get(qty_col)) if qty_col else 0.0}
        rows.append(row)
        by_model[row["model"]] = round(by_model.get(row["model"], 0.0) + cost, 6)

    if currencies:
        # Loud, and it must reach `findings`, because the failure mode is silent agreement:
        # every line reads as $0.00, the invoice total is zero, drift is undefined, and the
        # report concludes "nothing to flag" over a bill in another currency.
        warnings.append(
            f"the cost column is in {', '.join(sorted(currencies))}, not USD. Every estimate in "
            f"Provenrail is in USD and no exchange rate is applied here, so these lines were "
            f"read as $0.00 and this reconciliation is not valid. Convert the invoice to USD "
            f"and re-run.")
    if unreadable:
        warnings.append(
            f"{unreadable} cost cell(s) could not be read as a number and were counted as "
            f"$0.00, so the invoice total is a floor rather than the real figure.")

    return {
        "rows": rows,
        "by_model": by_model,
        "total_usd": round(sum(by_model.values()), 6),
        "columns": {"model": model_col, "cost": cost_col, "date": date_col, "quantity": qty_col},
        "warnings": warnings,
        "currencies": sorted(currencies),
        "unreadable_cost_cells": unreadable,
    }


def _recorded_by_model(streams: list[tuple[str, list[dict[str, Any]]]],
                       since: str | None, until: str | None,
                       table: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for _stream_id, records in streams:
        for r in records:
            rec = r.get("record", r) or {}
            if rec.get("action_type") != MODEL_CALL:
                continue
            day = str(rec.get("ts_utc") or "")[:10]
            if day and since and day < since:
                continue
            if day and until and day > until:
                continue
            payload = rec.get("payload", {}) or {}
            model = str(payload.get("model") or "(unknown)")
            cost = cost_for(model, payload.get("usage"), table)
            entry = out.setdefault(model, {"model": model, "estimated_usd": 0.0, "calls": 0,
                                           "unpriced_calls": 0})
            entry["estimated_usd"] = round(entry["estimated_usd"] + cost["cost_usd"], 6)
            entry["calls"] += 1
            if not cost["priced"]:
                entry["unpriced_calls"] += 1
    return out


def _model_key(name: str) -> str:
    """Collapse a model name to letters and digits only.

    Invoices and APIs punctuate differently for the same model: "Claude Sonnet 4.5 (input)"
    against "claude-sonnet-4-5-20260101". Keeping the punctuation would leave those two
    strings with no common substring, and every line would come back unmatched, which reads
    as "all of your spend is unaccounted for" when it is really a formatting difference.
    """
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


#: Suffixes an invoice appends to a model name that carry no model identity, so they can be
#: trimmed before deciding whether two names are the same model.
_LINE_ITEM_NOISE = ("input", "output", "inputtokens", "outputtokens", "cached", "cachedinput",
                    "cacheread", "cachewrite", "batch", "tokens", "usage")


def _match_model(invoice_model: str, recorded_models: list[str]) -> str | None:
    """Align an invoice line to a recorded model name.

    Punctuation is stripped first, because an invoice writes "Claude Sonnet 4.5 (input)" where
    the API says "claude-sonnet-4-5-20260101" and those share no substring otherwise.

    Substring matching alone is then WRONG in a way that silently costs money: `gpt4o` is a
    substring of `gpt4omini`, so an invoice line for the expensive model matched recorded
    calls to the cheap one and produced a confident -99% variance with a plausible but false
    explanation. Matching is therefore anchored: after trimming known line-item noise, the two
    names must be equal, or one must extend the other at a token boundary that is not another
    alphanumeric run. Anything ambiguous is left unmatched and reported, which is the honest
    outcome, rather than attributed to the wrong model.
    """
    target = _model_key(invoice_model)
    if not target:
        return None
    for noise in sorted(_LINE_ITEM_NOISE, key=len, reverse=True):
        if target.endswith(noise) and len(target) > len(noise):
            target = target[: -len(noise)]
            break
    best, best_len = None, -1
    for model in recorded_models:
        candidate = _model_key(model)
        if not candidate:
            continue
        if candidate == target:
            return model                      # exact identity always wins outright
        # One may extend the other only by a version/date suffix, never by more letters:
        # "gpt4o" vs "gpt4o20260101" is the same model, "gpt4o" vs "gpt4omini" is not.
        longer, shorter = (candidate, target) if len(candidate) > len(target) else (target, candidate)
        if longer.startswith(shorter) and not longer[len(shorter):][:1].isalpha():
            if len(candidate) > best_len:
                best, best_len = model, len(candidate)
    return best


def reconcile(streams: list[tuple[str, list[dict[str, Any]]]], invoice_csv: str,
              since: str | None = None, until: str | None = None,
              table: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compare recorded estimates against an invoice and explain the difference.

    Returns per-model rows (estimate, actual, drift), totals, unmatched lines in both
    directions, and a plain-language reading of what the drift is consistent with.
    """
    table = table if table is not None else load_price_table()
    invoice = parse_invoice(invoice_csv)
    recorded = _recorded_by_model(streams, since, until, table)

    rows: list[dict[str, Any]] = []
    matched_recorded: set[str] = set()
    unmatched_invoice: list[dict[str, Any]] = []

    for invoice_model, actual in sorted(invoice["by_model"].items()):
        match = _match_model(invoice_model, list(recorded))
        if match is None:
            unmatched_invoice.append({"model": invoice_model, "actual_usd": actual})
            continue
        matched_recorded.add(match)
        estimated = recorded[match]["estimated_usd"]
        rows.append({
            "model": match,
            "invoice_line": invoice_model,
            "estimated_usd": estimated,
            "actual_usd": actual,
            "drift_usd": round(estimated - actual, 6),
            "drift_pct": round((estimated - actual) / actual * 100.0, 2) if actual else None,
            "calls": recorded[match]["calls"],
            "unpriced_calls": recorded[match]["unpriced_calls"],
        })

    unmatched_recorded = [
        {"model": m, "estimated_usd": v["estimated_usd"], "calls": v["calls"]}
        for m, v in sorted(recorded.items()) if m not in matched_recorded
    ]

    estimated_total = round(sum(v["estimated_usd"] for v in recorded.values()), 6)
    actual_total = invoice["total_usd"]
    drift = round(estimated_total - actual_total, 6)
    drift_pct = round(drift / actual_total * 100.0, 2) if actual_total else None
    unaccounted = round(sum(r["actual_usd"] for r in unmatched_invoice), 6)
    unpriced_calls = sum(v["unpriced_calls"] for v in recorded.values())

    return {
        "rows": sorted(rows, key=lambda r: -abs(r["drift_usd"])),
        "totals": {
            "estimated_usd": estimated_total,
            "actual_usd": actual_total,
            "drift_usd": drift,
            "drift_pct": drift_pct,
            "unaccounted_on_invoice_usd": unaccounted,
        },
        "unmatched_invoice_lines": unmatched_invoice,
        "unmatched_recorded_models": unmatched_recorded,
        "invoice_columns": invoice["columns"],
        "invoice": {"currencies": invoice.get("currencies", []),
                    "unreadable_cost_cells": invoice.get("unreadable_cost_cells", 0)},
        "warnings": invoice["warnings"],
        "findings": _findings(drift, drift_pct, unaccounted, unpriced_calls, unmatched_recorded,
                              invalid=[w for w in invoice["warnings"]
                                       if "not USD" in w or "no cost column" in w]),
        "prices_as_of": table_as_of(table),
        "from": since,
        "to": until,
    }


def _findings(drift: float, drift_pct: float | None, unaccounted: float,
              unpriced_calls: int, unmatched_recorded: list[dict[str, Any]],
              invalid: list[str] | None = None) -> list[str]:
    """Name what the numbers are consistent with, instead of leaving a bare percentage.

    A reader handed "-31%" has to invent an explanation, and the one they invent is usually
    "the tool is broken" when the real answer is a shadow agent or a negotiated rate.
    """
    out: list[str] = []
    if invalid:
        # First, and it suppresses the reassuring conclusion below. An invoice this module
        # could not read produces a zero total, and a zero total makes drift undefined, which
        # silently skips every drift finding. Without this the report ends on "nothing to
        # flag" over a bill it never actually read.
        out.extend(invalid)
        return out
    if unaccounted > 0:
        out.append(
            f"${unaccounted:,.2f} on the invoice matches no recorded model. This is the finding "
            f"that matters: it is spend that did not go through the recorder (an uninstrumented "
            f"service, a scheduled job, or a machine outside this deployment).")
    if unpriced_calls:
        out.append(
            f"{unpriced_calls} recorded call(s) had no verified price and contributed $0.00 to "
            f"the estimate, so the estimate is a floor. Set rates in .provenrail-prices.json.")
    if drift_pct is not None and abs(drift_pct) > MATERIAL_DRIFT * 100:
        if drift < 0:
            out.append(
                f"The estimate is {abs(drift_pct):.1f}% BELOW the invoice. Consistent with calls "
                f"made outside the recorder, or with list prices that are lower than what you "
                f"are actually charged (a region, a tier, or a surcharge we do not model).")
        else:
            out.append(
                f"The estimate is {drift_pct:.1f}% ABOVE the invoice. Consistent with a "
                f"negotiated or committed-use discount the price table does not know about; set "
                f"your real rates in .provenrail-prices.json and re-run.")
    elif drift_pct is not None:
        out.append(f"Estimate and invoice agree within {MATERIAL_DRIFT * 100:.0f}%; the "
                   f"remaining difference is normal rounding and billing-window edges.")
    if unmatched_recorded:
        names = ", ".join(r["model"] for r in unmatched_recorded[:5])
        out.append(f"{len(unmatched_recorded)} recorded model(s) do not appear on the invoice "
                   f"({names}). Usually billing lag, or a model billed under a different name.")
    if not out:
        out.append("Nothing to flag: recorded spend and the invoice line up.")
    return out


def render_text(result: dict[str, Any]) -> str:
    """A readable reconciliation, for `pr reconcile` and for pasting into a finance thread."""
    t = result["totals"]
    lines = ["Estimated vs invoiced spend"]
    window = f"{result.get('from') or 'all time'} to {result.get('to') or 'now'}"
    lines.append(f"  window      {window}")
    lines.append(f"  estimated   ${t['estimated_usd']:,.2f}")
    lines.append(f"  invoiced    ${t['actual_usd']:,.2f}")
    drift_pct = "" if t["drift_pct"] is None else f" ({t['drift_pct']:+.1f}%)"
    lines.append(f"  drift       ${t['drift_usd']:+,.2f}{drift_pct}")
    if result["warnings"]:
        lines.append("")
        for w in result["warnings"]:
            lines.append(f"  ! {w}")
    if result["rows"]:
        lines.append("")
        lines.append(f"  {'model':<34}{'estimated':>13}{'invoiced':>13}{'drift':>13}")
        for row in result["rows"]:
            estimated = f"${row['estimated_usd']:,.2f}"
            actual = f"${row['actual_usd']:,.2f}"
            drift = f"${row['drift_usd']:+,.2f}"
            lines.append(f"  {row['model'][:33]:<34}{estimated:>13}{actual:>13}{drift:>13}")
    lines.append("")
    for finding in result["findings"]:
        lines.append(f"  * {finding}")
    lines.append("")
    lines.append("  The invoice is an untrusted input used to interpret the record, never to")
    lines.append("  amend it. The recorded run is unchanged and still verifies.")
    return "\n".join(lines)
