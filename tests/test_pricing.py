"""Cost estimation: cached tokens, reasoning tokens, overrides, and staleness.

These are the details that decide whether a finance number is actionable or merely
plausible. Every assertion here corresponds to a way a naive implementation silently
undercounts or double-counts real money.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from provenrail import pricing
from provenrail.pricing import ModelPrice, cost_for, is_stale, load_price_table, resolve_price


def test_backward_compatible_two_tuple_resolution():
    assert resolve_price("gpt-4o-mini-2026") == (0.15, 0.60)
    assert resolve_price("gpt-4o-2026") == (2.50, 10.00)
    assert resolve_price("some-local-finetune") is None


def test_plain_call_prices_input_and_output():
    c = cost_for("claude-sonnet-4-5", {"input_tokens": 1_000_000, "output_tokens": 1_000_000})
    assert c["priced"] is True
    assert c["cost_usd"] == pytest.approx(18.00)


def test_anthropic_cache_tokens_are_added_not_folded():
    """Anthropic reports input_tokens EXCLUSIVE of cache tokens, so both are billable."""
    c = cost_for("claude-sonnet-4-5", {
        "input_tokens": 1_000_000,
        "output_tokens": 0,
        "cache_read_input_tokens": 1_000_000,
        "cache_creation_input_tokens": 1_000_000,
    })
    # 1M @ $3 + 1M @ $0.30 (0.1x read) + 1M @ $3.75 (1.25x write)
    assert c["cost_usd"] == pytest.approx(7.05)
    assert c["cache_basis"] == "explicit"


def test_openai_cached_tokens_are_not_double_charged():
    """OpenAI reports prompt_tokens INCLUSIVE of cached_tokens; the cached portion must be
    priced once, at the cached rate, not twice."""
    c = cost_for("gpt-4.1", {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 0,
        "prompt_tokens_details": {"cached_tokens": 400_000},
    })
    # 600k uncached @ $2 + 400k cached @ $0.50 (0.25x)
    assert c["cost_usd"] == pytest.approx(1.4)
    assert c["tokens_billable_in"] == 600_000
    assert c["tokens_cache_read"] == 400_000


def test_reasoning_tokens_are_reported_but_never_billed_twice():
    """OpenAI reasoning_tokens are a subset of completion_tokens and are already billed."""
    plain = cost_for("o3", {"prompt_tokens": 0, "completion_tokens": 100_000})
    with_reasoning = cost_for("o3", {
        "prompt_tokens": 0,
        "completion_tokens": 100_000,
        "output_tokens_details": {"reasoning_tokens": 90_000},
    })
    assert with_reasoning["cost_usd"] == plain["cost_usd"]
    assert with_reasoning["tokens_reasoning"] == 90_000


def test_unknown_model_is_unpriced_and_zero():
    c = cost_for("some-local-llama-finetune-xyz", {"input": 10, "output": 5})
    assert c["priced"] is False
    assert c["cost_usd"] == 0.0
    assert c["known_unpriced"] is False


def test_known_model_without_a_verified_rate_says_so():
    """Refusing to invent a rate is the point; the caller must be able to tell the difference
    between 'never heard of it' and 'we know it and will not guess'."""
    c = cost_for("claude-opus-5", {"input_tokens": 1000, "output_tokens": 1000})
    assert c["priced"] is False
    assert c["known_unpriced"] is True


def test_override_file_replaces_list_price(tmp_path, monkeypatch):
    f = tmp_path / "prices.json"
    f.write_text(json.dumps({"prices": {"claude-sonnet-4-5": {"input": 1.0, "output": 2.0}}}))
    monkeypatch.setenv("PROVENRAIL_PRICES", str(f))
    table = load_price_table()
    c = cost_for("claude-sonnet-4-5", {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
                 table=table)
    assert c["cost_usd"] == pytest.approx(3.0)
    assert c["basis"] == "override"
    # untouched entries keep their list price and basis
    assert cost_for("gpt-4.1", {"prompt_tokens": 1_000_000}, table=table)["basis"] == "list"


def test_override_shorthand_tuple_form(tmp_path, monkeypatch):
    f = tmp_path / "prices.json"
    f.write_text(json.dumps({"gpt-4.1": [1.0, 4.0]}))
    monkeypatch.setenv("PROVENRAIL_PRICES", str(f))
    c = cost_for("gpt-4.1", {"prompt_tokens": 1_000_000, "completion_tokens": 0},
                 table=load_price_table())
    assert c["cost_usd"] == pytest.approx(1.0)


def test_malformed_override_never_breaks_recording(tmp_path, monkeypatch):
    f = tmp_path / "prices.json"
    f.write_text("{not json at all")
    monkeypatch.setenv("PROVENRAIL_PRICES", str(f))
    assert load_price_table()["gpt-4.1"].input == 2.00


def test_table_staleness_is_reported():
    fresh = {"x": ModelPrice(1.0, 2.0, as_of="2026-08-01")}
    old = {"x": ModelPrice(1.0, 2.0, as_of="2020-01-01")}
    assert is_stale(fresh, today=date(2026, 8, 4)) is False
    assert is_stale(old, today=date(2026, 8, 4)) is True
    assert is_stale({"x": ModelPrice(1.0, 2.0)}, today=date(2026, 8, 4)) is True


def test_builtin_table_carries_verification_dates():
    assert pricing.table_as_of()
    assert all(p.as_of for p in pricing.PRICES.values())


def test_google_camelcase_usage_is_priced_not_silently_zero():
    """A real Gemini REST response used to price at $0.00 while reporting priced=True: an
    authoritative-looking zero, which is worse than an unpriced call. Field names verified
    against ai.google.dev/api/generate-content."""
    c = cost_for("gemini-2.5-flash", {
        "promptTokenCount": 1_000_000,
        "candidatesTokenCount": 200_000,
        "cachedContentTokenCount": 400_000,
    })
    # Google reports the prompt count INCLUSIVE of cache, so 600k uncached at $0.30 +
    # 400k cached at $0.075 + 200k out at $2.50
    assert c["priced"] is True
    assert c["cost_usd"] == pytest.approx(0.71)
    assert c["tokens_billable_in"] == 600_000


def test_google_python_sdk_snake_case_usage_is_priced():
    c = cost_for("gemini-2.5-pro", {"prompt_token_count": 1_000_000,
                                    "candidates_token_count": 0})
    assert c["priced"] is True
    assert c["cost_usd"] == pytest.approx(1.25)


def test_gemini_thoughts_tokens_are_surfaced_and_flagged_as_unverified():
    """Whether thoughtsTokenCount is additive to candidatesTokenCount is not stated in
    Google's official token documentation, so it is reported and left unbilled rather than
    guessed at, and the blind spot is flagged rather than hidden."""
    c = cost_for("gemini-2.5-flash", {"promptTokenCount": 0, "candidatesTokenCount": 1000,
                                      "thoughtsTokenCount": 5000})
    assert c["tokens_reasoning"] == 5000
    assert c["reasoning_billing_unverified"] is True
    # a provider whose convention IS documented is not flagged
    openai = cost_for("o3", {"prompt_tokens": 0, "completion_tokens": 1000,
                             "output_tokens_details": {"reasoning_tokens": 900}})
    assert openai["reasoning_billing_unverified"] is False


def test_negative_token_counts_cannot_reduce_a_budget():
    """A negative cost subtracts from projected spend and could carry a session back under a
    cap it had already blown."""
    c = cost_for("claude-sonnet-4-5", {"input_tokens": -1_000_000, "output_tokens": -50})
    assert c["cost_usd"] == 0.0
    assert c["tokens_in"] == 0 and c["tokens_out"] == 0


def test_bare_grok_is_recognised_as_known_unpriced():
    assert cost_for("grok", {"input": 10})["known_unpriced"] is True
    assert cost_for("grok-4", {"input": 10})["known_unpriced"] is True
