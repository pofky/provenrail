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
    c = cost_for("gpt-5", {"input_tokens": 1000, "output_tokens": 1000})
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
    # 400k cached at $0.03 + 200k out at $2.50
    assert c["priced"] is True
    assert c["cost_usd"] == pytest.approx(0.692)
    assert c["tokens_billable_in"] == 600_000


def test_google_cache_read_is_a_tenth_of_input_not_a_quarter():
    """The cache rate was carried at 0.25x from an assumption. The published rates are
    $0.03 against $0.30 for flash, $0.01 against $0.10 for flash-lite, and $0.125 against
    $1.25 for pro: one tenth in every case. At 0.25x every Google cache hit was overcharged
    by 150%.

    Pro is measured below its 200k tier here, because above it the cached rate doubles along
    with the input rate (see test_a_tiered_model_tiers_its_cached_reads_too)."""
    for model, expected in (("gemini-2.5-flash", 0.03), ("gemini-2.5-flash-lite", 0.01)):
        c = cost_for(model, {"promptTokenCount": 1_000_000,
                             "cachedContentTokenCount": 1_000_000})
        assert c["cost_usd"] == pytest.approx(expected), model
    pro = cost_for("gemini-2.5-pro", {"promptTokenCount": 100_000,
                                      "cachedContentTokenCount": 100_000})
    assert pro["cost_usd"] == pytest.approx(0.0125)


def test_google_python_sdk_snake_case_usage_is_priced():
    c = cost_for("gemini-2.5-pro", {"prompt_token_count": 100_000,
                                    "candidates_token_count": 0})
    assert c["priced"] is True
    assert c["cost_usd"] == pytest.approx(0.125)


def test_gemini_pro_switches_to_the_long_prompt_tier_over_200k():
    """Gemini 2.5 Pro lists two price tiers and the higher one applies to the whole call, not
    only the excess. A flat rate undercharges precisely the long-context calls that cost the
    most, so a budget would keep letting them through."""
    under = cost_for("gemini-2.5-pro", {"promptTokenCount": 200_000,
                                        "candidatesTokenCount": 100_000})
    over = cost_for("gemini-2.5-pro", {"promptTokenCount": 200_001,
                                       "candidatesTokenCount": 100_000})
    assert under["tier_applied"] is False
    assert under["cost_usd"] == pytest.approx(0.2 * 1.25 + 0.1 * 10.00)
    assert over["tier_applied"] is True
    assert over["cost_usd"] == pytest.approx(0.200001 * 2.50 + 0.1 * 15.00)


def test_gemini_thinking_tokens_are_billed_on_top_of_the_candidate_count():
    """Two official statements settle this. The REST reference defines totalTokenCount as
    "prompt + thoughts + response candidates", so thoughts are not inside candidatesTokenCount,
    and the pricing page labels the output row "Output price (including thinking tokens)".
    Leaving them unbilled undercounted every Gemini thinking call."""
    c = cost_for("gemini-2.5-flash", {"promptTokenCount": 0, "candidatesTokenCount": 1_000_000,
                                      "thoughtsTokenCount": 1_000_000})
    assert c["tokens_reasoning"] == 1_000_000
    assert c["cost_usd"] == pytest.approx(5.00)   # 2M output tokens at $2.50
    assert c["reasoning_billing_unverified"] is False


def test_openai_and_anthropic_reasoning_stays_a_subset_and_is_not_double_charged():
    openai = cost_for("o3", {"prompt_tokens": 0, "completion_tokens": 1_000_000,
                             "output_tokens_details": {"reasoning_tokens": 900_000}})
    assert openai["cost_usd"] == pytest.approx(8.00)
    anthropic = cost_for("claude-sonnet-4-5", {"input_tokens": 0, "output_tokens": 1_000_000,
                                               "output_tokens_details":
                                                   {"thinking_tokens": 900_000}})
    assert anthropic["cost_usd"] == pytest.approx(15.00)


def test_anthropic_one_hour_cache_writes_cost_double_not_1_25x():
    """`cache_creation_input_tokens` is the 5m + 1h total and the TTL split arrives nested in
    `cache_creation`. Pricing the whole total at the 5-minute 1.25x rate undercounts every
    long-TTL write, which is the tier a large repeated system prompt actually uses."""
    c = cost_for("claude-sonnet-4-5", {
        "input_tokens": 0, "output_tokens": 0,
        "cache_creation_input_tokens": 800_000,
        "cache_creation": {"ephemeral_5m_input_tokens": 500_000,
                           "ephemeral_1h_input_tokens": 300_000},
    })
    # 500k at 1.25 x $3 + 300k at 2.0 x $3
    assert c["cost_usd"] == pytest.approx(0.5 * 3.75 + 0.3 * 6.00)
    assert c["tokens_cache_write"] == 800_000 and c["tokens_cache_write_1h"] == 300_000
    # with no split reported, the whole write stays at the 5-minute rate rather than guessing
    plain = cost_for("claude-sonnet-4-5", {"cache_creation_input_tokens": 800_000})
    assert plain["cost_usd"] == pytest.approx(0.8 * 3.75)


def test_current_opus_models_are_not_billed_at_the_retired_opus_4_rate():
    """Longest-substring resolution handed claude-opus-4-6/4-7/4-8 to the "claude-opus-4"
    entry, because "claude-opus-4-5" does not contain them. Every current Opus call was
    estimated at 3x its real price."""
    for model in ("claude-opus-4-5", "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
                  "claude-opus-5"):
        c = cost_for(model, {"input_tokens": 1_000_000, "output_tokens": 1_000_000})
        assert c["cost_usd"] == pytest.approx(30.00), model
    for retired in ("claude-opus-4-1", "claude-opus-4-20250514"):
        c = cost_for(retired, {"input_tokens": 1_000_000, "output_tokens": 1_000_000})
        assert c["cost_usd"] == pytest.approx(90.00), retired


def test_a_published_future_price_change_is_flagged_before_it_bites():
    """Sonnet 5 is on introductory pricing that the provider has already announced ends on
    31 August 2026. The table is freshly verified and still about to be wrong, which ordinary
    staleness cannot express."""
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000}
    before = cost_for("claude-sonnet-5", usage, today="2026-08-04")
    assert before["cost_usd"] == pytest.approx(12.00)   # $2 in + $10 out, introductory
    assert before["price_until"] == "2026-08-31"
    assert before["price_expired"] is False
    # The date is passed in rather than read from the clock, so the expired branch is actually
    # exercised. Asserting "not expired yet" against the real clock tests nothing today and
    # fails the build on 1 September, which is the one day the flag starts mattering.
    assert cost_for("claude-sonnet-5", usage, today="2026-09-01")["price_expired"] is True
    assert cost_for("claude-sonnet-4-5", {"input_tokens": 1})["price_until"] is None


def test_negative_token_counts_cannot_reduce_a_budget():
    """A negative cost subtracts from projected spend and could carry a session back under a
    cap it had already blown."""
    c = cost_for("claude-sonnet-4-5", {"input_tokens": -1_000_000, "output_tokens": -50})
    assert c["cost_usd"] == 0.0
    assert c["tokens_in"] == 0 and c["tokens_out"] == 0


def test_bare_grok_is_recognised_as_known_unpriced():
    assert cost_for("grok", {"input": 10})["known_unpriced"] is True
    assert cost_for("grok-4", {"input": 10})["known_unpriced"] is True


def test_a_tiered_model_tiers_its_cached_reads_too():
    """Gemini 2.5 Pro charges $0.125/M for cached reads below 200k input tokens and $0.25/M
    above it. The input and output rates crossed the boundary and the cache rate did not, so
    every long-context cached read was billed at half price: exactly the calls where caching is
    worth using, and exactly where a spend cap most needs to be right."""
    from provenrail.pricing import PRICES, cost_for

    price = PRICES["gemini-2.5-pro"]
    assert price.cache_read == 0.125 and price.tier_cache_read == 0.25

    above = cost_for("gemini-2.5-pro",
                     {"input": 250_000, "output": 1_000, "cache_read": 100_000})
    # 150k uncached at $2.50/M + 1k out at $15/M + 100k cached at $0.25/M
    assert abs(above["cost_usd"] - (0.375 + 0.015 + 0.025)) < 1e-9

    below = cost_for("gemini-2.5-pro",
                     {"input": 100_000, "output": 1_000, "cache_read": 50_000})
    # 50k uncached at $1.25/M + 1k out at $10/M + 50k cached at $0.125/M
    assert abs(below["cost_usd"] - (0.0625 + 0.01 + 0.00625)) < 1e-9


def test_o_series_cache_discounts_are_not_one_number():
    """o3 and o4-mini are billed at 25% of input for a cached read, o1 and o3-mini at 50%.
    Taking one default for all four halved the recorded cost of every cached call on the two
    older reasoning models. Verified against developers.openai.com/api/docs/pricing 2026-08-05."""
    from provenrail.pricing import PRICES

    assert PRICES["o1"].cache_read == 7.50
    assert PRICES["o3-mini"].cache_read == 0.55
    assert PRICES["o3"].cache_read == 0.50
    assert PRICES["o4-mini"].cache_read == 0.275
