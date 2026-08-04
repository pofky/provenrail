"""Token cost estimation from captured model-call usage.

This is display-only analytics, never part of a hashed or signed record. Prices are public
list prices in USD per 1,000,000 tokens and are deliberately easy to override: pass a custom
table to `cost_for`, or ship a `.provenrail-prices.json`. An unknown model is reported with
`priced=False` and zero cost rather than a wrong guess, so the dashboard can show "unpriced"
instead of silently undercounting spend.

Three details separate a cost number a finance team can act on from one that merely looks
plausible. Every one of them is a silent undercount or double-count if ignored:

**Cached tokens are priced differently, and providers disagree about whether they are already
counted in the input total.** Anthropic reports `input_tokens` *excluding* cache reads and
cache creation; OpenAI reports `prompt_tokens` *including* `cached_tokens`; Google reports
`promptTokenCount` including the cached portion. Pricing both without knowing which convention
applies either double-charges the cached tokens or charges them at the wrong rate. Each entry
therefore declares `cache_inclusive`, and inclusive inputs have their cached portion subtracted
before the uncached input rate is applied.

**Reasoning tokens are already billed as output.** OpenAI's `reasoning_tokens` are a subset of
`completion_tokens`, and Anthropic's thinking tokens are inside `output_tokens`. They are
reported here for visibility and never added again.

**A price table has an expiry.** Every entry carries the date it was verified, and a table
older than `STALE_AFTER_DAYS` reports `stale=True` so the UI can say "prices last verified on
<date>" instead of implying a live feed. Estimates are labelled as estimates everywhere;
reconciliation against the provider's actual invoice is a separate, explicit step.

Enterprise and committed-use customers do not pay list. `load_price_table()` merges an
operator-supplied override file over the built-in table, so a negotiated rate produces a
correct number instead of a wrong one, and `basis` records which prices were used.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

#: Filename looked up in the working directory (and honoured via $PROVENRAIL_PRICES).
PRICES_FILENAME = ".provenrail-prices.json"

#: A table whose newest entry is older than this reports `stale=True`.
STALE_AFTER_DAYS = 120


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1,000,000 tokens for one model.

    `cache_read` / `cache_write` are None when the provider does not price cached tokens
    separately (or when we have not verified the rate); those tokens are then billed at the
    plain input rate and the result says so via `cache_basis`, rather than being dropped.

    `cache_inclusive` describes the provider's *usage reporting*, not its billing: True means
    the reported input/prompt token count already contains the cached tokens, so the cached
    portion must be subtracted before the uncached input rate is applied.
    """

    input: float
    output: float
    cache_read: float | None = None
    cache_write: float | None = None
    cache_inclusive: bool = False
    as_of: str = ""          # ISO date the rate was verified against the provider's public page
    source: str = "list"     # "list" | "override"

    def as_tuple(self) -> tuple[float, float]:
        return (self.input, self.output)


def _a(input_: float, output: float, as_of: str = "2026-05-01") -> ModelPrice:
    """Anthropic: cache read 0.1x input, cache write (5m TTL) 1.25x input, usage EXCLUSIVE."""
    return ModelPrice(input_, output, round(input_ * 0.10, 6), round(input_ * 1.25, 6),
                      cache_inclusive=False, as_of=as_of)


def _o(input_: float, output: float, cache_ratio: float = 0.25,
       as_of: str = "2026-05-01") -> ModelPrice:
    """OpenAI: cached input billed at a discount, no separate cache-write charge, usage
    INCLUSIVE (`prompt_tokens` already contains `cached_tokens`)."""
    return ModelPrice(input_, output, round(input_ * cache_ratio, 6), None,
                      cache_inclusive=True, as_of=as_of)


def _g(input_: float, output: float, as_of: str = "2026-05-01") -> ModelPrice:
    """Google: context-cache reads at 0.25x input, usage INCLUSIVE."""
    return ModelPrice(input_, output, round(input_ * 0.25, 6), None,
                      cache_inclusive=True, as_of=as_of)


def _flat(input_: float, output: float, as_of: str = "2026-05-01") -> ModelPrice:
    """Open-weight / hosted models with no published cache pricing."""
    return ModelPrice(input_, output, None, None, cache_inclusive=False, as_of=as_of)


# model-name substring -> price. Longest matching key wins, so "gpt-4o-mini" resolves before
# "gpt-4o" and "claude-3-5-haiku" before "claude-3".
PRICES: dict[str, ModelPrice] = {
    # OpenAI
    "gpt-4o-mini": _o(0.15, 0.60, cache_ratio=0.50),
    "gpt-4o": _o(2.50, 10.00, cache_ratio=0.50),
    "gpt-4.1-nano": _o(0.10, 0.40),
    "gpt-4.1-mini": _o(0.40, 1.60),
    "gpt-4.1": _o(2.00, 8.00),
    "gpt-4-turbo": _o(10.00, 30.00, cache_ratio=1.0),
    "gpt-3.5-turbo": _o(0.50, 1.50, cache_ratio=1.0),
    "o4-mini": _o(1.10, 4.40),
    "o3-mini": _o(1.10, 4.40),
    "o3": _o(2.00, 8.00),
    "o1-mini": _o(1.10, 4.40),
    "o1": _o(15.00, 60.00),
    # Anthropic
    "claude-3-5-haiku": _a(0.80, 4.00),
    "claude-3-5-sonnet": _a(3.00, 15.00),
    "claude-3-haiku": _a(0.25, 1.25),
    "claude-3-opus": _a(15.00, 75.00),
    "claude-haiku-4-5": _a(1.00, 5.00),
    "claude-haiku-4": _a(1.00, 5.00),
    "claude-sonnet-4-5": _a(3.00, 15.00),
    "claude-sonnet-4": _a(3.00, 15.00),
    "claude-opus-4-5": _a(5.00, 25.00),
    "claude-opus-4": _a(15.00, 75.00),
    # Google
    "gemini-2.5-flash-lite": _g(0.10, 0.40),
    "gemini-2.5-flash": _g(0.30, 2.50),
    "gemini-2.5-pro": _g(1.25, 10.00),
    "gemini-1.5-flash": _g(0.075, 0.30),
    "gemini-1.5-pro": _g(1.25, 5.00),
    # Meta / open weights / others (typical hosted price)
    "llama-3.1-405b": _flat(3.50, 3.50),
    "llama-3.1-70b": _flat(0.90, 0.90),
    "mistral-large": _flat(2.00, 6.00),
    "deepseek-chat": _flat(0.27, 1.10),
    "deepseek-reasoner": _flat(0.55, 2.19),
}

#: Models we know exist but will not price from memory. Reporting these as "known model, no
#: verified rate" is honest; inventing a number would quietly corrupt every budget and finance
#: total downstream. Set a rate in the override file to price them.
KNOWN_UNPRICED: tuple[str, ...] = (
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable-5",
    "gpt-5",
    "grok",
)

# Google reports usage in camelCase over REST and snake_case through the Python SDK, and
# neither spelling matched here before, so a real Gemini response priced at $0.00 while
# reporting priced=True: an authoritative-looking zero, the worst possible failure. Field
# names verified against the official REST reference (ai.google.dev/api/generate-content)
# and the google-genai Python SDK reference.
_INPUT_KEYS = ("input", "in", "input_tokens", "prompt_tokens", "prompt", "tokens_in",
               "promptTokenCount", "prompt_token_count")
_OUTPUT_KEYS = ("output", "out", "output_tokens", "completion_tokens", "completion", "tokens_out",
                "candidatesTokenCount", "candidates_token_count")
_CACHE_READ_KEYS = ("cache_read_input_tokens", "cached_tokens", "cache_read_tokens",
                    "cache_read", "cached_input_tokens", "cached_content_token_count",
                    "cachedContentTokenCount")
_CACHE_WRITE_KEYS = ("cache_creation_input_tokens", "cache_write_tokens", "cache_write",
                     "cache_creation_tokens")
# Reported for visibility, never billed. For OpenAI and Anthropic that is provably right:
# reasoning/thinking tokens are a subset of the output count and are already charged. For
# Google, whether `thoughtsTokenCount` is additive to `candidatesTokenCount` is NOT stated in
# the official token documentation, so it is surfaced and left unbilled rather than guessed at
# in either direction. `cost_for` flags this via `reasoning_billing_unverified` so a caller can
# say so instead of quietly under- or over-charging.
_REASONING_KEYS = ("reasoning_tokens", "thinking_tokens", "reasoning",
                   "thoughtsTokenCount", "thoughts_token_count")

#: Model families whose reasoning-token billing relationship we have not been able to verify
#: from official documentation.
_UNVERIFIED_REASONING_BILLING = ("gemini",)


def _to_int(value: Any) -> int:
    """Token counts are non-negative by definition.

    A negative count would produce a negative cost, and a negative cost SUBTRACTS from
    projected spend, so one bad usage dict could carry a session back under a cap it had
    already blown. No provider emits negative counts; a hand-built or mis-parsed usage dict
    can. Clamping is the difference between a wrong number and a lifted budget.
    """
    try:
        return max(0, int(str(value).strip()))
    except (TypeError, ValueError):
        return 0


def _flatten_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """Fold one level of provider nesting (`prompt_tokens_details.cached_tokens`,
    `output_tokens_details.reasoning_tokens`) into the flat namespace we key on."""
    flat: dict[str, Any] = {}
    for k, v in usage.items():
        if isinstance(v, dict):
            for ik, iv in v.items():
                flat.setdefault(str(ik), iv)
        else:
            flat.setdefault(str(k), v)
    return flat


def _pick(usage: dict[str, Any], keys: tuple[str, ...]) -> int:
    for k in keys:
        if k in usage and usage[k] is not None:
            return _to_int(usage[k])
    return 0


def _coerce_price(value: Any) -> ModelPrice | None:
    """Accept a ModelPrice, a 2-tuple/list, or a dict from an override file."""
    if isinstance(value, ModelPrice):
        return value
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return ModelPrice(float(value[0]), float(value[1]))
    if isinstance(value, dict):
        try:
            return ModelPrice(
                input=float(value.get("input", value.get("in", 0.0))),
                output=float(value.get("output", value.get("out", 0.0))),
                cache_read=None if value.get("cache_read") is None else float(value["cache_read"]),
                cache_write=(None if value.get("cache_write") is None
                             else float(value["cache_write"])),
                cache_inclusive=bool(value.get("cache_inclusive", False)),
                as_of=str(value.get("as_of", "")),
                source=str(value.get("source", "override")),
            )
        except (TypeError, ValueError):
            return None
    return None


def _normalize_table(table: dict[str, Any] | None) -> dict[str, ModelPrice]:
    if table is None:
        return PRICES
    out: dict[str, ModelPrice] = {}
    for key, value in table.items():
        price = _coerce_price(value)
        if price is not None:
            out[str(key).lower()] = price
    return out


def override_path() -> Path | None:
    """The operator's price override file, if one is configured and present."""
    env = os.environ.get("PROVENRAIL_PRICES")
    candidate = Path(env) if env else Path.cwd() / PRICES_FILENAME
    return candidate if candidate.is_file() else None


def load_price_table(path: str | Path | None = None) -> dict[str, ModelPrice]:
    """Built-in list prices with an operator override file merged over the top.

    The override file is `{"model-substring": {"input": 1.5, "output": 6.0, ...}}` or the
    shorthand `{"model-substring": [1.5, 6.0]}`. Overridden entries are tagged
    `source="override"` so a report can state which numbers are negotiated rather than list.
    A malformed file is ignored rather than fatal: a broken price file must never take down
    recording, which is the part that matters.
    """
    target = Path(path) if path is not None else override_path()
    merged = dict(PRICES)
    if target is None or not Path(target).is_file():
        return merged
    try:
        raw = json.loads(Path(target).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return merged
    if not isinstance(raw, dict):
        return merged
    entries = raw.get("prices") if isinstance(raw.get("prices"), dict) else raw
    for key, value in entries.items():
        price = _coerce_price(value)
        if price is not None:
            merged[str(key).lower()] = replace(price, source="override")
    return merged


def table_as_of(table: dict[str, ModelPrice] | None = None) -> str:
    """The newest verification date in the table, or "" if none carry one."""
    dates = [p.as_of for p in (table or PRICES).values() if p.as_of]
    return max(dates) if dates else ""


def is_stale(table: dict[str, ModelPrice] | None = None, today: date | None = None) -> bool:
    """True when the table's newest verified rate is older than STALE_AFTER_DAYS."""
    newest = table_as_of(table)
    if not newest:
        return True
    try:
        when = datetime.strptime(newest, "%Y-%m-%d").date()
    except ValueError:
        return True
    now = today or datetime.now(UTC).date()
    return (now - when).days > STALE_AFTER_DAYS


def resolve(model: str, table: dict[str, Any] | None = None) -> ModelPrice | None:
    """Return the ModelPrice for the longest matching known model, or None."""
    prices = _normalize_table(table)
    name = (model or "").lower()
    best: ModelPrice | None = None
    best_len = -1
    for key, price in prices.items():
        if key in name and len(key) > best_len:
            best, best_len = price, len(key)
    return best


def resolve_price(model: str, table: dict[str, Any] | None = None
                  ) -> tuple[float, float] | None:
    """Return (input, output) $/1M for the longest matching known model, or None."""
    price = resolve(model, table)
    return None if price is None else price.as_tuple()


def is_known_unpriced(model: str) -> bool:
    """True for a model we recognise but deliberately refuse to price from memory."""
    name = (model or "").lower()
    return any(marker in name for marker in KNOWN_UNPRICED)


def cost_for(model: str, usage: dict[str, Any] | None,
             table: dict[str, Any] | None = None) -> dict[str, Any]:
    """Estimate the cost of one model call.

    Returns token counts (including the cached and reasoning breakdown), USD, and the basis
    for the number. `priced=False` means no rate was found and `cost_usd` is 0.0, which the
    caller must surface as "unpriced" rather than as "free".
    """
    usage = _flatten_usage(usage or {})
    tin = _pick(usage, _INPUT_KEYS)
    tout = _pick(usage, _OUTPUT_KEYS)
    t_cache_read = _pick(usage, _CACHE_READ_KEYS)
    t_cache_write = _pick(usage, _CACHE_WRITE_KEYS)
    t_reasoning = _pick(usage, _REASONING_KEYS)

    price = resolve(model, table)
    base: dict[str, Any] = {
        "tokens_in": tin,
        "tokens_out": tout,
        "tokens_cache_read": t_cache_read,
        "tokens_cache_write": t_cache_write,
        "tokens_reasoning": t_reasoning,
    }
    if price is None:
        return {**base, "cost_usd": 0.0, "priced": False, "basis": "unknown",
                "known_unpriced": is_known_unpriced(model), "cache_basis": "none"}

    # Providers that report cached tokens inside the prompt total would otherwise be charged
    # twice: once at the input rate inside `tin`, once at the cache rate.
    uncached_in = max(0, tin - t_cache_read) if price.cache_inclusive else tin
    billable_write = 0 if price.cache_inclusive else t_cache_write

    if price.cache_read is None:
        cache_read_rate, cache_basis = price.input, "assumed_input_rate"
    else:
        cache_read_rate, cache_basis = price.cache_read, "explicit"
    cache_write_rate = price.cache_write if price.cache_write is not None else price.input

    cost = (uncached_in * price.input
            + tout * price.output
            + t_cache_read * cache_read_rate
            + billable_write * cache_write_rate) / 1_000_000.0

    return {
        **base,
        "tokens_billable_in": uncached_in,
        "cost_usd": round(cost, 6),
        "priced": True,
        "basis": price.source,
        "cache_basis": cache_basis,
        "as_of": price.as_of,
        # True when this family's reasoning tokens might be additive to the output count and
        # the provider has not documented it. The estimate then has a known blind spot, and
        # saying so beats a confident number.
        "reasoning_billing_unverified": bool(
            t_reasoning and any(m in (model or "").lower()
                                for m in _UNVERIFIED_REASONING_BILLING)),
    }
