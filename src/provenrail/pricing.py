"""Token cost estimation from captured model-call usage.

This is display-only analytics, never part of a hashed or signed record. Prices are public
list prices in USD per 1,000,000 tokens (input, output) as of mid-2026 and are deliberately
easy to override: pass a custom table to `cost_for`. An unknown model is reported with
`priced=False` and zero cost rather than a wrong guess, so the dashboard can show "unpriced"
instead of silently undercounting spend.
"""

from __future__ import annotations

from typing import Any

# model-name substring -> (input $/1M, output $/1M). Longest matching key wins, so
# "gpt-4o-mini" resolves before "gpt-4o" and "claude-3-5-haiku" before "claude-3".
PRICES: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "o4-mini": (1.10, 4.40),
    "o3-mini": (1.10, 4.40),
    "o3": (2.00, 8.00),
    "o1-mini": (1.10, 4.40),
    "o1": (15.00, 60.00),
    # Anthropic
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-haiku": (0.25, 1.25),
    "claude-3-opus": (15.00, 75.00),
    "claude-haiku-4": (1.00, 5.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    # Google
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-1.5-pro": (1.25, 5.00),
    # Meta / open weights (typical hosted price)
    "llama-3.1-405b": (3.50, 3.50),
    "llama-3.1-70b": (0.90, 0.90),
    "mistral-large": (2.00, 6.00),
}

_INPUT_KEYS = ("input", "in", "input_tokens", "prompt_tokens", "prompt", "tokens_in")
_OUTPUT_KEYS = ("output", "out", "output_tokens", "completion_tokens", "completion", "tokens_out")


def _to_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _pick(usage: dict[str, Any], keys: tuple[str, ...]) -> int:
    for k in keys:
        if k in usage and usage[k] is not None:
            return _to_int(usage[k])
    return 0


def resolve_price(model: str, table: dict[str, tuple[float, float]] | None = None
                  ) -> tuple[float, float] | None:
    """Return (input, output) $/1M for the longest matching known model, or None."""
    prices = table or PRICES
    name = (model or "").lower()
    best: tuple[float, float] | None = None
    best_len = -1
    for key, price in prices.items():
        if key in name and len(key) > best_len:
            best, best_len = price, len(key)
    return best


def cost_for(model: str, usage: dict[str, Any] | None,
             table: dict[str, tuple[float, float]] | None = None) -> dict[str, Any]:
    """Estimate the cost of one model call. Returns tokens and USD; priced=False if unknown."""
    usage = usage or {}
    tin = _pick(usage, _INPUT_KEYS)
    tout = _pick(usage, _OUTPUT_KEYS)
    price = resolve_price(model, table)
    if price is None:
        return {"tokens_in": tin, "tokens_out": tout, "cost_usd": 0.0, "priced": False}
    cost = (tin * price[0] + tout * price[1]) / 1_000_000.0
    return {"tokens_in": tin, "tokens_out": tout, "cost_usd": round(cost, 6), "priced": True}
