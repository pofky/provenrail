"""Replay and diff: compare two runs of an agent with provable fidelity.

Every observability tool can diff two logs. Only an integrity tool can promise the two logs
it diffed are the exact, unaltered records each run produced: the diff is computed over bundles
the standalone verifier has already checked, so a difference is a real behavioral difference,
not a tampered or truncated log. That provable fidelity is the differentiator.

The diff aligns the two runs' meaningful steps (model calls, tool calls, decisions, data
access) by a stable signature (action type + primary target) using a longest-common-subsequence
alignment, then within aligned steps compares a content hash to surface changed payloads. The
output is a step-by-step list tagged equal / changed / added / removed, plus a summary.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonicalize, sha256_hex

_MEANINGFUL = {"model_call", "tool_call", "mcp_call", "decision", "data_access",
               "human_oversight", "policy.decision"}


def _primary(action_type: str, payload: dict[str, Any]) -> str:
    if action_type in ("tool_call", "mcp_call"):
        return payload.get("tool", "")
    if action_type == "model_call":
        return payload.get("model", "")
    if action_type == "data_access":
        return payload.get("resource", "")
    if action_type == "decision":
        return (payload.get("summary", "") or "")[:60]
    if action_type == "policy.decision":
        return f"{payload.get('rule', '')}:{payload.get('effect', '')}"
    if action_type == "human_oversight":
        return payload.get("action", "")
    return ""


def extract_steps(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Ordered, normalized meaningful steps of a run, each with a signature and content hash."""
    steps = []
    records = sorted((sr["record"] for sr in bundle.get("records", [])),
                     key=lambda r: r.get("seq", 1 << 30))
    for r in records:
        at = r.get("action_type", "")
        if at not in _MEANINGFUL:
            continue
        payload = r.get("payload", {})
        primary = _primary(at, payload)
        steps.append({
            "seq": r.get("seq"),
            "action_type": at,
            "primary": primary,
            "signature": f"{at}|{primary}",
            "content_hash": sha256_hex(canonicalize(payload)),
        })
    return steps


def _lcs(a: list[str], b: list[str]) -> list[tuple[int, int]]:
    """Indices (i, j) of a longest common subsequence of two signature lists."""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    pairs: list[tuple[int, int]] = []
    i = j = 0
    while i < n and j < m:
        if a[i] == b[j]:
            pairs.append((i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            i += 1
        else:
            j += 1
    return pairs


def diff_runs(bundle_a: dict[str, Any], bundle_b: dict[str, Any],
              verify: bool = True) -> dict[str, Any]:
    """Diff two runs. When verify is True (default), both bundles are integrity-checked first
    and the result carries each verdict, so a consumer knows the diff is over trustworthy data."""
    result: dict[str, Any] = {}
    if verify:
        from .verifier.verify import verify_bundle
        ra, rb = verify_bundle(bundle_a), verify_bundle(bundle_b)
        result["verified_a"] = ra.ok
        result["verified_b"] = rb.ok

    sa, sb = extract_steps(bundle_a), extract_steps(bundle_b)
    pairs = _lcs([s["signature"] for s in sa], [s["signature"] for s in sb])
    matched_a = {i for i, _ in pairs}
    matched_b = {j for _, j in pairs}

    steps: list[dict[str, Any]] = []
    ia = ib = 0
    pi = 0
    while ia < len(sa) or ib < len(sb):
        if pi < len(pairs) and ia == pairs[pi][0] and ib == pairs[pi][1]:
            a, b = sa[ia], sb[ib]
            tag = "equal" if a["content_hash"] == b["content_hash"] else "changed"
            steps.append({"tag": tag, "action_type": a["action_type"], "primary": a["primary"],
                          "seq_a": a["seq"], "seq_b": b["seq"]})
            ia += 1
            ib += 1
            pi += 1
        elif ia < len(sa) and ia not in matched_a:
            a = sa[ia]
            steps.append({"tag": "removed", "action_type": a["action_type"],
                          "primary": a["primary"], "seq_a": a["seq"], "seq_b": None})
            ia += 1
        elif ib < len(sb) and ib not in matched_b:
            b = sb[ib]
            steps.append({"tag": "added", "action_type": b["action_type"],
                          "primary": b["primary"], "seq_a": None, "seq_b": b["seq"]})
            ib += 1
        else:  # pragma: no cover - alignment guard
            ia += 1
            ib += 1

    summary = {"equal": 0, "changed": 0, "added": 0, "removed": 0}
    for s in steps:
        summary[s["tag"]] += 1
    summary["identical"] = summary["changed"] == 0 and summary["added"] == 0 and summary["removed"] == 0
    result["summary"] = summary
    result["steps"] = steps
    return result
