"""Active policy / guardrail layer.

Provenrail is a passive recorder by default: it observes what the agent did. A policy
turns it into an optional enforcer: declarative rules are evaluated at the dispatch boundary,
and the decision (allow or deny, with the rule that fired) is written into the same signed,
hash-chained record stream. The record therefore becomes evidence of enforcement, not merely
of observation: an auditor can verify that a spend cap was in force and that a denied tool call
was actually blocked.

Honesty boundary (consistent with the rest of the product): this is enforcement only over the
dispatch points the SDK wraps. A hostile agent that bypasses the SDK is not constrained, and we
never claim completeness. What a clean record DOES show is that, for the calls that went through
the recorder, the stated policy was applied and the recorded decisions match it. That is a real,
checkable property and a genuine security gradient, framed without overclaiming.

A rule matches on event attributes (event type, tool name, resource, provider) using simple
case-insensitive glob patterns, and has one of two effects:
  - "deny": the action is blocked (PolicyViolation) and a deny decision is recorded.
  - "require_oversight": allowed only if a human_oversight event has been recorded in the
    session already; otherwise treated as a deny with a clear reason.
A session-level spend cap (USD, estimated from model usage) denies a model call that would push
the running estimated cost over the cap.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonicalize, sha256_hex

DENY = "deny"
REQUIRE_OVERSIGHT = "require_oversight"
LIMIT = "limit"
ALLOW = "allow"

# Effects whose verdicts a standalone verifier can re-evaluate offline from recorded metadata
# alone (tool name, provider, model, usage, oversight, counts). A rule that additionally gates on
# argument content (arg_contains) cannot be re-checked once content is hashed, so it is reported
# as enforced-but-not-offline-reverifiable rather than silently trusted or silently dropped.


class PolicyViolation(Exception):
    """Raised when an enforced policy denies an action. Carries the firing rule and reason."""

    def __init__(self, rule_id: str, reason: str):
        self.rule_id = rule_id
        self.reason = reason
        super().__init__(f"policy '{rule_id}' denied the action: {reason}")


@dataclass
class Rule:
    id: str
    effect: str                      # DENY | REQUIRE_OVERSIGHT | LIMIT
    event_type: str = "*"            # tool_call | data_access | model_call | mcp_call | *
    tool: str = "*"                  # glob over the tool name
    resource: str = "*"             # glob over a data_access resource
    provider: str = "*"             # glob over a model provider
    arg_contains: str = ""           # regex over the call's argument/request text (content gate)
    max_per_session: int | None = None  # for LIMIT: deny once this many matches occur in a session
    reason: str = ""

    _FIELDS = ("id", "effect", "event_type", "tool", "resource", "provider",
               "arg_contains", "max_per_session", "reason")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Rule:
        return cls(**{k: v for k, v in d.items() if k in cls._FIELDS})

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self._FIELDS}

    @property
    def content_based(self) -> bool:
        return bool(self.arg_contains)

    def matches(self, event_type: str, ctx: dict[str, Any]) -> bool:
        if self.event_type != "*" and self.event_type != event_type:
            return False
        if not _glob(self.tool, ctx.get("tool", "")):
            return False
        if not _glob(self.resource, ctx.get("resource", "")):
            return False
        if not _glob(self.provider, ctx.get("provider", "")):
            return False
        if self.arg_contains:
            text = ctx.get("match_text", "")
            if text is None or not re.search(self.arg_contains, text, re.IGNORECASE | re.DOTALL):
                return False
        return True


@dataclass
class Decision:
    effect: str          # ALLOW | DENY
    rule_id: str | None
    reason: str


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    session_spend_cap_usd: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = [Rule.from_dict(r) for r in data.get("rules", [])]
        cap = data.get("session_spend_cap_usd")
        return cls(rules=rules, session_spend_cap_usd=None if cap is None else float(cap))

    def to_dict(self) -> dict[str, Any]:
        """Canonical serializable form. The basis for policy_id, so it must be deterministic AND
        canonicalizable: the spend cap is emitted as a string because the record canonicalizer
        forbids floats (they would hash differently across verifiers)."""
        cap = self.session_spend_cap_usd
        return {"rules": [r.to_dict() for r in self.rules],
                "session_spend_cap_usd": None if cap is None else f"{cap:.6f}"}

    def policy_id(self) -> str:
        """A content hash of the policy. Committed into the signed chain at session start so a
        verifier can prove exactly which guardrails were in force and detect any later edit."""
        return sha256_hex(canonicalize(self.to_dict()))

    def decide(self, event_type: str, ctx: dict[str, Any], session: SessionState) -> Decision:
        """Evaluate the policy for one dispatch. ctx may carry tool/resource/provider/usage/model
        and (for content gates) match_text."""
        # Spend cap first, since it is a session-level invariant independent of named rules.
        if event_type == "model_call" and self.session_spend_cap_usd is not None:
            projected = session.spend_usd + _estimate_cost(ctx)
            if projected > self.session_spend_cap_usd + 1e-9:
                return Decision(DENY, "session_spend_cap",
                                f"model call would push estimated session spend to "
                                f"${projected:.4f}, over the ${self.session_spend_cap_usd:.4f} cap")
        for rule in self.rules:
            if not rule.matches(event_type, ctx):
                continue
            if rule.effect == DENY:
                return Decision(DENY, rule.id, rule.reason or "denied by policy")
            if rule.effect == REQUIRE_OVERSIGHT and not session.had_oversight:
                return Decision(DENY, rule.id,
                                rule.reason or "action requires a recorded human_oversight first")
            if rule.effect == LIMIT:
                session.counts[rule.id] = session.counts.get(rule.id, 0) + 1
                if rule.max_per_session is not None and session.counts[rule.id] > rule.max_per_session:
                    return Decision(DENY, rule.id, rule.reason or
                                    f"exceeds the {rule.max_per_session}-per-session limit")
                return Decision(ALLOW, rule.id, f"within the per-session limit "
                                f"({session.counts[rule.id]}/{rule.max_per_session})")
            if rule.effect == REQUIRE_OVERSIGHT:
                # oversight present: an explicit, recorded allow.
                return Decision(ALLOW, rule.id, "allowed: required human oversight is present")
        return Decision(ALLOW, None, "no rule matched")


@dataclass
class SessionState:
    """Running session facts the policy needs: estimated spend, whether oversight occurred, and
    per-rule match counts (for LIMIT rules)."""
    spend_usd: float = 0.0
    had_oversight: bool = False
    counts: dict[str, int] = field(default_factory=dict)


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatch((value or "").lower(), (pattern or "*").lower())


def _estimate_cost(ctx: dict[str, Any]) -> float:
    from .pricing import cost_for
    return cost_for(ctx.get("model", ""), ctx.get("usage")).get("cost_usd", 0.0)
