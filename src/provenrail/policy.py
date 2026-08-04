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

**Budgets** deny a model call that would push estimated spend over a cap, at one of three
scopes. The scope is the whole point: the failure everyone actually has is not one session
that costs too much, it is an agent that runs all night across hundreds of sessions and is
discovered when the invoice arrives. A `session` budget cannot see that; `day` and `total`
can. Scopes:

  - `session`: this run only. Held in memory, always exact.
  - `day`:     this run plus spend already recorded today (UTC), supplied by the caller from
               the local ledger or the sink.
  - `total`:   this run plus all prior recorded spend for the agent.

Cross-session scopes are only as good as the prior figure handed in. A caller that cannot
supply one passes 0 and the budget degrades to session scope rather than failing open
silently: `budget_status()` reports `prior_known` so a dashboard can say which it is.

Budgets also warn before they bite. Crossing `warn_at` (a fraction of the limit) leaves the
decision an allow but attaches a `warning`, which the recorder writes into the chain and the
sink turns into a `budget.warning` alert. A cost alert that arrives after the cap already
blocked the work is a post-mortem, not a control.

Costs here are *estimates* derived from reported token usage and a public price table (see
`pricing.py`). They are labelled as estimates everywhere and are never a substitute for the
provider's invoice.
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
    warning: str | None = None   # set when an allowed call crossed a budget's warn threshold


SESSION = "session"
DAY = "day"
TOTAL = "total"
BUDGET_SCOPES = (SESSION, DAY, TOTAL)


@dataclass
class Budget:
    """A spend cap in USD at one scope, with an optional early warning.

    `warn_at` is a fraction of the limit (0.8 = warn from 80%); 0 disables warnings. The
    warning never changes the verdict, so a budget cannot block work merely by being close.
    """

    scope: str = SESSION
    limit_usd: float = 0.0
    warn_at: float = 0.8
    id: str = ""

    _FIELDS = ("id", "scope", "limit_usd", "warn_at")

    def __post_init__(self) -> None:
        self.scope = (self.scope or SESSION).lower()
        if self.scope not in BUDGET_SCOPES:
            raise ValueError(f"budget scope must be one of {BUDGET_SCOPES}, got {self.scope!r}")
        self.limit_usd = float(self.limit_usd)
        self.warn_at = max(0.0, min(1.0, float(self.warn_at)))
        if not self.id:
            self.id = f"budget.{self.scope}"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Budget:
        return cls(**{k: v for k, v in d.items() if k in cls._FIELDS})

    def to_dict(self) -> dict[str, Any]:
        # Floats are forbidden by the record canonicalizer (they would hash differently across
        # verifiers), so money and fractions are emitted as fixed-precision strings.
        return {"id": self.id, "scope": self.scope,
                "limit_usd": f"{self.limit_usd:.6f}", "warn_at": f"{self.warn_at:.4f}"}


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    session_spend_cap_usd: float | None = None
    budgets: list[Budget] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = [Rule.from_dict(r) for r in data.get("rules", [])]
        cap = data.get("session_spend_cap_usd")
        budgets = [Budget.from_dict(b) for b in data.get("budgets", [])]
        return cls(rules=rules, budgets=budgets,
                   session_spend_cap_usd=None if cap is None else float(cap))

    def to_dict(self) -> dict[str, Any]:
        """Canonical serializable form. The basis for policy_id, so it must be deterministic AND
        canonicalizable: money is emitted as a string because the record canonicalizer forbids
        floats (they would hash differently across verifiers).

        `budgets` is omitted entirely when empty, so committing this change does not alter the
        policy hash of any policy written before budgets existed."""
        cap = self.session_spend_cap_usd
        out: dict[str, Any] = {"rules": [r.to_dict() for r in self.rules],
                               "session_spend_cap_usd": None if cap is None else f"{cap:.6f}"}
        if self.budgets:
            out["budgets"] = [b.to_dict() for b in self.budgets]
        return out

    def effective_budgets(self) -> list[Budget]:
        """Declared budgets, plus the legacy `session_spend_cap_usd` shorthand as a session
        budget when no explicit session budget already covers it."""
        out = list(self.budgets)
        if self.session_spend_cap_usd is not None and not any(b.scope == SESSION for b in out):
            out.append(Budget(scope=SESSION, limit_usd=self.session_spend_cap_usd,
                              warn_at=0.8, id="session_spend_cap"))
        return out

    def policy_id(self) -> str:
        """A content hash of the policy. Committed into the signed chain at session start so a
        verifier can prove exactly which guardrails were in force and detect any later edit."""
        return sha256_hex(canonicalize(self.to_dict()))

    def decide(self, event_type: str, ctx: dict[str, Any], session: SessionState) -> Decision:
        """Evaluate the policy for one dispatch. ctx may carry tool/resource/provider/usage/model
        and (for content gates) match_text."""
        # Budgets first, since they are session-level invariants independent of named rules.
        warning: str | None = None
        if event_type == "model_call":
            cost = _estimate_cost(ctx)
            for budget in self.effective_budgets():
                projected = session.scope_spend(budget.scope) + cost
                if projected > budget.limit_usd + 1e-9:
                    return Decision(DENY, budget.id,
                                    f"model call would push estimated {budget.scope} spend to "
                                    f"${projected:.4f}, over the ${budget.limit_usd:.4f} cap")
                if warning is None and budget.warn_at > 0 and \
                        projected >= budget.limit_usd * budget.warn_at - 1e-9:
                    pct = (projected / budget.limit_usd * 100.0) if budget.limit_usd else 100.0
                    warning = (f"{budget.id}: estimated {budget.scope} spend ${projected:.4f} is "
                               f"{pct:.0f}% of the ${budget.limit_usd:.4f} cap")
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
                                f"({session.counts[rule.id]}/{rule.max_per_session})", warning)
            if rule.effect == REQUIRE_OVERSIGHT:
                # oversight present: an explicit, recorded allow.
                return Decision(ALLOW, rule.id, "allowed: required human oversight is present",
                                warning)
        return Decision(ALLOW, None, "no rule matched", warning)


@dataclass
class SessionState:
    """Running session facts the policy needs: estimated spend, whether oversight occurred, and
    per-rule match counts (for LIMIT rules).

    `prior_day_usd` and `prior_total_usd` carry spend recorded *before* this session, so a
    day or total budget can bind across the many sessions an overnight agent run produces.
    They are supplied by the caller (the local spend ledger, or the sink); when the caller has
    no figure they stay 0 and `prior_known` is False, which `budget_status()` surfaces so a
    cross-session budget is never displayed as authoritative when it is not.
    """
    spend_usd: float = 0.0
    had_oversight: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    prior_day_usd: float = 0.0
    prior_total_usd: float = 0.0
    prior_known: bool = False

    def scope_spend(self, scope: str) -> float:
        """Estimated spend so far against one budget scope, this session included."""
        if scope == DAY:
            return self.prior_day_usd + self.spend_usd
        if scope == TOTAL:
            return self.prior_total_usd + self.spend_usd
        return self.spend_usd


def budget_status(policy: Policy, session: SessionState) -> list[dict[str, Any]]:
    """Per-budget spend, headroom, and percentage, for dashboards, `pr guard status`, and the
    CLI. `prior_known` is reported per budget so a cross-session figure is never presented with
    the same confidence as an in-session one."""
    out: list[dict[str, Any]] = []
    for budget in policy.effective_budgets():
        spent = session.scope_spend(budget.scope)
        limit_usd = budget.limit_usd
        out.append({
            "id": budget.id,
            "scope": budget.scope,
            "limit_usd": round(limit_usd, 6),
            "spent_usd": round(spent, 6),
            "remaining_usd": round(max(0.0, limit_usd - spent), 6),
            "pct": round((spent / limit_usd * 100.0) if limit_usd else 0.0, 2),
            "warn_at_usd": round(limit_usd * budget.warn_at, 6) if budget.warn_at else None,
            "warning": budget.warn_at > 0 and spent >= limit_usd * budget.warn_at - 1e-9,
            "exceeded": spent > limit_usd + 1e-9,
            "prior_known": True if budget.scope == SESSION else session.prior_known,
        })
    return out


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatch((value or "").lower(), (pattern or "*").lower())


def _estimate_cost(ctx: dict[str, Any]) -> float:
    from .pricing import cost_for
    return cost_for(ctx.get("model", ""), ctx.get("usage")).get("cost_usd", 0.0)
