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

#: Longest glob a rule may carry and still be re-evaluated by an offline verifier. Enforcement
#: at record time has no such limit; this bounds only what a verifier will compile from an
#: untrusted bundle. It is shared with web/verify.js, and it has to be, because a limit on one
#: side alone is a lockstep break: the CLI reported the rule as unenforced while the browser
#: reported the same bundle as fully verified.
MAX_GLOB_PATTERN = 512

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

    @property
    def offline_reverifiable(self) -> bool:
        """False when an offline verifier cannot faithfully re-evaluate this rule.

        A content gate needs argument text the bundle hashes away. An over-long glob is the
        other case: a bundle is an untrusted input handed to a public web page, and a 100k
        character pattern compiles to a regex that is a denial-of-service on the reader's
        browser, so the browser verifier refuses to evaluate it. `fnmatch` on the CLI has no
        such limit, and that difference alone made the two implementations reach opposite
        conclusions about whether a rule had been enforced. They now both decline the same
        patterns and both say so, rather than one quietly skipping the rule.
        """
        return not self.content_based and not self.oversized_glob

    @property
    def oversized_glob(self) -> bool:
        return any(len(p or "") > MAX_GLOB_PATTERN
                   for p in (self.tool, self.resource, self.provider))

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
    #: What a budget does about a model it cannot price. "warn" (the default) allows the call
    #: and says plainly that no cap binds it; "deny" refuses to run a model whose spend cannot
    #: be counted. Warn is the default because a provider shipping a new model would otherwise
    #: stop every budgeted agent on the day of the announcement, which is a worse failure than
    #: a visible blind spot. Teams that treat a cap as a hard control set "deny".
    on_unpriced: str = "warn"

    def __post_init__(self) -> None:
        self.on_unpriced = (self.on_unpriced or "warn").lower()
        if self.on_unpriced not in ("warn", DENY):
            raise ValueError(f"on_unpriced must be 'warn' or 'deny', got {self.on_unpriced!r}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = [Rule.from_dict(r) for r in data.get("rules", [])]
        cap = data.get("session_spend_cap_usd")
        budgets = [Budget.from_dict(b) for b in data.get("budgets", [])]
        return cls(rules=rules, budgets=budgets,
                   on_unpriced=str(data.get("on_unpriced") or "warn"),
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
        if self.on_unpriced != "warn":
            # Omitted at the default so adding this knob leaves every existing policy hash,
            # and every frozen conformance vector, byte-identical.
            out["on_unpriced"] = self.on_unpriced
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
            cost, priced = _estimate_cost(ctx)
            budgets = self.effective_budgets()
            if budgets and not priced:
                session.unpriced_calls += 1
                model = str(ctx.get("model") or "(unnamed model)")
                if self.on_unpriced == DENY:
                    return Decision(DENY, "budget.unpriced",
                                    f"no verified price for {model}, so this call cannot be "
                                    f"counted against a spend cap")
                warning = (f"budget.unpriced: {model} has no verified price, so this call adds "
                           f"$0.00 to every cap. Spend limits are not binding for it.")
            for budget in budgets:
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
            if rule.effect == REQUIRE_OVERSIGHT and not session.satisfied(rule.id):
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
    #: Rule ids a human has explicitly signed off in this session. A single session-wide
    #: "someone approved something" flag let one approval of a harmless action unlock every
    #: other oversight-gated rule in the run, so approving a read query also released a
    #: delete. Oversight is per rule; `had_oversight` remains as the coarse legacy signal for
    #: hosts that record an approval without naming the rule it answered.
    oversight_rules: set[str] = field(default_factory=set)
    prior_day_usd: float = 0.0
    prior_total_usd: float = 0.0
    prior_known: bool = False
    #: Model calls this session that no budget could count, because the model has no verified
    #: price. Every one of them is real money that no cap saw.
    unpriced_calls: int = 0

    def satisfied(self, rule_id: str) -> bool:
        """True when a human has signed off THIS rule, or gave a rule-less blanket approval.

        A host that records oversight without naming a rule (the Claude Code permission
        prompt, an operator calling record_human_oversight by hand) sets `had_oversight` and
        keeps the old blanket behaviour, because tightening that silently would start denying
        work people had genuinely approved. An approval that DOES name its rule only unlocks
        that rule, which is what the out-of-band approval flow always sends.
        """
        return rule_id in self.oversight_rules or self.had_oversight

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
            # A cap reading 12% of its limit means nothing if half the run used a model with no
            # rate. `binding` is False exactly when this figure is a floor rather than a total.
            "unpriced_calls": session.unpriced_calls,
            "binding": session.unpriced_calls == 0,
        })
    return out


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatch((value or "").lower(), (pattern or "*").lower())


def _estimate_cost(ctx: dict[str, Any]) -> tuple[float, bool]:
    """(estimated cost, whether that estimate is real).

    The second value is the one budgets get wrong if they ignore it. A model with no verified
    rate estimates at $0.00, and $0.00 added to projected spend never crosses a cap, so a
    budget silently stops binding the moment an agent moves to a model the price table has not
    caught up with. The cost alone cannot express that; the caller needs the flag.
    """
    from .pricing import cost_for
    c = cost_for(ctx.get("model", ""), ctx.get("usage"))
    return c.get("cost_usd", 0.0), bool(c.get("priced"))
