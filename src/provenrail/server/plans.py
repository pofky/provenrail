"""Plans, quotas, and feature entitlements: the billing surface for licensed Provenrail.

A plan is a named set of limits and feature flags. Usage is metered per account per UTC
month (server/storage.py `usage` table) and checked here before an over-limit write is
accepted. Features are boolean entitlements gated at the API boundary. A payment provider
only has to flip an account's `plan` column (e.g. from a Polar webhook) to change what that
account may do.

Honesty notes, load-bearing:
  - Quotas and feature gates are a COMMERCIAL control, NOT a security control. They bound
    cost on the build you license and decide which paid capabilities are unlocked. They have
    nothing to do with the integrity guarantee, which holds on every plan, free included.
  - There is no retention dimension. Records are append-only by construction (the storage
    layer forbids UPDATE and DELETE with triggers) and Provenrail hosts no customer records,
    so we cannot and do not promise to delete or to retain on anyone's behalf. Retention is
    the operator's own storage decision. We never claim a retention window we do not control.
  - `None` on a numeric limit means unlimited. A feature value is a plain bool.

Tiers (must match web/index.html pricing and the Polar product mapping exactly):
  free       integrity + local/hosted verify, single project, single user, hash-chain only (no trusted time)
  builder    + RFC 3161 trusted timestamps, + shareable proof links/badge (still single user)
  team       + unlimited projects, + up to 10 members with roles + SSO, + data exports, + attestation/HIPAA
  enterprise unlimited volume + unlimited members, everything on, sold by contact (custom deploy + SLA)
"""

from __future__ import annotations

from typing import Any

# Numeric limits (None = unlimited):
#   events   = records ingested per month
#   anchors  = anchors taken per month
#   streams  = concurrently owned streams (projects)
#   seats    = total users incl. owner (gated on member invite; 1 = single-user plan)
# Feature flags (bool):
#   trusted_time = anchors carry an RFC 3161 trusted timestamp (else hash-chain time only)
#   proof_links  = shareable client proof pages + live integrity badge
#   exports      = bulk data exports (NDJSON / SIEM)
#   reports      = one-click attestation + regime evidence packs (EU AI Act, HIPAA)
#   witnessed    = the independently witnessed (green) transparency-log path is included
#   members      = invite teammates with role-based access (owner/admin/member/viewer)
#   sso          = configure org SSO (OIDC) for member login
PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "events": 50_000,
        "anchors": 1_000,
        "streams": 1,
        "seats": 1,            # single user (owner only); multi-user is a Team feature
        "trusted_time": False,
        "proof_links": False,
        "exports": False,
        "reports": False,
        "witnessed": False,
        "members": False,
        "sso": False,
    },
    "builder": {
        "events": 500_000,
        "anchors": 50_000,
        "streams": 1,
        "seats": 1,            # still single user; Builder adds trusted time + proof links, not seats
        "trusted_time": True,
        "proof_links": True,
        "exports": False,
        "reports": False,
        "witnessed": True,
        "members": False,
        "sso": False,
    },
    "team": {
        "events": 2_000_000,
        "anchors": 200_000,
        "streams": None,
        "seats": 10,           # up to 10 users total (owner + invited), role-based access + SSO
        "trusted_time": True,
        "proof_links": True,
        "exports": True,
        "reports": True,
        "witnessed": True,
        "members": True,
        "sso": True,
    },
    "enterprise": {
        "events": None,
        "anchors": None,
        "streams": None,
        "seats": None,         # unlimited members
        "trusted_time": True,
        "proof_links": True,
        "exports": True,
        "reports": True,
        "witnessed": True,
        "members": True,
        "sso": True,
    },
}

DEFAULT_PLAN = "free"

# Low-to-high tier order, used to compare plans (e.g. a license floor vs a stored plan).
ORDER = ("free", "builder", "team", "enterprise")

# The boolean entitlement keys, so callers can iterate without hard-coding the set.
FEATURES = ("trusted_time", "proof_links", "exports", "reports", "witnessed", "members", "sso")
# The metered numeric keys.
QUOTAS = ("events", "anchors", "streams")
# "seats" is a numeric limit (members incl. owner) gated on invite, not a metered usage dimension,
# so it stays out of QUOTAS to keep the /v1/usage report unchanged.


def rank(plan_name: str | None) -> int:
    """Position of a plan in ORDER (free=0 ... enterprise=3). Unknown plans rank as free."""
    try:
        return ORDER.index(plan_name or DEFAULT_PLAN)
    except ValueError:
        return 0


def higher(a: str | None, b: str | None) -> str:
    """Return whichever of two plan names is the higher tier. Used to apply a license as a
    floor over an account's stored plan."""
    return a if rank(a) >= rank(b) else (b or DEFAULT_PLAN)


def plan_for(name: str | None) -> dict[str, Any]:
    """Return the entitlement dict for a plan name, falling back to free for unknowns."""
    return PLANS.get(name or DEFAULT_PLAN, PLANS[DEFAULT_PLAN])


def limit(plan_name: str | None, key: str) -> int | None:
    return plan_for(plan_name).get(key)


def feature(plan_name: str | None, key: str) -> bool:
    """True if the plan unlocks the named boolean feature. Unknown plan -> free entitlements."""
    return bool(plan_for(plan_name).get(key, False))


def would_exceed(plan_name: str | None, key: str, current: int, add: int = 1) -> bool:
    """True if (current + add) crosses the plan's limit for `key`. Unlimited (None) never does."""
    lim = limit(plan_name, key)
    if lim is None:
        return False
    return current + add > lim


def describe(plan_name: str | None, usage: dict[str, int]) -> dict[str, Any]:
    """A usage report for GET /v1/usage: limits, feature flags, current counts, percent-of-limit."""
    p = plan_for(plan_name)
    out: dict[str, Any] = {
        "plan": plan_name or DEFAULT_PLAN,
        "limits": p,
        "features": {k: bool(p.get(k, False)) for k in FEATURES},
        "usage": usage,
        "percent": {},
    }
    for key in QUOTAS:
        lim = p.get(key)
        used = usage.get(key, 0)
        out["percent"][key] = None if lim in (None, 0) else round(100.0 * used / lim, 1)
    return out
