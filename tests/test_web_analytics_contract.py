"""The analytics beacon spans three files that nothing forced to agree, and they drifted.

Three separate holes were live at once on 2026-08-10, none of them visible from any single file:

  - `verify_run` was in the edge function's allow-list and no client code ever emitted it, so the
    in-browser verifier, which is the whole product on that page, produced no signal at all;
  - the beacon posted straight to the Supabase host, which Cloudflare fronts but does not give a
    `cf-ipcountry` header, so `country` was NULL on all 2,204 rows recorded to that point;
  - the pricing CTAs linked to a bare `/account`, dropping the plan the visitor had just picked
    and making them choose it a second time before checkout.

Each is a contract between files rather than a bug inside one, which is why review missed them
and why they are asserted here instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
MAIN_JS = WEB / "main.js"
PAGEVIEW = ROOT / "supabase" / "functions" / "pageview" / "index.ts"
PROXY = ROOT / "functions" / "pv.js"


def _allowed_events() -> set[str]:
    src = PAGEVIEW.read_text(encoding="utf-8")
    block = re.search(r"const ALLOWED_EVENTS = new Set\(\[(.*?)\]\)", src, flags=re.S)
    assert block, "pageview/index.ts no longer declares ALLOWED_EVENTS as a literal set"
    return set(re.findall(r'"([a-z_]+)"', block.group(1)))


def _emitted_events() -> set[str]:
    """Every event name the site can actually send: send('x') / track('x') in the shared script
    and the page scripts, plus the data-ev attributes the click handler forwards verbatim."""
    events: set[str] = set()
    sources = [MAIN_JS] + sorted(WEB.glob("*.html"))
    for path in sources:
        text = path.read_text(encoding="utf-8")
        # Every quoted name inside a send(...) / track(...) call, so a conditional argument
        # (`track(own ? 'verify_own' : 'verify_run')`) counts as emitting both.
        for call in re.findall(r"\b(?:send|track)\(([^)\n]*)\)", text):
            events |= set(re.findall(r"""['"]([a-z_]+)['"]""", call))
        events |= set(re.findall(r'data-ev="([a-z_]+)"', text))
    return events


def test_every_emitted_event_is_accepted_by_the_endpoint() -> None:
    unknown = _emitted_events() - _allowed_events()
    assert not unknown, (
        f"the site emits {sorted(unknown)}, which the pageview function silently rewrites to "
        f"'pageview'. Add them to ALLOWED_EVENTS or stop emitting them."
    )


def test_every_accepted_event_has_something_that_emits_it() -> None:
    """The other direction, which is the one that actually broke: an event can sit in the
    allow-list forever looking like instrumentation while nothing on the site ever sends it."""
    dead = _allowed_events() - _emitted_events()
    assert not dead, (
        f"the pageview function accepts {sorted(dead)} but no page emits it. Either wire it up "
        f"or drop it: an allow-list entry is not instrumentation."
    )


def test_the_verifier_reports_that_it_ran() -> None:
    """The in-browser verifier is the product demo. A visit that verifies something and a visit
    that bounces must not look identical in the data."""
    verify_html = (WEB / "verify.html").read_text(encoding="utf-8")
    assert "verify_run" in verify_html and "verify_own" in verify_html, (
        "verify.html must report both a demo verification and one of the visitor's own bundle"
    )


def test_the_beacon_goes_through_the_edge_proxy_that_knows_the_country() -> None:
    """Posting straight to Supabase cannot record a country: Cloudflare fronts that host but
    does not forward cf-ipcountry to it (checked against the live endpoint). Only our own Pages
    edge sees the country, so the beacon has to land there first."""
    main = MAIN_JS.read_text(encoding="utf-8")
    assert re.search(r"var ENDPOINT = '/pv'", main), "the beacon must post same-origin to /pv"
    assert PROXY.is_file(), (
        "functions/pv.js is missing. It must live in the repo-root functions/ directory: "
        "wrangler bundles ./functions relative to the working directory, not to the deployed "
        "web/ directory, so a copy under web/functions/ is uploaded as a readable static file "
        "and never runs."
    )


def test_the_proxy_does_not_let_anyone_forge_a_country() -> None:
    """The country arrives as a plain header, so the endpoint must only believe it when the
    proxy proves itself. Without the secret the field stays null rather than becoming fiction."""
    fn = PAGEVIEW.read_text(encoding="utf-8")
    assert "PV_PROXY_SECRET" in fn and "x-pv-secret" in fn
    assert re.search(r"if \(!secret \|\| req\.headers\.get\(\"x-pv-secret\"\) !== secret\) return null",
                     fn), "an unproven caller must get country = null, never its own claimed value"
    assert "PV_PROXY_SECRET" in PROXY.read_text(encoding="utf-8")


def test_the_beacon_still_records_the_event_if_the_proxy_is_down() -> None:
    """Analytics is allowed to lose the country. It is not allowed to lose the pageview."""
    main = MAIN_JS.read_text(encoding="utf-8")
    assert "FALLBACK" in main and "supabase.co/functions/v1/pageview" in main
    assert "proxyDown" in main, "a failed /pv must fall back rather than drop the event"


@pytest.mark.parametrize("page", ["index.html", "pricing.html"])
def test_the_plan_the_visitor_picked_survives_the_click(page: str) -> None:
    """"Start Builder" has to start Builder. Linking to a bare /account throws the choice away
    and asks for it again, which is a step between intent and card for no reason."""
    html = (WEB / page).read_text(encoding="utf-8")
    for plan in ("builder", "team"):
        assert f'href="/account?plan={plan}"' in html, (
            f"{page}: the {plan} CTA must carry the plan to the account page"
        )


def test_the_account_page_acts_on_the_carried_plan() -> None:
    account = (WEB / "account.html").read_text(encoding="utf-8")
    assert 'params.get("plan")' in account, "account.html must read the plan from the URL"
    assert "pr_plan_intent" in account, (
        "the plan must survive sign-in, which can happen in another tab via a magic link"
    )
    assert "takePlanIntent" in account and "nowActive" in account, (
        "the intent must be consumed once, and never re-open checkout for an active subscriber"
    )


def test_the_nav_does_not_invite_a_signed_in_visitor_to_sign_in() -> None:
    main = MAIN_JS.read_text(encoding="utf-8")
    assert "'.nav-links a[href=\"/account\"]'" in main and "'Account'" in main, (
        "main.js must relabel the shared nav link when a session token is present"
    )
