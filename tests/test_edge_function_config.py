"""The Polar edge functions must resolve product ids from secrets, never from literals.

This exists because of a real outage-shaped bug. A hardcoded Builder product id was added to
three edge functions as a workaround, at a time when `POLAR_PRODUCT_BUILDER` pointed at a $1
live-test SKU and the secret was believed to be uneditable. The workaround outlived its reason.
When Provenrail moved to its own Polar organization on 2026-08-04, that literal id belonged to
the old organization, so:

  - `polar-checkout` would have created a checkout for a product that does not exist,
  - `polar-webhook` would have acked a real Builder purchase with 202 and never provisioned the
    plan or minted a licence, silently,
  - `polar-prices` silently dropped Builder from the pricing API while Team stayed correct.

Team was unaffected throughout, because it read its secret. Nothing failed loudly. The tests
below are cheap and they turn "someone remembers not to hardcode this" into a build failure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FUNCTIONS = Path(__file__).resolve().parent.parent / "supabase" / "functions"

# Any 8-4-4-4-12 hex UUID sitting in the source as a literal. Polar product, organization and
# subscription ids all take this shape, and none of them belong in code.
UUID_LITERAL = re.compile(r"""["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"""
                          r"""[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']""")

PLAN_FUNCTIONS = ["polar-checkout", "polar-webhook", "polar-prices"]


def _source(name: str) -> str:
    path = FUNCTIONS / name / "index.ts"
    if not path.is_file():
        pytest.skip(f"{name} not present in this checkout")
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", PLAN_FUNCTIONS)
def test_no_hardcoded_uuid_ids(name: str) -> None:
    src = _source(name)
    # Strip comments: the incident is documented in prose in these files, and an id quoted in a
    # comment is a warning to the next reader, not a live configuration value.
    without_comments = re.sub(r"//[^\n]*", "", src)
    without_comments = re.sub(r"/\*.*?\*/", "", without_comments, flags=re.S)
    found = UUID_LITERAL.findall(without_comments)
    assert not found, (
        f"{name}/index.ts hardcodes {found}. Product and organization ids must come from "
        f"Deno.env.get(...), or the next organization move silently breaks billing."
    )


@pytest.mark.parametrize("name", PLAN_FUNCTIONS)
def test_both_plans_resolve_from_secrets(name: str) -> None:
    src = _source(name)
    for var in ("POLAR_PRODUCT_BUILDER", "POLAR_PRODUCT_TEAM"):
        assert f'Deno.env.get("{var}")' in src, (
            f"{name}/index.ts does not read {var}. Both paid plans must resolve the same way; "
            f"an asymmetry here is exactly how Builder broke while Team kept working."
        )


def test_webhook_keeps_its_signature_check() -> None:
    """The webhook is publicly reachable (verify_jwt is off), so its own signature verification
    is the entire security boundary. Losing it would make the endpoint unauthenticated."""
    src = _source("polar-webhook")
    assert "POLAR_WEBHOOK_SECRET" in src
    assert "status: 403" in src, "an unsigned or badly signed delivery must be rejected with 403"


def test_verify_jwt_is_pinned_for_public_functions() -> None:
    """Both publicly-called functions must have the gateway JWT check disabled in config.toml.

    Polar sends no Supabase JWT, and the marketing site fetches prices before anyone signs in.
    Deploying either without it returns 401 at the gateway and breaks billing or pricing with no
    visible error. This was a real 10-minute outage on 2026-08-04.
    """
    config = FUNCTIONS.parent / "config.toml"
    assert config.is_file(), "supabase/config.toml is missing"
    text = config.read_text(encoding="utf-8")
    for fn in ("polar-webhook", "polar-prices"):
        block = re.search(rf"\[functions\.{re.escape(fn)}\](.*?)(?=\n\[|\Z)", text, flags=re.S)
        assert block, f"config.toml has no [functions.{fn}] block"
        assert re.search(r"verify_jwt\s*=\s*false", block.group(1)), (
            f"[functions.{fn}] must set verify_jwt = false"
        )
