"""Outbound webhook delivery for integrity alerts.

Every delivery is signed with an HMAC-SHA256 of the exact JSON body using the per-webhook
secret, so a receiver can confirm the alert actually came from this sink and was not forged
or replayed (the body carries a timestamp and event id). Delivery is best-effort with a short
timeout and a couple of retries; an alert that cannot be delivered must never wedge the
anchor loop, so failures are swallowed after retries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SIGNATURE_HEADER = "X-Provenrail-Signature"
EVENT_HEADER = "X-Provenrail-Event"


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def deliver(url: str, secret: str, event: dict[str, Any], *, http: Any | None = None,
            timeout: float = 5.0, max_retries: int = 2) -> bool:
    """POST one signed event. Returns True on a 2xx, False otherwise. Never raises."""
    # Re-validate the destination at delivery time, not just at registration: this is what
    # closes DNS rebinding (a name public when the webhook was created can later resolve to an
    # internal address). A non-public target is dropped, never fetched.
    if http is None:
        from .security import safe_outbound_url
        ok_url, _ = safe_outbound_url(url)
        if not ok_url:
            return False
    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: sign(secret, body),
        EVENT_HEADER: str(event.get("type", "")),
    }
    client = http
    owns = False
    if client is None:
        try:
            import httpx
            client = httpx.Client(timeout=timeout)
            owns = True
        except Exception:
            return False
    try:
        last = False
        for attempt in range(max_retries + 1):
            try:
                resp = client.post(url, content=body, headers=headers)
                code = getattr(resp, "status_code", 0)
                if 200 <= code < 300:
                    return True
                last = False
            except Exception:
                last = False
            if attempt < max_retries:
                continue
        return last
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass
