"""Account API keys and a small in-memory rate limiter.

API keys authenticate account-level actions (create/list streams). They are distinct from
the per-stream capability tokens (write/read/share): an account key is the operator's
secret and never goes into an agent; write tokens go into agents and can only append.
Only the SHA-256 of a key is stored, so a leaked database does not leak usable keys.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import socket
import threading
import time
import uuid
from collections import deque
from urllib.parse import urlparse


def _ip_is_safe(ip_str: str) -> bool:
    """True only for a public, routable unicast address. Blocks loopback, private (RFC 1918
    / ULA), link-local (incl. the 169.254.169.254 cloud metadata endpoint), reserved,
    multicast and unspecified ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def valid_webhook_url(url: str) -> tuple[bool, str]:
    """Registration-time check: cheap and DNS-free. Requires http(s) and rejects a literal
    private/loopback/reserved IP. A hostname is allowed through here even if it does not
    resolve yet; the authoritative, DNS-resolving check happens at delivery time in
    `safe_outbound_url`, which is what defeats rebinding."""
    try:
        u = urlparse(url)
    except Exception:
        return False, "unparseable url"
    if u.scheme not in ("http", "https"):
        return False, "url must be http(s)"
    host = u.hostname
    if not host:
        return False, "url has no host"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # A hostname normally defers to delivery-time resolution. The loopback names are the
        # exception: they can never be a valid public endpoint, and accepting them here would
        # hand back a 200 for a webhook that then silently never delivers. For an alerting
        # feature, a silent non-delivery is the worst failure mode, so reject it up front
        # with a message that says what to do instead.
        h = host.lower().rstrip(".")
        if h == "localhost" or h.endswith(".localhost") or h == "localhost.localdomain":
            return False, ("url resolves to a non-public address (localhost). Alert endpoints "
                           "must be reachable from the sink; use a public URL or a tunnel.")
        return True, "ok"
    return (True, "ok") if _ip_is_safe(host) else (False, "url resolves to a non-public address")


def safe_outbound_url(url: str) -> tuple[bool, str]:
    """Guard against SSRF for operator-supplied webhook URLs. Requires http(s), resolves the
    host, and rejects the request if any resolved address is non-public. Returns (ok, reason).

    Resolving at delivery time (not just registration) is what closes the DNS-rebinding hole:
    a name that resolved public at registration can later point at an internal address."""
    try:
        u = urlparse(url)
    except Exception:
        return False, "unparseable url"
    if u.scheme not in ("http", "https"):
        return False, "url must be http(s)"
    host = u.hostname
    if not host:
        return False, "url has no host"
    # Literal IP: validate directly.
    try:
        ipaddress.ip_address(host)
        return (True, "ok") if _ip_is_safe(host) else (False, "url resolves to a non-public address")
    except ValueError:
        pass
    # Hostname: every resolved address must be public.
    try:
        infos = socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except Exception:
        return False, "host does not resolve"
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False, "host does not resolve"
    for addr in addrs:
        if not _ip_is_safe(addr):
            return False, "url resolves to a non-public address"
    return True, "ok"


def new_api_key() -> tuple[str, str]:
    """Return (api_key, sha256_hex). The plaintext key is shown to the user once."""
    key = f"pr_sk_{secrets.token_urlsafe(32)}"
    return key, hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_member_key() -> tuple[str, str]:
    """A per-member key, prefixed so it is distinguishable from the org root key."""
    key = f"pr_mk_{secrets.token_urlsafe(32)}"
    return key, hashlib.sha256(key.encode("utf-8")).hexdigest()


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_account_id() -> str:
    return f"acct_{uuid.uuid4().hex[:20]}"


def new_member_id() -> str:
    return f"mbr_{uuid.uuid4().hex[:20]}"


# ---- RBAC: roles and the permissions each grants ----
# Least privilege by role. viewer can look but not export or change anything; member runs
# agents and pulls evidence for its own streams; admin manages streams/members/webhooks;
# owner additionally manages owners and billing. The org root API key maps to owner.
OWNER, ADMIN, MEMBER, VIEWER = "owner", "admin", "member", "viewer"
ROLES = (OWNER, ADMIN, MEMBER, VIEWER)

_PERMS: dict[str, set[str]] = {
    VIEWER: {"stream.read"},
    MEMBER: {"stream.read", "stream.create", "stream.anchor", "stream.export",
             "evidence.export", "agent.manage"},
    ADMIN: {"stream.read", "stream.create", "stream.anchor", "stream.export", "evidence.export",
            "agent.manage", "stream.revoke", "webhook.manage", "member.manage", "audit.read"},
    OWNER: {"stream.read", "stream.create", "stream.anchor", "stream.export", "evidence.export",
            "agent.manage", "stream.revoke", "webhook.manage", "member.manage", "audit.read",
            "owner.manage", "billing.manage"},
}


def role_can(role: str | None, permission: str) -> bool:
    """True if the role grants the permission. None (open/dev mode) is all-powerful."""
    if role is None:
        return True
    return permission in _PERMS.get(role, set())


def assignable_roles(actor_role: str | None) -> set[str]:
    """Which roles an actor may grant. Only an owner may create another owner."""
    if actor_role == OWNER:
        return set(ROLES)
    if actor_role == ADMIN:
        return {ADMIN, MEMBER, VIEWER}
    return set()


class RateLimiter:
    """Fixed-window token bucket keyed by an arbitrary string (IP, account, stream)."""

    def __init__(self, limit: int, window_s: float):
        self.limit = limit
        self.window = window_s
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic() if now is None else now
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = self._hits[key] = deque()
            while dq and dq[0] <= now - self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            # Opportunistically evict idle keys so a flood of distinct keys (e.g. spoofed
            # source IPs) cannot grow this dict without bound. Cheap amortized sweep.
            if len(self._hits) > 4096:
                cutoff = now - self.window
                for k in [k for k, d in self._hits.items() if not d or d[-1] <= cutoff]:
                    if k != key:
                        del self._hits[k]
            return True
