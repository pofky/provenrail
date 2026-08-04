"""Agent identity registry (Know Your Agent).

The base verifier confirms records were signed by ONE device key. That answers "were these
records produced by a single consistent key" but not "is that the key that belongs to agent X
at organization Y". The registry closes that gap: it binds an `agent_id` (a stable name the
operator chose) to a device public key, in a small signed assertion the verifier can check
offline with the registry's public key.

A registry assertion is deliberately minimal and self-contained so it travels inside the
bundle and verifies with nothing but the registry public key:

    body = {account_id, agent_id, pubkey, status, registered_at, revoked_at}
    assertion = {**body, "sig": Ed25519(registry_key, canonicalize(body))}

Honesty boundary: the registry proves a key was registered to an agent name by whoever holds
the registry key. It does not prove the agent behaved, nor that the operator named it
truthfully; it upgrades "signed by some key" to "signed by the key registered for agent X".
Key rotation keeps the old assertion (with revoked_at set) so historical records still resolve.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonicalize
from .keys import verify_signature


def assertion_body(account_id: str, agent_id: str, pubkey: str, status: str,
                   registered_at: str, revoked_at: str | None) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "agent_id": agent_id,
        "pubkey": pubkey,
        "status": status,
        "registered_at": registered_at,
        "revoked_at": revoked_at,
    }


def sign_assertion(body: dict[str, Any], signing_key) -> dict[str, Any]:
    """Return the assertion with an Ed25519 signature by the registry key."""
    sig = signing_key.sign(canonicalize(body))
    return {**body, "sig": sig}


def verify_assertion(assertion: dict[str, Any], registry_pubkey_hex: str) -> bool:
    """True if the assertion is signed by the given registry key over its own body."""
    body = {k: assertion[k] for k in assertion if k != "sig"}
    expected_keys = {"account_id", "agent_id", "pubkey", "status", "registered_at", "revoked_at"}
    if set(body.keys()) != expected_keys:
        return False
    return verify_signature(registry_pubkey_hex, canonicalize(body), assertion.get("sig", ""))
