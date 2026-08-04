"""Provenrail: off-box, hash-chained, independently verifiable record of agent activity.

Honest guarantee (B2C / single-machine deployment):
  Integrity of *flushed* records only. Once a record reaches the off-box append-only
  sink, it cannot be silently altered, reordered, deleted, or back-dated without the
  standalone verifier detecting it. This does NOT guarantee completeness (a hostile
  agent can refuse to emit an event) and does NOT protect against the machine owner.
  See DESIGN-agent-audit-trail.md section 11 for the full topology/claim matrix.
"""

# Kept in lockstep with pyproject.toml by test_version_matches_pyproject.
__version__ = "0.2.12"

GENESIS_PREV_HASH = "0" * 64


def __getattr__(name: str):
    # Lazy re-export of the simple front door so `import provenrail as fr; fr.record(...)`
    # works without pulling in the SDK/server stack until it is actually used.
    if name in ("record", "recorded", "configure", "make_recorder", "write_config",
                "current_recorder"):
        from . import easy
        return getattr(easy, name)
    if name in ("redactable", "Redactable"):
        from . import redaction
        return getattr(redaction, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
