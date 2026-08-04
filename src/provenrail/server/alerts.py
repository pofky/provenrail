"""Integrity alerting.

After a stream is anchored (or on demand), the engine recomputes the verdict with the
standalone verifier and compares it to the last observed state. On a meaningful transition,
for example a stream that verified cleanly now reports tampering, it fires a signed webhook to
the owning account's subscriptions. This is the difference between a passive archive and
active monitoring: the operator learns their agent's record was altered without having to look.

Two families of alert, on two different clocks.

**Integrity alerts** are about the record itself and are evaluated after an anchor, because
that is when a verdict can change. They answer "has my evidence been altered?".

**Policy alerts** are about the agent's behaviour and fire at ingest, within the same request
that carries the record, because "your agent just tried to wire 100k and was blocked" is
worthless an hour later. They answer "is my agent doing something I forbade?".

Event types:
  integrity.tampered     a previously-clean stream now fails verification
  integrity.recovered    a stream that was tampered now verifies again (e.g. export fixed)
  integrity.first_anchor a stream's first trusted-time anchor landed (informational)
  policy.denied          a policy rule blocked an action the agent attempted

A policy alert reports what the recorder already decided; it is not a second enforcement
point. The action was blocked client-side at the dispatch boundary before this fired, and
the alert exists so a human learns about it now rather than during a later audit.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from . import analytics

POLICY_DENIED = "policy.denied"
BUDGET_WARNING = "budget.warning"
BUDGET_EXCEEDED = "budget.exceeded"
APPROVAL_REQUESTED = "approval.requested"
EVENTS = ("integrity.tampered", "integrity.recovered", "integrity.first_anchor", POLICY_DENIED,
          BUDGET_WARNING, BUDGET_EXCEEDED, APPROVAL_REQUESTED)

# The record action_type the SDK writes for every policy evaluation.
_POLICY_DECISION = "policy.decision"


class AlertEngine:
    def __init__(self, store, deliver: Callable[..., bool], clock: Callable[[], str]):
        self.store = store
        self._deliver = deliver
        self._clock = clock

    def _emit(self, account_id: str | None, event_type: str, stream_id: str,
              verdict: dict[str, Any]) -> int:
        hooks = [h for h in self.store.webhooks_for_delivery(account_id)
                 if event_type in h["events"].split(",") or h["events"] == "*"]
        sent = 0
        for h in hooks:
            event = {
                "id": uuid.uuid4().hex,
                "type": event_type,
                "stream_id": stream_id,
                "at": self._clock(),
                "verdict": {"state": verdict.get("state"), "ok": verdict.get("ok"),
                            "fails": verdict.get("fails"), "warns": verdict.get("warns"),
                            "headline": verdict.get("headline")},
            }
            try:
                if self._deliver(h["url"], h["secret"], event):
                    sent += 1
            except Exception:
                continue
        return sent

    def emit_payload(self, account_id: str | None, event_type: str, stream_id: str,
                     body: dict[str, Any]) -> int:
        """Deliver one already-built event body to every subscribed webhook."""
        hooks = [h for h in self.store.webhooks_for_delivery(account_id)
                 if event_type in h["events"].split(",") or h["events"] == "*"]
        sent = 0
        for h in hooks:
            event = {"id": uuid.uuid4().hex, "type": event_type, "stream_id": stream_id,
                     "at": self._clock(), **body}
            try:
                if self._deliver(h["url"], h["secret"], event):
                    sent += 1
            except Exception:
                continue
        return sent

    @staticmethod
    def denials_in(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Pick the blocked actions out of a batch of just-ingested records.

        Reads only the recorded decision. It does not re-run the policy: re-evaluating
        server-side would need the argument content, which is hashed and never sent by
        default, and would invent a second source of truth for what was enforced.
        """
        out = []
        for r in records or []:
            rec = r.get("record", r) or {}
            if rec.get("action_type") != _POLICY_DECISION:
                continue
            payload = rec.get("payload") or {}
            if str(payload.get("effect", "")).lower() != "deny":
                continue
            out.append({
                "rule": payload.get("rule"),
                "reason": payload.get("reason"),
                "event_type": payload.get("event_type"),
                "target": payload.get("target"),
                "session_id": rec.get("session_id"),
                "seq": rec.get("seq"),
                "ts_utc": rec.get("ts_utc"),
                "record_hash": rec.get("record_hash"),
            })
        return out

    @staticmethod
    def budget_events_in(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Pick budget warnings and budget denials out of a just-ingested batch.

        A budget warning is the alert that actually saves money: it arrives while the run is
        still under the cap and can be stopped, whereas a denial reports work that has already
        been blocked. Both are read from the recorded decision rather than recomputed, for the
        same reason as `denials_in`: the recorder is the single source of truth for what was
        enforced.
        """
        out = []
        for r in records or []:
            rec = r.get("record", r) or {}
            if rec.get("action_type") != _POLICY_DECISION:
                continue
            payload = rec.get("payload") or {}
            rule = str(payload.get("rule") or "")
            is_budget = rule.startswith("budget.") or rule == "session_spend_cap"
            denied = str(payload.get("effect", "")).lower() == "deny"
            warning = payload.get("warning")
            if not (warning or (is_budget and denied)):
                continue
            out.append({
                "type": BUDGET_EXCEEDED if (is_budget and denied) else BUDGET_WARNING,
                "rule": payload.get("rule"),
                "detail": warning or payload.get("reason"),
                "target": payload.get("target"),
                "session_id": rec.get("session_id"),
                "seq": rec.get("seq"),
                "ts_utc": rec.get("ts_utc"),
                "record_hash": rec.get("record_hash"),
                "estimated": True,
            })
        return out

    def check_records(self, stream_id: str, records: list[dict[str, Any]],
                      account_id: str | None) -> dict[str, Any]:
        """Fire a policy.denied alert for each blocked action in a just-ingested batch, and a
        budget alert for each spend warning or budget denial.

        Called on the ingest path so the notification is immediate. One event per denial
        rather than one per batch: an operator needs to see which rule fired on what, and
        collapsing five different denials into a single "5 denials" alert loses exactly the
        detail that makes it actionable.
        """
        denials = self.denials_in(records)
        fired = 0
        for d in denials:
            fired += self.emit_payload(account_id, POLICY_DENIED, stream_id, {"denial": d})
        budget_events = self.budget_events_in(records)
        for b in budget_events:
            fired += self.emit_payload(account_id, b["type"], stream_id, {"budget": b})
        return {"denials": len(denials), "budget_events": len(budget_events), "fired": fired}

    def check_stream(self, stream_id: str, bundle: dict[str, Any],
                     account_id: str | None) -> dict[str, Any]:
        """Recompute the verdict, persist it, and fire webhooks on a state transition.
        Returns {state, prev, fired, events}."""
        if not bundle.get("records"):
            return {"state": "empty", "prev": None, "fired": 0, "events": []}
        verdict = analytics.verdict(bundle)
        state = verdict["state"]
        prev = self.store.get_stream_state(stream_id)
        fired = 0
        events: list[str] = []
        # Healthy states (any non-tampered, non-empty verdict). The transparency-log states
        # amber-proofs and witnessed are healthy upgrades of amber/verified, not tamper events.
        healthy = {"verified", "witnessed", "amber-proofs", "amber"}
        trusted = {"verified", "witnessed"}  # first_anchor means first trusted/witnessed proof
        if prev != state:
            if state == "tampered":
                fired += self._emit(account_id, "integrity.tampered", stream_id, verdict)
                events.append("integrity.tampered")
            elif prev == "tampered" and state in healthy:
                fired += self._emit(account_id, "integrity.recovered", stream_id, verdict)
                events.append("integrity.recovered")
            if prev in (None, "amber", "amber-proofs", "empty") and state in trusted:
                fired += self._emit(account_id, "integrity.first_anchor", stream_id, verdict)
                events.append("integrity.first_anchor")
            self.store.set_stream_state(stream_id, state)
        return {"state": state, "prev": prev, "fired": fired, "events": events}
