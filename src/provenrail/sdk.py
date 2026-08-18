"""Capture SDK: the thing an agent installs to record what it does.

Captures at two boundaries:
  - model calls (record_model_call / wrap_openai-style helpers)
  - the tool-dispatch boundary (@recorder.tool, record_tool_call), which catches LOCAL
    tool calls a network proxy never sees. This directly addresses the red-team finding
    that a network chokepoint misses shell/exec/filesystem/local-model activity.

Privacy default: store-hash-not-content. Inputs/outputs are SHA-256 hashed, not stored,
unless capture_content=True. This keeps PII out of the sink by default.

Honest limitation: this SDK runs inside the agent process, so a hostile agent can refuse
to call it. It cannot make capture complete. Its job is to push records OFF-BOX quickly so
that whatever IS recorded becomes immutable. Completeness is surfaced, never guaranteed.
"""

from __future__ import annotations

import functools
import json
import queue
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import GENESIS_PREV_HASH
from .canonical import hash_value
from .chain import (
    DATA_ACCESS,
    DECISION,
    HUMAN_OVERSIGHT,
    MODEL_CALL,
    TOOL_CALL,
    Chain,
)
from .ingest_client import IngestClient
from .keys import SigningKey


class SinkIntegrityError(RuntimeError):
    """The sink returned a receipt inconsistent with the receipt chain it already issued
    (reorder, fork, or rollback). The sink is misbehaving."""


def _match_text(value: Any) -> str:
    """A bounded text view of a call's arguments for content-gate policy rules (arg_contains).
    Computed in-process only; never sent to the sink (the recorded payload still hashes content
    by default), so a content gate stays local and private."""
    if isinstance(value, str):
        return value[:20000]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        # An argv array IS a command line, and every content rule is written against command
        # lines. Serialized as JSON it reads `["rm", "-rf", "/"]`, where the quotes and commas
        # between the program and its flags defeat `\brm\s+-rf` and every pattern like it. The
        # hook path already joined argv back into a command; a caller using the `decide()` API
        # directly got the JSON, and an allow.
        return " ".join(value)[:20000]
    try:
        text = json.dumps(value, default=str, ensure_ascii=False)[:20000]
    except Exception:
        return str(value)[:20000]
    # json.dumps turns a real tab into the two characters backslash-t, so `rm\t-rf /` stopped
    # matching `\brm\s+-rf`: a shell treats a tab as whitespace and the matcher no longer did.
    # Undo that one substitution, for whitespace only, so the text a rule sees is the text a
    # shell would run. Nothing else is unescaped: a literal backslash-n inside a string stays
    # as written.
    return text.replace("\\t", " ").replace("\\n", " ").replace("\\r", " ")


def _digest(value: Any) -> dict[str, Any]:
    """Return a content descriptor: always a hash, plus the value if small and allowed."""
    try:
        return {"hash": hash_value(value)}
    except Exception:
        # value not JSON-canonicalizable; hash its repr deterministically enough for a digest
        return {"hash": hash_value(repr(value)), "note": "hashed_repr"}


class FlightRecorder:
    def __init__(
        self,
        endpoint: str,
        write_token: str,
        stream_id: str,
        key: SigningKey | None = None,
        capture_content: bool = False,
        http: Any | None = None,
        flush: bool = True,
        pin_path: str | None = None,
        disclosure_path: str | None = None,
        flush_mode: str = "sync",
        flush_interval: float = 0.5,
        flush_batch: int = 50,
        max_retries: int = 3,
        policy: Any | None = None,
        enforce: bool = True,
        approval_timeout: float = 0.0,
        approval_poll: float = 2.0,
    ):
        self.key = key or SigningKey.generate()
        # Optional active-policy enforcement at the dispatch boundary. The decision is recorded
        # into the chain so the record is evidence of enforcement, not just observation.
        self.policy = policy
        self.enforce = enforce
        # Out-of-band oversight. Zero (the default) keeps today's behaviour exactly: a
        # `require_oversight` rule with no recorded oversight denies immediately. A positive
        # timeout turns that denial into a question asked of a human, and blocks the agent for
        # up to this many seconds waiting for the answer. It is opt-in because pausing an agent
        # on a human is a decision the operator must make deliberately, not inherit.
        self.approval_timeout = float(approval_timeout or 0.0)
        self.approval_poll = max(0.05, float(approval_poll))
        self._session_state = None  # policy.SessionState, reset per session
        self.chain = Chain(stream_id=stream_id, key=self.key)
        self.stream_id = stream_id
        self.client = IngestClient(endpoint, write_token, http=http)
        self.capture_content = capture_content
        # Operator-held keystore of redaction openings (commit -> {salt, value}). NEVER sent to
        # the sink: only commitments reach the record. Written to disclosure_path on close.
        self.disclosure_path = disclosure_path
        self._openings: dict[str, Any] = {}
        self._flush = flush
        self._lock = threading.Lock()
        self._hb_stop: threading.Event | None = None
        self._hb_thread: threading.Thread | None = None
        # client-side pin: an independent attestation that the sink held N records ending
        # in this hash at this time. Lets a later verify detect malicious tail-truncation.
        self.pin_path = pin_path
        self.head = {"recv_seq": -1, "server_record_hash": GENESIS_PREV_HASH}
        # transport: "sync" flushes each record before returning (max assurance, adds RTT);
        # "async" buffers and flushes in the background (never blocks the agent). A blocking
        # drain on seal() guarantees the session is fully off-box before it is considered done.
        self._mode = flush_mode
        self._flush_batch = flush_batch
        self._max_retries = max_retries
        if self._mode == "async" and self._flush:
            self._q: queue.Queue = queue.Queue()
            self._worker_stop = threading.Event()
            self._worker = threading.Thread(target=self._worker_loop, args=(flush_interval,),
                                            daemon=True, name="fr-flush")
            self._worker.start()

    # ---- low level ----
    def _push(self, record: dict[str, Any]) -> None:
        if not self._flush:
            return
        if self._mode == "async":
            self._q.put(record)
            return
        self._send_with_retry([record])

    def _worker_loop(self, interval: float) -> None:
        while not self._worker_stop.is_set():
            try:
                first = self._q.get(timeout=interval)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < self._flush_batch:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            try:
                self._send_with_retry(batch)
            finally:
                for _ in batch:
                    self._q.task_done()

    def _send_with_retry(self, batch: list[dict[str, Any]]) -> None:
        delay = 0.2
        for attempt in range(self._max_retries):
            try:
                self._send(batch)
                return
            except SinkIntegrityError:
                raise  # integrity failures are not transient; surface immediately
            except Exception:
                if attempt == self._max_retries - 1:
                    raise
                time.sleep(delay)
                delay *= 2

    #: How far the client will walk to close a gap another writer opened, per receipt. Generous
    #: for real interleaving (measured gaps under 24 concurrent writers were single digits) and
    #: still bounded, so a sink cannot make a client fetch forever.
    MAX_GAP_RECEIPTS = 5000

    #: One request's worth, matching the sink's own per-request ceiling.
    GAP_PAGE = 1000

    def _close_gap(self, prev: str, receipt: dict[str, Any]) -> None:
        """Another writer appended between our last receipt and this one. Prove it, or raise.

        The client is issued a head and expects the next receipt to link to it. That assumption
        only holds while it is the only writer on the stream, and one project with two agents
        breaks it immediately: every record reports tampering when nothing is wrong.

        Not looking would be worse than the false alarm, so instead of assuming adjacency the
        client asks the sink for the links it missed and walks them. The chain must run
        unbroken from the head we were issued to the record we are now being told about. A sink
        that reordered, forked or rolled back cannot produce that walk, so the check it was
        doing before is still being done, just over a span instead of a single step.

        Caller holds self._lock.
        """
        want = self.head["server_record_hash"]
        after = self.head["recv_seq"]
        target = receipt.get("recv_seq")
        cursor = want
        walked = 0
        while cursor != prev and walked < self.MAX_GAP_RECEIPTS:
            try:
                page = self.client.receipts_after(self.stream_id, after, self.GAP_PAGE)
            except Exception as e:
                raise SinkIntegrityError(
                    f"sink receipt links to {prev!r} but last issued head was {want!r}, and the "
                    f"sink would not show the receipts in between, so the gap cannot be checked "
                    f"({e})"
                ) from e
            progressed = False
            for link in page:
                # Stop at our own record: the walk only has to reach the one before it.
                if target is not None and link.get("recv_seq", -1) >= target:
                    break
                if link.get("server_prev_hash") != cursor:
                    raise SinkIntegrityError(
                        f"sink receipt chain does not join up: receipt {link.get('recv_seq')} "
                        f"links to {link.get('server_prev_hash')!r}, expected {cursor!r} "
                        f"(reorder/fork/rollback)"
                    )
                cursor = link.get("server_record_hash")
                after = link.get("recv_seq", after)
                walked += 1
                progressed = True
                if cursor == prev:
                    break
            # A page that moved us nowhere would otherwise be fetched forever.
            if not progressed:
                break
        if cursor != prev:
            raise SinkIntegrityError(
                f"sink receipt links to {prev!r} but the receipts it showed us reach only "
                f"{cursor!r} from our last head {want!r} (reorder/fork/rollback, or more than "
                f"{self.MAX_GAP_RECEIPTS} records arrived from other writers between two of "
                f"ours)"
            )

    def _send(self, batch: list[dict[str, Any]]) -> None:
        resp = self.client.ingest(batch)
        for receipt in resp.get("receipts", []):
            if receipt.get("duplicate"):
                continue
            prev = receipt.get("server_prev_hash")
            with self._lock:
                if (self.head["recv_seq"] == -1
                        and self.head["server_record_hash"] == GENESIS_PREV_HASH
                        and prev is not None):
                    # First receipt this process. A reused stream (the normal quickstart
                    # config pins one) already has a receipt chain, so the sink's stated
                    # head is adopted as the starting point: this process has issued
                    # nothing yet, so there is no local history to contradict. Continuity
                    # is enforced strictly from here on; cross-restart truncation and
                    # forks are what `pr verify` and the signed pin exist to catch.
                    self.head["server_record_hash"] = prev
                if prev is not None and prev != self.head["server_record_hash"]:
                    self._close_gap(prev, receipt)
                self.head = {
                    "recv_seq": receipt.get("recv_seq", self.head["recv_seq"]),
                    "server_record_hash": receipt.get("server_record_hash",
                                                      self.head["server_record_hash"]),
                }
        self._write_pin()

    @property
    def session_id(self) -> str:
        """The current session's id. The chain owns it, and it is reset per session, so read it
        here rather than caching a copy at construction time."""
        return self.chain.session_id

    def flush(self) -> None:
        """Block until every buffered record has reached the sink."""
        if self._mode == "async" and self._flush:
            self._q.join()

    def close(self) -> None:
        self.stop_heartbeat()
        if self._mode == "async" and self._flush:
            self.flush()
            self._worker_stop.set()
        self._write_openings()

    def openings(self) -> dict[str, Any]:
        """The redaction keystore (commit -> {salt, value}) accumulated this session. Operator-held;
        guard it like a secret and never ship it to the sink. Reveal entries to disclose fields;
        destroy entries to erase them while the record stays verifiable."""
        return dict(self._openings)

    def write_openings(self, path: str) -> None:
        Path(path).write_text(json.dumps({"format": "flightrecorder.openings/1",
                                          "openings": self._openings}, indent=2), encoding="utf-8")

    def _write_openings(self) -> None:
        if self.disclosure_path and self._openings:
            self.write_openings(self.disclosure_path)

    def _write_pin(self) -> None:
        if not self.pin_path:
            return
        pin = self.export_pin()
        Path(self.pin_path).write_text(json.dumps(pin), encoding="utf-8")

    def export_pin(self) -> dict[str, Any]:
        """A signed client-held checkpoint of the sink's receipt-chain head."""
        with self._lock:
            recv_seq = self.head["recv_seq"]
            srh = self.head["server_record_hash"]
        body = {
            "stream_id": self.stream_id,
            "recv_seq": recv_seq,
            "server_record_hash": srh,
            "pinned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "pubkey": self.key.public_key_hex(),
        }
        from .canonical import canonicalize
        body["pin_sig"] = self.key.sign(canonicalize(body))
        return body

    def _content(self, label: str, value: Any) -> dict[str, Any]:
        # Replace any redactable fields with salted commitments BEFORE hashing or storing, so the
        # sink only ever sees commitments. The openings are kept operator-side.
        from . import redaction
        value = redaction.extract(value, self._openings)
        d = _digest(value)
        if self.capture_content:
            d["content"] = value
        elif redaction.contains_commitment(value):
            # Keep redactable commitments in the stored record (they are privacy-safe) so they can
            # be disclosed later, without storing the non-redacted siblings.
            d["content"] = redaction.redacted_skeleton(value)
        return {label: d}

    # ---- lifecycle ----
    def start(self, meta: dict[str, Any] | None = None) -> None:
        if self.policy is not None:
            from .policy import SessionState
            self._session_state = SessionState()
            self._seed_prior_spend()
            # Commit the active policy into the session-start record (signed + hash-chained), so a
            # verifier can prove which guardrails were in force and detect any later edit to them.
            meta = {**(meta or {}), "policy": self.policy.to_dict(),
                    "policy_sha256": self.policy.policy_id()}
        with self._lock:
            rec = self.chain.start(meta)
        self._push(rec)

    def _cross_session_budgets(self) -> bool:
        """True when the active policy has a budget that must outlive this process."""
        from .policy import SESSION
        return bool(self.policy is not None
                    and any(b.scope != SESSION for b in self.policy.effective_budgets()))

    def _spend_agent_id(self) -> str:
        """Ledger key. Agent identity if one was set, else the stream, else a shared default."""
        return str(getattr(self, "agent_id", None) or getattr(self, "stream_id", None) or "default")

    def _seed_prior_spend(self) -> None:
        """Carry spend recorded before this session into the session state, so a day or total
        budget binds across the many sessions an overnight run produces. Only touched when such
        a budget exists: a session-only policy never pays for ledger I/O."""
        if self._session_state is None or not self._cross_session_budgets():
            return
        from . import spend as spend_ledger
        day, total, known = spend_ledger.prior_spend(self._spend_agent_id())
        self._session_state.prior_day_usd = day
        self._session_state.prior_total_usd = total
        self._session_state.prior_known = known

    def _is_oversight_rule(self, rule_id: str | None) -> bool:
        """True when the denial came from a rule that wanted a human, not from a hard deny.

        Only `require_oversight` is answerable by a person. A `deny` rule and a blown budget
        are decisions the operator already made, and offering to click past them would turn
        every guardrail into a prompt.
        """
        from .policy import REQUIRE_OVERSIGHT
        if not rule_id:
            return False
        return any(r.id == rule_id and r.effect == REQUIRE_OVERSIGHT
                   for r in getattr(self.policy, "rules", []))

    def _await_human(self, event_type: str, ctx: dict[str, Any], decision: Any) -> bool:
        """Open an approval request and block until a human answers, or the deadline passes.

        Returns True only on an explicit approval. Every other outcome, including a sink that
        is unreachable, a request that expires, and an interrupted wait, returns False and the
        original denial stands: the flow fails closed, always.
        """
        import time

        from .chain import POLICY_DECISION
        target = ctx.get("tool") or ctx.get("resource") or ctx.get("model") or ""
        try:
            req = self.client.request_approval({
                "stream_id": self.stream_id,
                "session_id": self.chain.session_id,
                "rule": decision.rule_id,
                "event_type": event_type,
                "target": target,
                "reason": decision.reason,
                "ttl_seconds": int(self.approval_timeout),
            })
        except Exception:
            return False   # cannot ask anyone: the deny stands
        # Recorded before the wait, so the pause itself is evidence: an auditor can see the
        # agent stopped and asked, even if nobody ever answered.
        self.record(POLICY_DECISION, {
            "effect": "await_oversight", "rule": decision.rule_id,
            "reason": f"waiting up to {int(self.approval_timeout)}s for a human decision",
            "event_type": event_type, "target": target, "enforced": self.enforce,
            "approval_request_id": req.get("request_id"),
        })
        deadline = time.monotonic() + self.approval_timeout
        status = "expired"
        decided_by = ""
        while time.monotonic() < deadline:
            time.sleep(min(self.approval_poll, max(0.0, deadline - time.monotonic())))
            try:
                current = self.client.get_approval(req["request_id"])
            except Exception:
                continue   # a transient sink failure must not read as a decision
            status = current.get("status", "pending")
            if status in ("approved", "denied", "expired"):
                decided_by = current.get("decided_by") or ""
                break
        if status != "approved":
            return False
        # The agent writes the outcome into its own chain and signs it. The sink stores the
        # answer but never holds the signing key, so it cannot manufacture an approval that
        # verifies.
        self.record_human_oversight(
            "approved", approver=decided_by or "out-of-band link", rule=decision.rule_id,
            target=target, approval_request_id=req.get("request_id"), channel="out_of_band")
        return True

    def _enforce(self, event_type: str, ctx: dict[str, Any]) -> None:
        """Evaluate the active policy at a dispatch point. Records the decision into the chain
        (so it is signed evidence of enforcement) and, when a denial is enforced, raises
        PolicyViolation before the action's own record is written."""
        if self.policy is None:
            return
        from .chain import POLICY_DECISION
        from .policy import ALLOW, PolicyViolation, SessionState
        if self._session_state is None:
            self._session_state = SessionState()
        decision = self.policy.decide(event_type, ctx, self._session_state)
        if (decision.effect != ALLOW and self.approval_timeout > 0
                and self._is_oversight_rule(decision.rule_id)):
            # The rule wanted a human, and this process has none at the keyboard. Ask one
            # out of band rather than failing the work outright. A granted approval is
            # recorded as human_oversight first, so re-deciding now finds the oversight
            # present and the SAME policy allows the call: the approval flows through the
            # policy engine, it does not bypass it.
            if self._await_human(event_type, ctx, decision):
                decision = self.policy.decide(event_type, ctx, self._session_state)
        # Record an explicit decision only when a rule fired (deny, an oversight-gated allow, or
        # a budget warning); a default no-rule allow is left silent to avoid doubling every event.
        if decision.rule_id is not None or decision.effect != ALLOW or decision.warning:
            payload = {
                "effect": decision.effect, "rule": decision.rule_id, "reason": decision.reason,
                "event_type": event_type,
                "target": ctx.get("tool") or ctx.get("resource") or ctx.get("model") or "",
                "enforced": self.enforce,
            }
            if decision.warning:
                # Written into the signed chain so the alert the operator receives before an
                # overrun is itself evidence, not a transient notification.
                payload["warning"] = decision.warning
            self.record(POLICY_DECISION, payload)
        if decision.effect != ALLOW and self.enforce:
            raise PolicyViolation(decision.rule_id or "policy", decision.reason)

    def seal(self, outcome: str = "success", trigger: str = "normal") -> None:
        with self._lock:
            rec = self.chain.seal(outcome=outcome, trigger=trigger)
        self._push(rec)

    @contextmanager
    def session(self, meta: dict[str, Any] | None = None):
        self.start(meta)
        try:
            yield self
            self.stop_heartbeat()  # stop before sealing so no heartbeat races the seal
            self.seal(outcome="success", trigger="normal")
        except BaseException:
            self.stop_heartbeat()
            self.seal(outcome="failure", trigger="exception")
            raise
        finally:
            self.close()  # blocking drain: the session is off-box before we return

    # ---- capture ----
    def record(self, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        # Single chokepoint: replace any redactable fields anywhere in the payload (including ones
        # passed directly, like record_decision(detail=redactable(...))) with commitments before
        # the record is hashed, signed, and sent. Idempotent over already-extracted commitments.
        from . import redaction
        payload = redaction.extract(payload, self._openings)
        with self._lock:
            rec = self.chain.append(action_type, payload)
        self._push(rec)
        return rec

    def record_model_call(self, provider: str, model: str, request: Any, response: Any,
                          usage: dict | None = None, **extra) -> dict[str, Any]:
        self._enforce(MODEL_CALL, {"provider": provider, "model": model, "usage": usage,
                                   "match_text": _match_text(request)})
        payload = {"provider": provider, "model": model}
        payload.update(self._content("request", request))
        payload.update(self._content("response", response))
        if usage:
            payload["usage"] = usage
        if extra:
            payload["extra"] = extra
        rec = self.record(MODEL_CALL, payload)
        # Track estimated spend so a spend cap can be enforced across calls, and persist it when
        # a budget has to outlive this process.
        if self._session_state is not None:
            from .pricing import cost_for
            cost = cost_for(model, usage).get("cost_usd", 0.0)
            self._session_state.spend_usd += cost
            if cost and self._cross_session_budgets():
                from . import spend as spend_ledger
                spend_ledger.add_spend(cost, self._spend_agent_id())
        return rec

    def record_tool_call(self, name: str, args: Any, result: Any,
                        outcome: str = "success", kind: str = TOOL_CALL,
                        _skip_policy: bool = False, **extra) -> dict[str, Any]:
        if not _skip_policy:
            self._enforce(kind, {"tool": name, "match_text": _match_text(args)})
        payload = {"tool": name, "outcome": outcome}
        payload.update(self._content("args", args))
        payload.update(self._content("result", result))
        if extra:
            payload["extra"] = extra
        return self.record(kind, payload)

    def record_decision(self, summary: str, **fields) -> dict[str, Any]:
        return self.record(DECISION, {"summary": summary, **fields})

    def record_data_access(self, resource: str, op: str, **fields) -> dict[str, Any]:
        self._enforce(DATA_ACCESS, {"resource": resource, "op": op})
        return self.record(DATA_ACCESS, {"resource": resource, "op": op, **fields})

    def record_human_oversight(self, action: str, **fields) -> dict[str, Any]:
        """Record that a human signed off.

        Passing `rule=` scopes the sign-off to that one rule, so approving a harmless action
        does not silently unlock every other oversight-gated rule in the session. Omitting it
        keeps the older blanket behaviour, which is what a host that cannot name the rule (a
        permission prompt, a manual call) can honestly report.
        """
        if self._session_state is not None:
            rule = fields.get("rule")
            if rule:
                self._session_state.oversight_rules.add(str(rule))
            else:
                self._session_state.had_oversight = True
        return self.record(HUMAN_OVERSIGHT, {"action": action, **fields})

    def tool(self, name: str | None = None, kind: str = TOOL_CALL) -> Callable:
        """Decorator capturing a local tool's args + result at the dispatch boundary."""
        def deco(fn: Callable) -> Callable:
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                # Enforce BEFORE running the tool, so a denied call is actually blocked (the
                # deny decision is recorded inside _enforce, then PolicyViolation propagates).
                self._enforce(kind, {"tool": tool_name})
                try:
                    result = fn(*args, **kwargs)
                except Exception as e:
                    self.record_tool_call(tool_name, {"args": args, "kwargs": kwargs},
                                          {"error": str(e)}, outcome="failure", kind=kind,
                                          _skip_policy=True)
                    raise
                self.record_tool_call(tool_name, {"args": args, "kwargs": kwargs}, result,
                                      kind=kind, _skip_policy=True)
                return result
            return wrapper
        return deco

    # ---- heartbeat ----
    def start_heartbeat(self, interval_s: float = 30.0) -> None:
        if self._hb_thread is not None:
            return
        self._hb_stop = threading.Event()

        def loop():
            while not self._hb_stop.wait(interval_s):
                try:
                    with self._lock:
                        rec = self.chain.heartbeat()
                    self._push(rec)
                except Exception:
                    break

        self._hb_thread = threading.Thread(target=loop, daemon=True)
        self._hb_thread.start()

    def stop_heartbeat(self) -> None:
        if self._hb_stop is not None:
            self._hb_stop.set()
        self._hb_thread = None
        self._hb_stop = None
