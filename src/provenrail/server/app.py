"""Provenrail ingest + export + public proof viewer.

Design constraints enforced here:
  - No DELETE or UPDATE route exists for records or anchors (append-only by construction).
  - Write tokens may ONLY append; they are rejected on read/export/share routes.
  - Read tokens may NOT write.
  - The share view is read-only and exposes no token.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import threading
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .. import anchor as anchor_mod
from .. import redaction
from ..anchor import Anchor, LocalAnchor
from ..canonical import CanonicalError
from . import approvals as approvals_mod
from . import plans
from . import security as sec
from . import storage as storage_mod
from . import tokens as tok
from .scheduler import AnchorScheduler

#: A finance query window is a plain UTC date. Rejecting anything else keeps a malformed
#: range from silently matching nothing and reporting $0.00 as if it were a real total.
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class CreateStreamIn(BaseModel):
    label: str | None = None


class CreateAccountIn(BaseModel):
    label: str | None = None


class IngestIn(BaseModel):
    records: list[dict[str, Any]]


class AnchorRootIn(BaseModel):
    """One anchor from a customer-hosted sink.

    Note what is absent: there is no field for a record, a prompt, an output, or a name. The
    schema is the privacy guarantee. A customer who self-hosts sends the root of their own
    hash tree and keeps everything the root was computed over, so this endpoint cannot receive
    personal data even if a caller wanted to send it."""
    stream_id: str
    merkle_root: str
    # Bounded because SQLite stores a signed 64-bit integer and an unbounded int reached the
    # INSERT as an OverflowError, after a live TSA round-trip had already been spent on it.
    # 2^53 is far past any real stream and stays exact in JSON consumers.
    covers_up_to: int = Field(ge=1, le=2**53)


class ApprovalIn(BaseModel):
    """An agent asking a human to approve one action it is about to take."""
    stream_id: str
    session_id: str | None = None
    rule: str | None = None
    event_type: str | None = None
    target: str | None = None
    reason: str = ""
    ttl_seconds: int = 3600


class VerifyIn(BaseModel):
    bundle: dict[str, Any]
    pin: dict[str, Any] | None = None
    openings: dict[str, Any] | None = None


class CreateWebhookIn(BaseModel):
    url: str
    events: list[str] | None = None  # subset of alerts.EVENTS, or None/['*'] for all


class InviteMemberIn(BaseModel):
    role: str
    label: str | None = None
    email: str | None = None


class UpdateMemberIn(BaseModel):
    role: str | None = None
    status: str | None = None  # active | disabled


class RegisterAgentIn(BaseModel):
    agent_id: str
    pubkey: str  # 64-char hex Ed25519 device public key


class OidcConfigIn(BaseModel):
    issuer: str
    audience: str
    jwks: dict[str, Any]
    default_role: str = "member"
    email_domain: str | None = None


class SsoLoginIn(BaseModel):
    id_token: str


class RotateAgentIn(BaseModel):
    old_pubkey: str
    new_pubkey: str


class SetPlanIn(BaseModel):
    plan: str


def create_app(
    db_path: str = ":memory:",
    anchor: Anchor | None = None,
    max_batch: int = 500,
    max_record_bytes: int = 65_536,
    max_records_per_stream: int = 5_000_000,
    auto_anchor_interval: float = 0.0,
    require_account: bool = True,
    billing_secret: str | None = None,
    signup_per_min: int = 10,
    ingest_per_min: int = 6000,
    anchor_per_min: int = 60,
    export_per_min: int = 120,
    share_per_min: int = 120,
    verify_per_min: int = 60,
    max_verify_bytes: int = 8_000_000,
    tlog_log_key: Any | None = None,
    tlog_origin_prefix: str | None = None,
    tlog_witnesses: list | None = None,
    tlog_witness_threshold: int = 0,
    tlog_per_min: int = 300,
    registry_key: Any | None = None,
    license_token: str | None = None,
) -> FastAPI:
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        _app.state.scheduler.start()
        yield
        _app.state.scheduler.stop()

    app = FastAPI(title="Provenrail", version="0.2.0", lifespan=lifespan)
    store = storage_mod.Storage(db_path)
    tokens = tok.TokenStore(store._db)  # share the same sqlite connection
    anchor_backend: Anchor = anchor or LocalAnchor()

    # Persisted server identity: the transparency-log key signs checkpoints and the registry
    # key signs KYA assertions. Both MUST be stable across restarts (a hosted sink reboots),
    # so when not injected they are loaded from / created in the DB rather than regenerated.
    if tlog_log_key is None:
        tlog_log_key = store.get_or_create_signing_key("tlog_log_key_pem")
    if registry_key is None:
        registry_key = store.get_or_create_signing_key("registry_key_pem")

    def _alert_on_policy_denials(stream_id: str, records: list[dict]) -> None:
        """Fire policy.denied webhooks for a just-ingested batch, off the request path.

        Delivery is a network call with retries (up to ~15s worst case), so running it
        inline would make an agent's ingest wait on the operator's webhook endpoint. The
        agent must never be slowed, or worse blocked, by alerting: it runs on a daemon
        thread and every failure is swallowed.
        """
        from ..chain import _utc_now_iso
        from . import notifier
        from .alerts import AlertEngine
        engine = AlertEngine(store, notifier.deliver, _utc_now_iso)
        if not engine.denials_in(records):
            return  # the overwhelmingly common case: no thread, no work
        owner = store.stream_owner(stream_id)

        def _run() -> None:
            try:
                engine.check_records(stream_id, records, owner)
            except Exception:
                pass  # alerting must never affect ingest

        threading.Thread(target=_run, name="pr-policy-alert", daemon=True).start()

    def _alert_approval_requested(stream_id: str, request: dict[str, Any]) -> None:
        """Deliver the approve/deny links to whoever is on call, off the request path.

        This alert is the only one that carries a capability, so it goes to the operator's own
        subscribed endpoints and nowhere else. The agent is blocked waiting for an answer, so
        the delivery must not also block the request that opened the request.
        """
        from ..chain import _utc_now_iso
        from . import notifier
        from .alerts import APPROVAL_REQUESTED, AlertEngine
        engine = AlertEngine(store, notifier.deliver, _utc_now_iso)
        owner = store.stream_owner(stream_id)

        def _run() -> None:
            try:
                engine.emit_payload(owner, APPROVAL_REQUESTED, stream_id, {"approval": request})
            except Exception:
                pass  # a missed notification must never break the approval flow itself

        threading.Thread(target=_run, name="pr-approval-alert", daemon=True).start()

    def _alert_after_anchor(stream_id: str) -> None:
        from ..chain import _utc_now_iso
        from . import notifier
        from .alerts import AlertEngine
        engine = AlertEngine(store, notifier.deliver, _utc_now_iso)
        engine.check_stream(stream_id, _bundle(store, stream_id), store.stream_owner(stream_id))

    # Commercial license: a valid signed token makes the whole self-hosted deployment run at the
    # licensed tier. Resolved once at startup from the explicit arg, else PROVENRAIL_LICENSE / the
    # file written by `pr activate`. Verified fully offline (src/provenrail/license.py).
    from .. import license as license_mod
    _lic = license_mod.verify_license(license_token or license_mod.load_license_token())
    licensed_plan = _lic.plan if (_lic.valid and _lic.plan in plans.PLANS) else None

    def _effective_plan(owner: str | None) -> str | None:
        """The plan actually in force for an owning account: the licensed tier when a valid
        license is active, otherwise the account's stored plan. None for open/dev streams."""
        if owner is None:
            return None
        return licensed_plan or store.account_plan(owner)

    def _plan_lookup(account_id: str | None) -> str | None:
        return _effective_plan(account_id)

    def _seats_in_use(account_id: str) -> int:
        """Users occupying a seat: the owner, plus every member who can still sign in.

        Disabled members are excluded deliberately. Their key is refused at authentication, so
        they are not using the product, and a member row can never be deleted (it is referenced
        by the audit log, which has to stay resolvable). Counting them would mean an org that
        rotates staff ratchets toward its cap with no way back short of upgrading, and the
        "free a seat" advice in the 402 would be advice nobody could follow."""
        members = store.list_members(account_id)
        return sum(1 for m in members if m["status"] == "active") + 1

    def _gate_feature(owner: str | None, feat: str) -> None:
        """Raise 402 if the plan in force for an owning account does not unlock a paid feature.
        Open/dev streams (no owner) are never gated. Commercial control, not a security control:
        the integrity guarantee holds on every plan regardless of this gate."""
        if owner is not None and not plans.feature(_effective_plan(owner), feat):
            raise HTTPException(402, f"plan upgrade required: the '{feat}' feature is not "
                                "included in this account's plan")

    scheduler = AnchorScheduler(store, anchor_backend, auto_anchor_interval,
                                on_anchor=_alert_after_anchor,
                                tlog_log_key=tlog_log_key,
                                tlog_origin_prefix=tlog_origin_prefix,
                                witnesses=tlog_witnesses or [],
                                witness_threshold=tlog_witness_threshold,
                                plan_lookup=_plan_lookup)
    # _bundle needs the same origin prefix the scheduler published under, and the registry key
    # to embed agent-identity assertions.
    store.tlog_origin_prefix = scheduler.tlog_origin_prefix
    store.registry_key = registry_key  # set to the resolved key below once app.state exists
    app.state.caps = {
        "max_batch": max_batch,
        "max_record_bytes": max_record_bytes,
        "max_records_per_stream": max_records_per_stream,
    }
    app.state.store = store
    app.state.tokens = tokens
    app.state.approvals = approvals_mod.ApprovalStore(store._db)
    app.state.anchor = anchor_backend
    app.state.scheduler = scheduler
    app.state.require_account = require_account
    # Only the payment provider's webhook knows this, so only a real payment can raise a plan.
    # Unset means no upgrade can be applied over the API at all, which is the safe default for
    # a self-hosted sink that has no billing provider in front of it.
    app.state.billing_secret = billing_secret or os.environ.get("PROVENRAIL_BILLING_SECRET")
    app.state.signup_limiter = sec.RateLimiter(signup_per_min, 60.0)
    app.state.ingest_limiter = sec.RateLimiter(ingest_per_min, 60.0)
    # Anchor triggers a TSA round-trip and export/share run a full verify; both are far more
    # expensive than ingest, so they get their own tighter per-stream limits.
    app.state.anchor_limiter = sec.RateLimiter(anchor_per_min, 60.0)
    app.state.export_limiter = sec.RateLimiter(export_per_min, 60.0)
    app.state.share_limiter = sec.RateLimiter(share_per_min, 60.0)
    app.state.verify_limiter = sec.RateLimiter(verify_per_min, 60.0)
    app.state.tlog_limiter = sec.RateLimiter(tlog_per_min, 60.0)
    app.state.max_verify_bytes = max_verify_bytes
    # Registry signing key: signs agent identity (KYA) assertions embedded in bundles, so an
    # offline verifier can confirm the device key is the one registered for the agent.
    app.state.registry_key = registry_key
    store.registry_key = app.state.registry_key

    def _witness_pubkeys() -> dict[str, str]:
        out: dict[str, str] = {}
        for w in app.state.scheduler.witnesses:
            name = getattr(w, "name", None)
            pub = (w.public_key_hex() if hasattr(w, "public_key_hex")
                   else getattr(w, "pubkey_hex", None))
            if name and pub:
                out[name] = pub
        return out

    def _verdict(bundle: dict[str, Any]) -> dict[str, Any]:
        """Verdict computed with this server's own log key and configured witnesses, so the
        dashboard and badge can show the witnessed (green) state."""
        from . import analytics
        return analytics.verdict(bundle, tlog_log_key=app.state.scheduler.tlog_log_key.public_key_hex(),
                                 witness_pubkeys=_witness_pubkeys())

    def _principal(authorization: str | None) -> dict[str, Any] | None:
        """Resolve the caller to {account_id, role, actor}. None in open/dev mode.

        The org root API key maps to an owner; a member key maps to that member's role. This
        is the single chokepoint both the legacy account resolution and RBAC build on."""
        if not app.state.require_account:
            return None
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing API key")
        key_hash = sec.hash_key(authorization.split(" ", 1)[1].strip())
        acct = store.resolve_account(key_hash)
        if acct is not None:
            return {"account_id": acct["account_id"], "role": sec.OWNER, "actor": "account_key"}
        member = store.resolve_member(key_hash)
        if member is not None:
            _check_seat_still_paid(member)
            return {"account_id": member["account_id"], "role": member["role"],
                    "actor": member["member_id"]}
        raise HTTPException(401, "invalid API key")

    def _check_seat_still_paid(member: dict[str, Any]) -> None:
        """Refuse a member key whose seat the account's current plan no longer covers.

        The seat limit was only ever checked when a member was created, so a plan could shrink
        underneath one. Cancel a Team subscription and every teammate you invited kept their key
        and kept reading the audit trail, indefinitely, on a single-seat plan. Downgrades from
        Enterprise had the same shape with a number instead of a boolean.

        Which members keep access is decided by invitation order, oldest first, so the outcome
        is deterministic and the same on every request rather than depending on who calls when.
        The owner is never affected: the owner key is resolved before this, and always holds
        seat one. Nothing is deleted or disabled here, so restoring the plan restores access."""
        account_id = member["account_id"]
        plan = _effective_plan(account_id)
        if not plans.feature(plan, "members"):
            raise HTTPException(402, f"this account's plan ('{plan}') does not include team "
                                "members; the account owner can restore access for invited "
                                "members by upgrading to Team")
        seats = plans.limit(plan, "seats")
        if seats is None:
            return
        # Seat one belongs to the owner; the remaining seats go to the longest-standing members.
        active = [m["member_id"] for m in store.list_members(account_id)
                  if m["status"] == "active"]
        if member["member_id"] not in active[:max(seats - 1, 0)]:
            raise HTTPException(402, f"this account has more active members than plan '{plan}' "
                                f"seats ({seats} incl. owner); the owner must upgrade the plan "
                                "or disable another member to restore your access")

    def _account(authorization: str | None) -> str | None:
        """Resolve an account id from an API key (org root or member). None in dev mode."""
        p = _principal(authorization)
        return None if p is None else p["account_id"]

    def _require(authorization: str | None, permission: str) -> dict[str, Any] | None:
        """Resolve the principal and enforce a permission. Returns the principal (None in
        open mode). Raises 403 if the caller's role does not grant the permission."""
        p = _principal(authorization)
        role = None if p is None else p["role"]
        if not sec.role_can(role, permission):
            raise HTTPException(403, f"role '{role}' lacks permission '{permission}'")
        return p

    def _audit(principal: dict[str, Any] | None, action: str, resource_type: str | None = None,
               resource_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
        """Record a sensitive action in the tamper-evident access log. No-op in open mode."""
        if principal is None:
            return
        store.append_audit(principal["account_id"], principal["actor"], principal.get("role"),
                           action, resource_type, resource_id, detail)

    def _auth(authorization: str | None, required_scope: str, stream_id: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        resolved = tokens.resolve(token)
        if resolved is None:
            raise HTTPException(401, "invalid token")
        tok_stream, scope = resolved
        if scope != required_scope:
            raise HTTPException(403, f"token scope '{scope}' cannot perform a '{required_scope}' action")
        if stream_id is not None and tok_stream != stream_id:
            raise HTTPException(403, "token does not match stream")
        return tok_stream

    @app.post("/v1/accounts")
    def create_account(body: CreateAccountIn, request: Request):
        ip = request.client.host if request.client else "unknown"
        if not app.state.signup_limiter.allow(ip):
            raise HTTPException(429, "too many signups, slow down")
        api_key, key_hash = sec.new_api_key()
        account_id = sec.new_account_id()
        store.create_account(account_id, key_hash, label=body.label)
        return {"account_id": account_id, "api_key": api_key,
                "note": "store this key now; it is shown only once"}

    @app.post("/v1/streams")
    def create_stream(body: CreateStreamIn, authorization: str | None = Header(default=None)):
        import uuid
        principal = _require(authorization, "stream.create")
        owner = None if principal is None else principal["account_id"]
        if owner is not None:
            plan = _effective_plan(owner)
            if plans.would_exceed(plan, "streams", store.count_streams(owner), 1):
                raise HTTPException(402, f"stream limit for plan '{plan}' reached; "
                                    "upgrade the plan or delete an unused stream")
        stream_id = str(uuid.uuid4())
        store.create_stream(stream_id, body.label, owner_account=owner)
        _audit(principal, "stream.create", "stream", stream_id, {"label": body.label})
        return {
            "stream_id": stream_id,
            "write_token": tokens.mint(stream_id, tok.WRITE),
            "read_token": tokens.mint(stream_id, tok.READ),
            "share_token": tokens.mint(stream_id, tok.SHARE),
        }

    @app.get("/v1/streams")
    def list_streams(authorization: str | None = Header(default=None)):
        owner = _account(authorization)
        if owner is None:
            raise HTTPException(400, "account required to list streams")
        return {"streams": store.list_streams(owner)}

    @app.get("/v1/usage")
    def usage(authorization: str | None = Header(default=None)):
        """Current billing-period usage against the account's plan limits. The billing surface:
        a dashboard or a payment provider reads this to show consumption and gate upgrades."""
        account_id = _account(authorization)
        if account_id is None:
            raise HTTPException(400, "account required to read usage")
        plan = _effective_plan(account_id)
        return plans.describe(plan, store.get_usage(account_id))

    @app.put("/v1/account/plan")
    def set_plan(body: SetPlanIn, authorization: str | None = Header(default=None),
                 x_provenrail_billing_secret: str | None = Header(default=None)):
        """Change the account plan. This is the billing provider's endpoint, not the user's.

        `billing.manage` is owner-only, which sounds like enough and is not: it grants the
        owner permission to manage THEIR billing, and this route hands them the plan value
        directly. An owner on the free tier could PUT {"plan": "enterprise"} with their own
        API key and receive unlimited events, seats, SSO and exports without paying. Every
        paid limit in the product was one request away from being free.

        An upgrade therefore requires the billing secret, which only the payment provider's
        webhook holds. Downgrades stay self-service, because nobody defrauds anyone by asking
        for less, and locking a user into a plan they are trying to leave is its own problem.
        """
        principal = _require(authorization, "billing.manage")
        if body.plan not in plans.PLANS:
            raise HTTPException(422, f"unknown plan '{body.plan}'; choose one of "
                                f"{sorted(plans.PLANS)}")
        account_id = None if principal is None else principal["account_id"]
        if account_id is None:
            raise HTTPException(400, "account required")
        current_plan = store.account_plan(account_id) or plans.DEFAULT_PLAN
        if plans.rank(body.plan) > plans.rank(current_plan):
            expected = app.state.billing_secret
            if not expected or not secrets.compare_digest(
                    str(x_provenrail_billing_secret or ""), str(expected)):
                raise HTTPException(
                    402, "an upgrade is applied by the billing provider after payment, not by "
                         "this API. Use the checkout link; a downgrade is self-service.")
        store.set_account_plan(account_id, body.plan)
        _audit(principal, "billing.set_plan", "account", account_id, {"plan": body.plan})
        return {"account_id": account_id, "plan": body.plan,
                "limits": plans.plan_for(body.plan)}

    @app.post("/v1/ingest")
    def ingest(body: IngestIn, authorization: str | None = Header(default=None)):
        import json as _json
        caps = app.state.caps
        if not body.records:
            raise HTTPException(400, "no records")
        if len(body.records) > caps["max_batch"]:
            raise HTTPException(413, f"batch too large (max {caps['max_batch']})")
        stream_id = body.records[0].get("stream_id")
        if not stream_id or not isinstance(stream_id, str):
            # Without a concrete stream_id, _auth cannot bind the write token to its stream.
            # Reject before auth so a token is never accepted against an unspecified target.
            raise HTTPException(400, "first record missing stream_id")
        _auth(authorization, tok.WRITE, stream_id)
        if not app.state.ingest_limiter.allow(stream_id):
            raise HTTPException(429, "ingest rate limit exceeded for this stream")
        if not store.stream_exists(stream_id):
            raise HTTPException(404, "unknown stream")
        if store.count_records(stream_id) + len(body.records) > caps["max_records_per_stream"]:
            raise HTTPException(429, "stream record cap reached")
        # Plan quota (hosted billing control, not a security control): a per-account monthly
        # event budget. Open/dev streams (no owner account) are unmetered.
        owner = store.stream_owner(stream_id)
        if owner is not None:
            used = store.get_usage(owner)["events"]
            plan = _effective_plan(owner)
            if plans.would_exceed(plan, "events", used, len(body.records)):
                raise HTTPException(402, f"monthly event quota for plan '{plan}' reached; "
                                    "upgrade the plan to continue ingesting")
        for rec in body.records:
            if rec.get("stream_id") != stream_id:
                raise HTTPException(400, "all records in a batch must share one stream_id")
            if not isinstance(rec.get("record_hash"), str) or not isinstance(rec.get("seq"), int):
                raise HTTPException(422, "record missing required fields (record_hash:str, seq:int)")
            if len(_json.dumps(rec, separators=(",", ":")).encode("utf-8")) > caps["max_record_bytes"]:
                raise HTTPException(413, f"record too large (max {caps['max_record_bytes']} bytes)")
        try:
            receipts = [store.append_record(stream_id, rec) for rec in body.records]
        except storage_mod.SeqConflict as exc:
            # 409, not 400: the request was well formed, it just conflicts with what is
            # already recorded. Nothing in this batch was stored.
            raise HTTPException(409, str(exc)) from None
        except CanonicalError as exc:
            # A record that cannot be canonicalized can never be hashed, so it can never be
            # verified, and storing it would put a permanently unverifiable entry into an
            # append-only chain. The two ways in are a float and an integer outside the
            # JS-safe range, both of which a real client produces by accident (a token count
            # from a buggy provider SDK, a nanosecond timestamp). It reached the caller as a
            # 500, which reads as "our fault, retry" for a record that will never be accepted.
            raise HTTPException(422, f"record cannot be canonicalized, so it could never be "
                                     f"verified: {exc}") from None
        if owner is not None:
            store.bump_usage(owner, events=len(receipts))
        # Instant behavioural alerting: if the agent just tried something the policy blocked,
        # the operator hears about it now, not at the next anchor. Off the request path.
        _alert_on_policy_denials(stream_id, body.records)
        return {"accepted": len(receipts), "receipts": receipts}

    @app.post("/v1/streams/{stream_id}/anchor")
    def do_anchor(stream_id: str = Path(...), authorization: str | None = Header(default=None)):
        _auth(authorization, tok.READ, stream_id)
        if not app.state.anchor_limiter.allow(stream_id):
            raise HTTPException(429, "anchor rate limit exceeded for this stream")
        owner = store.stream_owner(stream_id)
        if owner is not None:
            plan = _effective_plan(owner)
            if plans.would_exceed(plan, "anchors", store.get_usage(owner)["anchors"], 1):
                raise HTTPException(402, f"monthly anchor quota for plan '{plan}' reached; "
                                    "upgrade the plan to continue anchoring")
        try:
            result = app.state.scheduler.anchor_stream(stream_id)
        except ValueError as e:
            raise HTTPException(400, "nothing to anchor") from e
        if owner is not None:
            store.bump_usage(owner, anchors=1)
        return result

    # ---- the anchor-only trust service ---------------------------------------------------
    # A customer runs their own sink under the AGPL, keeps every record, and sends only the root
    # of the hash tree over those records. We timestamp it, keep an append-only history of it,
    # and will attest to it for a stranger. That independence is the thing a self-hoster cannot
    # manufacture for themselves, and it is sold without ever receiving their data.

    @app.post("/v1/anchors")
    def anchor_root(body: AnchorRootIn, authorization: str | None = Header(default=None)):
        from dataclasses import asdict

        from ..chain import _utc_now_iso

        principal = _require(authorization, "stream.anchor")
        stream_id = (body.stream_id or "").strip()
        if not stream_id or len(stream_id) > 200:
            raise HTTPException(422, "stream_id must be a label of 1 to 200 characters")
        if body.covers_up_to < 1:
            raise HTTPException(422, "covers_up_to is how many records the root spans, so it "
                                     "must be at least 1")
        if not app.state.anchor_limiter.allow(stream_id):
            raise HTTPException(429, "anchor rate limit exceeded for this stream")
        try:
            root = anchor_mod._checked_root(body.merkle_root)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None

        account_id = None if principal is None else principal["account_id"]

        # Everything that can refuse this request runs before the timestamp is minted. A 409 used
        # to cost a live TSA round-trip and a rate-limit token at the TSA, so a client retrying a
        # conflicting anchor in a loop burned a shared external resource to be told no.
        existing = store.newest_external_anchor(account_id or "open", stream_id)
        if existing is not None:
            if body.covers_up_to < existing["covers_up_to"]:
                raise HTTPException(409, storage_mod.coverage_went_backwards_message(
                    existing["covers_up_to"], body.covers_up_to))
            if body.covers_up_to == existing["covers_up_to"]:
                if existing["merkle_root"] != root:
                    raise HTTPException(409, storage_mod.two_histories_message(body.covers_up_to))
                # Same account, same stream, same coverage, same root: this is a retry, not a new
                # anchor. Return the one that already exists so a client with retry logic does not
                # accumulate a row per attempt, and so the anchor id it was given stays valid.
                return existing

        if account_id is not None:
            plan = _effective_plan(account_id)
            if plans.would_exceed(plan, "anchors", store.get_usage(account_id)["anchors"], 1):
                raise HTTPException(402, f"monthly anchor quota for plan '{plan}' reached; "
                                    "upgrade the plan to continue anchoring")
            backend = (app.state.scheduler.anchor if plans.feature(plan, "trusted_time")
                       else app.state.scheduler.local_anchor)
        else:
            backend = app.state.scheduler.local_anchor
        receipt = backend.anchor_root(root)   # network round-trip to the TSA, no lock held
        try:
            stored = store.append_external_anchor(
                anchor_id=sec.new_anchor_id(),
                account_id=account_id or "open",
                stream_id=stream_id,
                merkle_root=root,
                covers_up_to=body.covers_up_to,
                receipt=asdict(receipt),
                created_at=_utc_now_iso(),
            )
        except storage_mod.DuplicateAnchor as e:
            # Two identical requests raced past the pre-check; the loser answers with the winner.
            return store.get_external_anchor(e.anchor_id)
        except storage_mod.CoverageWentBackwards as e:
            # 409, not 400: the request is well formed, it conflicts with history. The receipt
            # minted above is simply discarded; nothing was recorded.
            raise HTTPException(409, str(e)) from None
        if account_id is not None:
            store.bump_usage(account_id, anchors=1)
        _audit(principal, "anchor.external", "stream", stream_id,
               {"covers_up_to": body.covers_up_to, "anchor_id": stored["anchor_id"]})
        return stored

    @app.get("/v1/anchors/{anchor_id}")
    def get_anchor(anchor_id: str = Path(...)):
        """Public on purpose. The customer hands an auditor an anchor id, and the auditor must be
        able to check it without an account, without our permission, and without asking the
        customer again. There is nothing here to protect: a root, a time, and a signature."""
        found = store.get_external_anchor(anchor_id)
        if found is None:
            raise HTTPException(404, "no such anchor")
        return found

    @app.get("/v1/anchors")
    def list_anchors(stream_id: str | None = None,
                     authorization: str | None = Header(default=None)):
        principal = _require(authorization, "stream.read")
        account_id = None if principal is None else principal["account_id"]
        return {"anchors": store.list_external_anchors(account_id or "open", stream_id)}

    @app.get("/v1/streams/{stream_id}/export")
    def export(stream_id: str = Path(...), authorization: str | None = Header(default=None)):
        _auth(authorization, tok.READ, stream_id)
        if not app.state.export_limiter.allow(stream_id):
            raise HTTPException(429, "export rate limit exceeded for this stream")
        if not store.stream_exists(stream_id):
            raise HTTPException(404, "unknown stream")
        return _bundle(store, stream_id)

    @app.get("/share/{share_token}", response_class=HTMLResponse)
    def share(share_token: str):
        resolved = tokens.resolve(share_token)
        if resolved is None or resolved[1] != tok.SHARE:
            raise HTTPException(404, "not found")
        stream_id = resolved[0]
        # Shareable proof links are a Builder+ feature. If the owner is on a plan without it
        # (or downgraded), the link stops resolving rather than silently serving.
        owner = store.stream_owner(stream_id)
        if owner is not None and not plans.feature(_effective_plan(owner), "proof_links"):
            raise HTTPException(402, "shareable proof links require the Builder plan or higher")
        if not app.state.share_limiter.allow(stream_id):
            raise HTTPException(429, "this proof page is being requested too often, retry shortly")
        from ..verifier.verify import verify_bundle
        bundle = _bundle(store, stream_id)
        report = verify_bundle(bundle, tlog_log_key=app.state.scheduler.tlog_log_key.public_key_hex(),
                               witness_pubkeys=_witness_pubkeys())
        return HTMLResponse(_render_proof(stream_id, bundle["records"], bundle["anchors"],
                                          report, share_token))

    def _owned(authorization: str | None, stream_id: str) -> dict[str, Any]:
        """Resolve the owning account and confirm it owns this stream. Open mode skips the
        ownership check (no accounts exist). Raises 404 if the stream is unknown."""
        acct = _account(authorization)  # None in open mode, else a verified account id
        st = store.get_stream(stream_id)
        if st is None:
            raise HTTPException(404, "unknown stream")
        if app.state.require_account and st.get("owner_account") != acct:
            raise HTTPException(403, "stream does not belong to this account")
        return st

    @app.get("/v1/overview")
    def overview(authorization: str | None = Header(default=None)):
        from . import analytics
        acct = _account(authorization)  # 401 in key mode if missing/invalid; None in open mode
        streams = store.list_streams(acct)
        out = []
        grand = {"sessions": 0, "events": 0, "model_calls": 0, "tool_calls": 0,
                 "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "unpriced_calls": 0,
                 "open_sessions": 0}
        for s in streams:
            records = store.get_records(s["stream_id"])
            summ = analytics.summarize(records)
            verdict = (_verdict(_bundle(store, s["stream_id"]))
                       if records else {"state": "empty", "ok": True, "fails": 0, "warns": 0,
                                        "anchors": 0, "headline": "No records"})
            out.append({**s, "totals": summ["totals"], "verdict": verdict})
            for k in grand:
                grand[k] = round(grand[k] + summ["totals"].get(k, 0), 6)
        return {"open_mode": not app.state.require_account, "account": acct,
                "streams": out, "totals": grand}

    @app.post("/v1/approvals")
    def create_approval(body: ApprovalIn, request: Request,
                        authorization: str | None = Header(default=None)):
        """A headless agent asks a human to approve one action, and waits.

        Authenticated with the agent's own WRITE token, because the agent already holds it and
        because a request can only ever be opened against its own stream. Opening a request
        grants nothing: the decision needs one of the two link tokens, which are returned here
        and never stored in the clear.
        """
        _auth(authorization, tok.WRITE, body.stream_id)
        if not app.state.ingest_limiter.allow(body.stream_id):
            raise HTTPException(429, "approval rate limit exceeded for this stream")
        if not store.stream_exists(body.stream_id):
            raise HTTPException(404, "unknown stream")
        req = app.state.approvals.create(
            body.stream_id, session_id=body.session_id,
            account_id=store.stream_owner(body.stream_id), rule=body.rule,
            event_type=body.event_type, target=body.target, reason=body.reason,
            ttl_seconds=body.ttl_seconds)
        base = str(request.base_url).rstrip("/")
        out = {k: v for k, v in req.items() if k not in ("approve_token", "deny_token")}
        out["approve_url"] = f"{base}/approve/{req['approve_token']}"
        out["deny_url"] = f"{base}/deny/{req['deny_token']}"
        # The notification carries the two links, so whoever is on call can answer from the
        # channel they already watch without an account here.
        _alert_approval_requested(body.stream_id, out)
        return out

    @app.get("/v1/approvals/{request_id}")
    def get_approval(request_id: str = Path(...),
                     authorization: str | None = Header(default=None)):
        """The waiting agent polls this. Fails closed: past its deadline it reads `expired`."""
        req = app.state.approvals.get(request_id)
        if req is None:
            raise HTTPException(404, "unknown approval request")
        _auth(authorization, tok.WRITE, req["stream_id"])
        return req

    @app.get("/v1/approvals")
    def list_approvals(authorization: str | None = Header(default=None)):
        acct = _account(authorization)
        return {"pending": app.state.approvals.list_pending(acct)}

    # GET reads, POST decides. A mail gateway, a Slack unfurler or an antivirus scanner will
    # GET every URL in a notification before a human sees it, so a GET that approved would be
    # answered by a robot. These two routes are deliberately side-effect free.
    @app.get("/approve/{token}", response_class=HTMLResponse)
    def approve_review(token: str = Path(...)):
        return _review_page(token, approvals_mod.APPROVED)

    @app.get("/deny/{token}", response_class=HTMLResponse)
    def deny_review(token: str = Path(...)):
        return _review_page(token, approvals_mod.DENIED)

    @app.post("/approve/{token}", response_class=HTMLResponse)
    def approve_submit(token: str = Path(...)):
        return _decision_page(token, approvals_mod.APPROVED)

    @app.post("/deny/{token}", response_class=HTMLResponse)
    def deny_submit(token: str = Path(...)):
        return _decision_page(token, approvals_mod.DENIED)

    def _humanize_deadline(stamp: str) -> str:
        """"Expires in 54 minutes", not an ISO 8601 timestamp.

        The reader is deciding on a phone at an awkward hour. "2026-08-04T18:47:53.745637Z"
        does not tell them how long they have; a duration does, and how long they have is the
        only reason the field is on the page.
        """
        from datetime import UTC, datetime
        try:
            when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return stamp
        seconds = (when - datetime.now(UTC)).total_seconds()
        if seconds <= 0:
            return "expired"
        if seconds < 90:
            return f"in {int(seconds)} seconds"
        if seconds < 5400:
            return f"in {round(seconds / 60)} minutes"
        return f"in {round(seconds / 3600, 1)} hours"

    def _detail_rows(req: dict[str, Any], keys: tuple[str, ...]) -> str:
        labels = {"rule": "Policy rule", "event_type": "Action type", "target": "Target",
                  "status": "Status", "decided_at": "Decided", "expires_at": "Expires",
                  "session_id": "Session"}
        values = {"expires_at": _humanize_deadline(str(req.get("expires_at") or ""))}
        return "".join(
            f"<tr><th>{html.escape(labels.get(k, k))}</th>"
            f"<td>{html.escape(str(values.get(k, req.get(k)) or ''))}</td></tr>"
            for k in keys if req.get(k))

    def _review_page(token: str, decision: str) -> HTMLResponse:
        """What the human actually reads before choosing. Nothing here changes state.

        The action being requested is the headline, because on a phone at an awkward hour the
        question is "what am I being asked to allow", not "what product is this".
        """
        req = app.state.approvals.peek_by_token(token, decision)
        if req is None:
            return HTMLResponse(app.state.approvals.decision_page("Link not recognised", """<main>
  <h1 class="no">Link not recognised</h1>
  <p>This approval link is not one this server issued, or the request behind it has been
  rotated away. Nothing was changed.</p></main>"""), status_code=404)
        if req.get("status") != approvals_mod.PENDING:
            status = str(req.get("status"))
            return HTMLResponse(app.state.approvals.decision_page(f"Already {status}", f"""<main>
  <h1 class="{'ok' if status == approvals_mod.APPROVED else 'no'}">Already {html.escape(status)}</h1>
  <p>This request was {html.escape(status)} and cannot be answered again. Nothing was changed
  by opening this link.</p>
  <table>{_detail_rows(req, ("target", "rule", "decided_at"))}</table></main>"""))
        wants_approval = decision == approvals_mod.APPROVED
        reason = str(req.get("reason") or "An agent is waiting for your decision.")
        target = str(req.get("target") or "")
        verb = "Allow this action?" if wants_approval else "Block this action?"
        # Both answers on one page, when the page is the approve link. A reviewer who reads the
        # target and decides it is wrong should be able to say so here. Sending them back to a
        # Slack thread to find the other link is what makes "approve" the path of least
        # resistance under time pressure, which is the opposite of what the gate is for. The
        # deny token is derived from the approve token one way, so this hands out no capability
        # the reader did not already hold; the deny page cannot offer the reverse.
        deny_form = ""
        if wants_approval:
            counterpart = approvals_mod.deny_token_for(token)
            deny_form = (f'<form method="post" action="/deny/{html.escape(counterpart)}" '
                         f'class="decide alt"><button type="submit" class="stop">Deny</button>'
                         f'</form>')
        body = f"""<main>
  <h1>{html.escape(verb)}</h1>
  <p class="lede">{html.escape(reason)}</p>
  {f'<p class="target">{html.escape(target)}</p>' if target else ''}
  <form method="post" class="decide">
    <button type="submit" class="{'go' if wants_approval else 'stop'}">
      {'Approve' if wants_approval else 'Deny'}</button>
  </form>
  {deny_form}
  <table>{_detail_rows(req, ("rule", "event_type", "session_id", "expires_at"))}</table>
  <p class="fine">An agent is paused waiting for this, and nothing has been decided yet.
  Opening this page changes nothing; only a button above does, and your decision is recorded
  once. If you did not expect this, close the page. The request then expires on its own and
  the action stays blocked.</p>
</main>"""
        return HTMLResponse(app.state.approvals.decision_page(verb, body))

    def _decision_page(token: str, decision: str) -> HTMLResponse:
        """The outcome, rendered only after a POST from the review page's button."""
        result = app.state.approvals.decide_by_token(token, decision)
        req = result.get("request") or {}
        approved = (req.get("status") == approvals_mod.APPROVED)
        if result["ok"]:
            headline = "Approved" if approved else "Denied"
            note = ("The agent has been released to take this action. The decision is now part "
                    "of its signed record." if approved else
                    "The agent has been told no. The refusal is part of its signed record.")
        else:
            headline = "No change"
            note = f"This link did not decide anything: {result['reason']}."
        body = f"""<main>
  <h1 class="{'ok' if approved else 'no'}">{html.escape(headline)}</h1>
  <p class="lede">{html.escape(note)}</p>
  <table>{_detail_rows(req, ("target", "rule", "event_type", "status", "decided_at"))}</table>
  <p class="fine">This link works once, so reopening it will not change the answer. The agent
  writes the outcome into its own hash-chained, signed record. This server never holds the
  agent's signing key, so it cannot forge an approval, though an operator who does not trust
  their sink should run one they control.</p>
</main>"""
        return HTMLResponse(app.state.approvals.decision_page(headline, body))

    @app.get("/v1/spend")
    def spend(group_by: str = "agent", since: str | None = None, until: str | None = None,
              format: str = "json", authorization: str | None = Header(default=None)):
        """Estimated spend across the account, grouped by agent / project / team / model / day.

        The grouping dimensions come from the operator's own session metadata, which is inside
        the signed record, so a finance rollup is derived from the same evidence as everything
        else rather than from a side table someone could edit independently.
        """
        from . import finance

        acct = _account(authorization)
        if group_by not in finance.DIMENSIONS:
            raise HTTPException(400, f"group_by must be one of {list(finance.DIMENSIONS)}")
        for label, value in (("since", since), ("until", until)):
            if value and not _DATE_RE.match(value):
                raise HTTPException(400, f"{label} must be a UTC date as YYYY-MM-DD")
        streams = [(s["stream_id"], store.get_records(s["stream_id"]))
                   for s in store.list_streams(acct)]
        result = finance.rollup(streams, group_by=group_by, since=since, until=until)
        if format == "csv":
            return PlainTextResponse(
                finance.to_csv(result), media_type="text/csv",
                headers={"Content-Disposition":
                         f'attachment; filename="provenrail-spend-by-{group_by}.csv"'})
        return result

    @app.get("/v1/streams/{stream_id}/summary")
    def stream_summary(stream_id: str = Path(...), authorization: str | None = Header(default=None)):
        from . import analytics
        st = _owned(authorization, stream_id)
        records = store.get_records(stream_id)
        summ = analytics.summarize(records)
        verdict = (_verdict(_bundle(store, stream_id))
                   if records else {"state": "empty", "ok": True, "fails": 0, "warns": 0,
                                    "anchors": 0, "headline": "No records"})
        return {"stream": st, "totals": summ["totals"], "sessions": summ["sessions"],
                "verdict": verdict}

    @app.get("/v1/streams/{stream_id}/sessions/{session_id}")
    def session_detail(stream_id: str = Path(...), session_id: str = Path(...),
                       authorization: str | None = Header(default=None)):
        from . import analytics
        _owned(authorization, stream_id)
        records = store.get_records(stream_id)
        tl = analytics.session_timeline(records, session_id)
        if tl["summary"] is None:
            raise HTTPException(404, "unknown session")
        # The sibling sessions, so the replay scrubber can offer "compare with the run that
        # worked" without a second round trip. Ids and start times only: the full timeline of
        # a comparison run is fetched on demand, and only if the reviewer asks for it.
        tl["sessions"] = [{"session_id": s["session_id"], "started_at": s["started_at"],
                           "outcome": s.get("outcome"), "events": s.get("events")}
                          for s in analytics.summarize(records)["sessions"]]
        return tl

    @app.get("/v1/streams/{stream_id}/receipts")
    def stream_receipts(stream_id: str = Path(...), after_seq: int = Query(-1),
                        limit: int = Query(500, ge=1, le=1000),
                        authorization: str | None = Header(default=None)):
        """The receipt-chain links after `after_seq`, so a writer can close a gap another
        writer opened instead of guessing.

        A client holds the head it was last issued and expects the next receipt to link to it.
        That only holds while it is the sole writer. Two agents recording into one stream, which
        is the ordinary shape of a project with more than one agent, interleave, and the second
        receipt legitimately links to something the first client never saw. Refusing to look is
        how a normal setup ends up reporting tampering on every single record.

        Link material only: recv_seq and the two hashes, never a record body. A write token is
        enough, because the holder can already append to this stream; what it must not gain is a
        way to read what other writers put in it.
        """
        _auth(authorization, tok.WRITE, stream_id)
        if not store.stream_exists(stream_id):
            raise HTTPException(404, "unknown stream")
        return {"stream_id": stream_id,
                "receipts": store.receipts_after(stream_id, after_seq, limit)}

    @app.get("/v1/streams/{stream_id}/bundle")
    def account_bundle(stream_id: str = Path(...), authorization: str | None = Header(default=None)):
        """Account-authenticated export, so the operator can pull a verifiable bundle from the
        dashboard with their account key instead of a per-stream read token."""
        principal = _require(authorization, "stream.export")
        _owned(authorization, stream_id)
        _audit(principal, "stream.export", "stream", stream_id)
        return _bundle(store, stream_id)

    @app.post("/v1/webhooks")
    def create_webhook(body: CreateWebhookIn, authorization: str | None = Header(default=None)):
        import secrets

        from .alerts import EVENTS
        principal = _require(authorization, "webhook.manage")
        acct = _account(authorization)
        url = (body.url or "").strip()
        from .security import valid_webhook_url
        ok_url, reason = valid_webhook_url(url)
        if not ok_url:
            raise HTTPException(422, reason)
        events = body.events or ["*"]
        if events != ["*"]:
            bad = [e for e in events if e not in EVENTS]
            if bad:
                raise HTTPException(422, f"unknown event(s): {bad}; valid: {list(EVENTS)}")
        events_str = "*" if events == ["*"] else ",".join(events)
        webhook_id = "wh_" + secrets.token_urlsafe(12)
        secret = "whsec_" + secrets.token_urlsafe(24)
        store.create_webhook(webhook_id, acct, url, secret, events_str)
        _audit(principal, "webhook.create", "webhook", webhook_id, {"url": url})
        return {"webhook_id": webhook_id, "url": url, "events": events_str, "secret": secret,
                "note": "store this secret now; alert deliveries are HMAC-signed with it"}

    @app.get("/v1/webhooks")
    def list_webhooks(authorization: str | None = Header(default=None)):
        _require(authorization, "webhook.manage")
        acct = _account(authorization)
        return {"webhooks": store.list_webhooks(acct)}

    @app.delete("/v1/webhooks/{webhook_id}")
    def delete_webhook(webhook_id: str = Path(...), authorization: str | None = Header(default=None)):
        principal = _require(authorization, "webhook.manage")
        acct = _account(authorization)
        if not store.delete_webhook(webhook_id, acct):
            raise HTTPException(404, "unknown webhook")
        _audit(principal, "webhook.delete", "webhook", webhook_id)
        return {"deleted": webhook_id}

    @app.post("/v1/streams/{stream_id}/revoke")
    def revoke_stream_tokens(stream_id: str = Path(...),
                             authorization: str | None = Header(default=None)):
        """Revoke all tokens for a stream, for example when an agent's write token leaks.
        Append-only: records already captured stay immutable and verifiable; only the ability
        to authenticate with the old tokens is killed. Mint fresh tokens with a new stream."""
        principal = _require(authorization, "stream.revoke")
        _owned(authorization, stream_id)
        n = tokens.revoke_stream(stream_id)
        _audit(principal, "stream.revoke", "stream", stream_id, {"revoked": n})
        return {"stream_id": stream_id, "revoked": n}

    @app.get("/v1/streams/{stream_id}/export.ndjson")
    def export_ndjson(stream_id: str = Path(...), authorization: str | None = Header(default=None)):
        """SIEM-ingestible newline-delimited JSON: one flattened record per line, with the
        hashes that tie each line back to the verifiable bundle. Account-authenticated."""
        from .siem import bundle_to_ndjson
        principal = _require(authorization, "stream.export")
        _owned(authorization, stream_id)
        _gate_feature(store.stream_owner(stream_id), "exports")
        _audit(principal, "stream.export_ndjson", "stream", stream_id)
        if not app.state.export_limiter.allow(stream_id):
            raise HTTPException(429, "export rate limit exceeded for this stream")
        body = bundle_to_ndjson(_bundle(store, stream_id))
        return Response(body, media_type="application/x-ndjson",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{stream_id[:8]}.ndjson"'})

    @app.get("/v1/streams/{stream_id}/evidence")
    def evidence_pack(stream_id: str = Path(...), regime: str = "generic",
                      authorization: str | None = Header(default=None)):
        """Account-authenticated one-click evidence pack: a self-contained, self-verifying ZIP
        (bundle + regime evidence report + verification guide + manifest) for an auditor."""
        from ..pack import build_pack
        principal = _require(authorization, "evidence.export")
        _owned(authorization, stream_id)
        _gate_feature(store.stream_owner(stream_id), "reports")
        if regime not in ("eu-ai-act", "hipaa", "generic"):
            raise HTTPException(422, "regime must be eu-ai-act, hipaa, or generic")
        if not app.state.export_limiter.allow(stream_id):
            raise HTTPException(429, "evidence pack rate limit exceeded for this stream")
        _audit(principal, "evidence.export", "stream", stream_id, {"regime": regime})
        data = build_pack(_bundle(store, stream_id), regime=regime)
        fname = f"provenrail-evidence-{stream_id[:8]}-{regime}.zip"
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    @app.get("/")
    def root():
        """Send anyone who opens the server's base URL to the dashboard. Without this a bare
        `pr serve` returns 404 at /, which reads as a broken server to a first-time self-hoster."""
        return RedirectResponse(url="/app", status_code=307)

    @app.get("/app", response_class=HTMLResponse)
    @app.get("/app/", response_class=HTMLResponse)
    def dashboard():
        from .dashboard import DASHBOARD_HTML
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page():
        from .verify_page import VERIFY_HTML
        return HTMLResponse(VERIFY_HTML)

    @app.get("/verify.js")
    def verify_js():
        """Serve the standalone JS verifier so the hosted page can verify fully client-side,
        trusting not even this server. Absent in a minimal install; the page falls back to
        the server-side /v1/verify endpoint."""
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[3] / "web" / "verify.js"
        if not path.is_file():
            raise HTTPException(404, "client verifier not bundled in this deployment")
        return Response(path.read_text(encoding="utf-8"),
                        media_type="text/javascript",
                        headers={"Cache-Control": "public, max-age=300"})

    @app.post("/v1/verify")
    def verify_endpoint(body: VerifyIn, request: Request):
        """Public, no-auth verification of a supplied bundle. Trusts nothing in the input:
        the verifier recomputes every value, so a hostile bundle can at worst be reported as
        tampered. Rate limited and size capped to bound abuse."""
        ip = request.client.host if request.client else "unknown"
        if not app.state.verify_limiter.allow(ip):
            raise HTTPException(429, "too many verifications, slow down")
        size = len(json.dumps(body.bundle, separators=(",", ":")).encode("utf-8"))
        if size > app.state.max_verify_bytes:
            raise HTTPException(413, "bundle too large to verify here; use the fr CLI")
        from ..verifier.verify import verify_bundle
        # A public, multi-tenant verifier cannot blindly trust one log key for every bundle.
        # If the bundle's checkpoint was issued by THIS deployment's transparency log (its
        # origin carries our prefix), hand the verifier our log key and witness keys so the
        # checkpoint signature and cosignatures are fully validated (green). For a bundle from
        # a log we do not host, we pass no key: the verifier then reports the checkpoint
        # signature as unvalidated (warn) rather than falsely failing a legitimate foreign
        # bundle. Trust in a foreign log is the caller's to pin, via the pr CLI and that log's
        # published key. Either way nothing in the bundle is trusted: every hash and proof is
        # recomputed, so a hostile bundle is at worst reported as tampered.
        our_key = None
        our_witnesses = None
        try:
            prefix = getattr(app.state.scheduler, "tlog_origin_prefix", "") or ""
            for a in body.bundle.get("anchors", []):
                note = (a.get("tlog_inclusion") or {}).get("checkpoint", "")
                origin = note.split("\n", 1)[0] if note else ""
                if origin and prefix and origin.startswith(prefix):
                    our_key = app.state.scheduler.tlog_log_key.public_key_hex()
                    our_witnesses = _witness_pubkeys()
                    break
        except Exception:
            our_key, our_witnesses = None, None
        rep = verify_bundle(body.bundle, pin=body.pin, disclosure_openings=body.openings,
                            tlog_log_key=our_key, witness_pubkeys=our_witnesses)
        return rep.to_dict()

    @app.get("/badge/{share_token}.svg")
    def badge(share_token: str):
        """Embeddable live integrity badge. Returns an SVG regardless of outcome (including a
        neutral badge for an unknown token) so an <img> embed never shows a broken image."""
        from .badges import render_badge
        resolved = tokens.resolve(share_token)
        headers = {"Cache-Control": "public, max-age=60", "Content-Type": "image/svg+xml"}
        if resolved is None or resolved[1] != tok.SHARE:
            return Response(render_badge("unknown"), headers=headers)
        stream_id = resolved[0]
        # Live badge is part of the Builder+ proof-links feature; neutral badge otherwise.
        owner = store.stream_owner(stream_id)
        if owner is not None and not plans.feature(_effective_plan(owner), "proof_links"):
            return Response(render_badge("unknown"), headers=headers)
        if not app.state.share_limiter.allow(stream_id):
            return Response(render_badge("unknown"), headers=headers)
        bundle = _bundle(store, stream_id)
        state = _verdict(bundle)["state"] if bundle["records"] else "empty"
        return Response(render_badge(state), headers=headers)

    @app.get("/v1/streams/{stream_a}/diff/{stream_b}")
    def diff_streams(stream_a: str = Path(...), stream_b: str = Path(...),
                     authorization: str | None = Header(default=None)):
        """Diff two runs with provable fidelity: both bundles are verified, then their
        meaningful steps are aligned. A difference is a real behavioral change, not a tampered
        log. Both streams must be owned by the caller."""
        from ..replay import diff_runs
        principal = _require(authorization, "stream.read")
        _owned(authorization, stream_a)
        _owned(authorization, stream_b)
        out = diff_runs(_bundle(store, stream_a), _bundle(store, stream_b))
        _audit(principal, "stream.diff", "stream", f"{stream_a},{stream_b}")
        return out

    # ---- members (RBAC) ----
    @app.post("/v1/members")
    def invite_member(body: InviteMemberIn, authorization: str | None = Header(default=None)):
        """Create a member of the org and mint their personal key (shown once). The actor may
        only grant roles at or below its own authority; only an owner may create an owner."""
        principal = _require(authorization, "member.manage")
        if principal is None:
            raise HTTPException(400, "member management requires account mode")
        if body.role not in sec.assignable_roles(principal["role"]):
            raise HTTPException(403, f"role '{principal['role']}' cannot grant '{body.role}'")
        # Multi-user is a Team+ feature. Free/Builder are single-user (owner only); Team caps the
        # seat count. Commercial control only: it never weakens the integrity guarantee.
        account_id = principal["account_id"]
        _gate_feature(account_id, "members")
        plan = _effective_plan(account_id)
        current_users = _seats_in_use(account_id)
        if plans.would_exceed(plan, "seats", current_users, 1):
            raise HTTPException(402, f"seat limit for plan '{plan}' reached "
                                f"({plans.limit(plan, 'seats')} members incl. owner); "
                                "upgrade for more seats")
        member_key, key_hash = sec.new_member_key()
        member_id = sec.new_member_id()
        try:
            store.create_member(member_id, principal["account_id"], key_hash, body.role,
                                body.label, body.email)
        except Exception as e:
            raise HTTPException(409, "a member with that email already exists") from e
        _audit(principal, "member.invite", "member", member_id,
               {"role": body.role, "email": body.email})
        return {"member_id": member_id, "role": body.role, "api_key": member_key,
                "note": "store this key now; it is shown only once"}

    @app.get("/v1/members")
    def list_members(authorization: str | None = Header(default=None)):
        principal = _require(authorization, "member.manage")
        if principal is None:
            return {"members": []}
        return {"members": store.list_members(principal["account_id"])}

    @app.patch("/v1/members/{member_id}")
    def update_member(member_id: str = Path(...), body: UpdateMemberIn = None,
                      authorization: str | None = Header(default=None)):
        principal = _require(authorization, "member.manage")
        if principal is None:
            raise HTTPException(400, "member management requires account mode")
        target = store.get_member(principal["account_id"], member_id)
        if target is None:
            raise HTTPException(404, "unknown member")
        # Only an owner may modify an owner-role member or promote someone to owner.
        if (target["role"] == sec.OWNER or body.role == sec.OWNER) and principal["role"] != sec.OWNER:
            raise HTTPException(403, "only an owner can manage owners")
        if body.role is not None:
            if body.role not in sec.ROLES:
                raise HTTPException(422, f"role must be one of {list(sec.ROLES)}")
            if body.role not in sec.assignable_roles(principal["role"]):
                raise HTTPException(403, f"role '{principal['role']}' cannot grant '{body.role}'")
            store.set_member_role(principal["account_id"], member_id, body.role)
        if body.status is not None:
            if body.status not in ("active", "disabled"):
                raise HTTPException(422, "status must be active or disabled")
            store.set_member_status(principal["account_id"], member_id, body.status)
        _audit(principal, "member.update", "member", member_id,
               {"role": body.role, "status": body.status})
        return {"member": store.get_member(principal["account_id"], member_id)}

    # ---- agent identity registry (KYA) ----
    @app.post("/v1/agents")
    def register_agent(body: RegisterAgentIn, authorization: str | None = Header(default=None)):
        """Bind an agent_id to a device public key. The verifier can then confirm records were
        signed by the registered key for that agent, not merely by some consistent key."""
        principal = _require(authorization, "agent.manage")
        acct = None if principal is None else principal["account_id"]
        if acct is None:
            raise HTTPException(400, "agent registration requires account mode")
        # Length alone let "z" * 64 register as a device key. It can never be one, and the
        # verifier that later tries to parse it has no good option left.
        if not re.fullmatch(r"[0-9a-f]{64}", body.pubkey or ""):
            raise HTTPException(422, "pubkey must be a 64-character lowercase hex Ed25519 key")
        store.register_agent_key(acct, body.agent_id, body.pubkey)
        _audit(principal, "agent.register", "agent", body.agent_id, {"pubkey": body.pubkey[:16]})
        return {"agent_id": body.agent_id, "pubkey": body.pubkey, "status": "active"}

    @app.post("/v1/agents/{agent_id}/rotate")
    def rotate_agent(agent_id: str = Path(...), body: RotateAgentIn = None,
                     authorization: str | None = Header(default=None)):
        principal = _require(authorization, "agent.manage")
        acct = None if principal is None else principal["account_id"]
        if acct is None:
            raise HTTPException(400, "agent rotation requires account mode")
        # Same hex check as registration: length alone let "z" * 64 through, and a key that can
        # never parse is not a key.
        if not body or not re.fullmatch(r"[0-9a-f]{64}", body.new_pubkey or ""):
            raise HTTPException(422, "new_pubkey must be a 64-character lowercase hex Ed25519 key")
        if not store.rotate_agent_key(acct, agent_id, body.old_pubkey, body.new_pubkey):
            # Answering 200 here told someone mid-incident that a key they believe is stolen had
            # been revoked, when it was still live and a second live key had just been added.
            raise HTTPException(404, "old_pubkey is not an active key for this agent; nothing "
                                     "was rotated and no new key was added")
        _audit(principal, "agent.rotate", "agent", agent_id)
        return {"agent_id": agent_id, "new_pubkey": body.new_pubkey, "rotated": True}

    @app.get("/v1/agents")
    def list_agents(authorization: str | None = Header(default=None)):
        principal = _require(authorization, "agent.manage")
        if principal is None:
            return {"agents": [], "registry_pubkey": app.state.registry_key.public_key_hex()}
        return {"agents": store.list_agent_keys(principal["account_id"]),
                "registry_pubkey": app.state.registry_key.public_key_hex()}

    # ---- OIDC single sign-on ----
    @app.put("/v1/sso/config")
    def set_sso_config(body: OidcConfigIn, authorization: str | None = Header(default=None)):
        """Configure the org's IdP. Owner only. The JWKS is pinned here (supplied out of band),
        so token validation needs no network call."""
        principal = _require(authorization, "owner.manage")
        if principal is None:
            raise HTTPException(400, "SSO config requires account mode")
        _gate_feature(principal["account_id"], "sso")
        if body.default_role not in sec.ROLES or body.default_role == sec.OWNER:
            raise HTTPException(422, "default_role must be admin, member, or viewer")
        store.set_oidc_config(principal["account_id"], body.issuer, body.audience,
                              json.dumps(body.jwks), body.default_role, body.email_domain)
        _audit(principal, "sso.configure", "oidc", principal["account_id"],
               {"issuer": body.issuer})
        return {"configured": True, "issuer": body.issuer, "default_role": body.default_role}

    @app.get("/v1/sso/config")
    def get_sso_config(authorization: str | None = Header(default=None)):
        principal = _require(authorization, "member.manage")
        if principal is None:
            return {"configured": False}
        cfg = store.get_oidc_config(principal["account_id"])
        if cfg is None:
            return {"configured": False}
        keys = len(json.loads(cfg["jwks"]).get("keys", []))
        return {"configured": True, "issuer": cfg["issuer"], "audience": cfg["audience"],
                "default_role": cfg["default_role"], "email_domain": cfg["email_domain"],
                "jwks_keys": keys}

    @app.post("/v1/sso/login")
    def sso_login(body: SsoLoginIn, request: Request):
        """Exchange a valid IdP ID token for an org member key. JIT-provisions the member on
        first login. Public: the signed ID token is the credential."""
        from datetime import UTC, datetime

        from . import sso
        ip = request.client.host if request.client else "unknown"
        if not app.state.signup_limiter.allow(ip):
            raise HTTPException(429, "too many SSO attempts, slow down")
        # Route to the org by the token's unverified iss/aud, then validate against its config.
        try:
            payload = sso._b64url_decode(body.id_token.split(".")[1])
            claims_unverified = json.loads(payload)
        except Exception as e:
            raise HTTPException(400, "malformed ID token") from e
        account_id = store.find_account_by_issuer(
            claims_unverified.get("iss", ""), _aud_str(claims_unverified.get("aud", "")))
        cfg = store.get_oidc_config(account_id) if account_id else None
        if cfg is None:
            raise HTTPException(404, "no SSO configuration matches this token")
        try:
            claims = sso.verify_id_token(
                body.id_token, jwks=json.loads(cfg["jwks"]), issuer=cfg["issuer"],
                audience=cfg["audience"], now=int(datetime.now(UTC).timestamp()))
        except sso.SSOError as e:
            raise HTTPException(401, f"SSO rejected: {e}") from e
        email = claims.get("email") or claims.get("sub")
        if cfg["email_domain"] and not str(email).endswith("@" + cfg["email_domain"]):
            raise HTTPException(403, "email domain is not permitted by this org's SSO policy")
        member_key, key_hash = sec.new_member_key()
        existing = store.find_member_by_email(account_id, email)
        if existing is not None:
            if existing["status"] != "active":
                raise HTTPException(403, "this member is disabled")
            store.set_member_key(account_id, existing["member_id"], key_hash)
            member_id, role = existing["member_id"], existing["role"]
        else:
            # A first-time SSO login provisions a seat, so it has to pass the same seat check
            # the invite path does. Without this, an org on a 10-seat plan grows without limit
            # just by having more staff log in with the IdP, which is both a billing hole and a
            # lie on the pricing card. Existing members are unaffected: they already hold a
            # seat, so they keep logging in even when the account is at its cap.
            plan = _effective_plan(account_id)
            current_users = _seats_in_use(account_id)
            if plans.would_exceed(plan, "seats", current_users, 1):
                raise HTTPException(402, f"seat limit for plan '{plan}' reached "
                                    f"({plans.limit(plan, 'seats')} members incl. owner); "
                                    "an administrator must free a seat or upgrade the plan "
                                    "before this user can sign in")
            member_id = sec.new_member_id()
            role = cfg["default_role"]
            store.create_member(member_id, account_id, key_hash, role, label=email, email=email)
        store.append_audit(account_id, member_id, role, "sso.login", "member", member_id,
                           {"email": email})
        return {"member_id": member_id, "role": role, "api_key": member_key,
                "note": "session key issued via SSO; store it for this session"}

    @app.get("/v1/audit-log")
    def audit_log(authorization: str | None = Header(default=None)):
        """The tamper-evident access log: who viewed, exported, revoked, or changed what. The
        log is itself hash-chained, so its integrity can be checked independently (audit of
        the audit). This is the access-control evidence HIPAA 164.312(b) expects."""
        principal = _require(authorization, "audit.read")
        if principal is None:
            return {"open_mode": True, "entries": [], "chain_ok": True}
        return {"entries": store.get_audit_log(principal["account_id"]),
                "chain_ok": store.verify_audit_chain(principal["account_id"])}

    @app.get("/v1/meta")
    def meta():
        from .. import __version__
        from .alerts import EVENTS
        # Was the literal "0.2.0" and had been since that release, so every sink reported a
        # version it was not running. This is the field you read to answer "which build is
        # this?" during an incident, which is precisely when a wrong answer costs the most.
        return {"open_mode": not app.state.require_account, "version": __version__,
                "alert_events": list(EVENTS),
                "tlog_pubkey": app.state.scheduler.tlog_log_key.public_key_hex(),
                "tlog_origin_prefix": app.state.scheduler.tlog_origin_prefix,
                "registry_pubkey": app.state.registry_key.public_key_hex()}

    # ---- public transparency-log endpoints (no auth, rate limited) ----
    # Per-account log shard. account_id is 'shared' in open/dev mode. These exist so an
    # external witness or monitor can fetch and audit the log independently of any bundle.
    def _origin(account_id: str) -> str:
        return f"{app.state.scheduler.tlog_origin_prefix}/{account_id}"

    @app.get("/v1/tlog/{account_id}/checkpoint")
    def tlog_checkpoint(account_id: str = Path(...), request: Request = None):
        if not app.state.tlog_limiter.allow(request.client.host if request and request.client else "unknown"):
            raise HTTPException(429, "transparency-log rate limit exceeded")
        origin = _origin(account_id)
        cp = store.get_latest_witnessed_checkpoint(origin) or store.get_latest_tlog_checkpoint(origin)
        if cp is None:
            raise HTTPException(404, "no checkpoint for this log")
        headers = {"X-Tree-Size": str(cp["tree_size"]),
                   "X-Witness-Count": str(cp["witnessed"]),
                   "X-Witnessed": "true" if cp["witnessed"] >= 1 else "false"}
        return Response(cp["signed_note"], media_type="text/plain; charset=utf-8", headers=headers)

    @app.get("/v1/tlog/{account_id}/inclusion/{leaf_index}")
    def tlog_inclusion(account_id: str = Path(...), leaf_index: int = Path(...),
                       request: Request = None):
        if not app.state.tlog_limiter.allow(request.client.host if request and request.client else "unknown"):
            raise HTTPException(429, "transparency-log rate limit exceeded")
        from .. import tlog as _t
        origin = _origin(account_id)
        cp = store.get_latest_tlog_checkpoint(origin)
        if cp is None or leaf_index < 0 or leaf_index >= cp["tree_size"]:
            raise HTTPException(404, "leaf index out of range")
        leaves = store.get_tlog_leaf_hashes(origin, 0, cp["tree_size"])
        return {"kind": "tlog_inclusion", "log_origin": origin, "leaf_index": leaf_index,
                "tree_size": cp["tree_size"],
                "proof_hashes": _t.make_inclusion_proof(leaf_index, leaves),
                "checkpoint": cp["signed_note"]}

    @app.get("/v1/tlog/{account_id}/consistency/{old_size}/{new_size}")
    def tlog_consistency(account_id: str = Path(...), old_size: int = Path(...),
                         new_size: int = Path(...), request: Request = None):
        if not app.state.tlog_limiter.allow(request.client.host if request and request.client else "unknown"):
            raise HTTPException(429, "transparency-log rate limit exceeded")
        from .. import tlog as _t
        if new_size - old_size > 1000:
            raise HTTPException(413, "consistency span too large (max 1000 checkpoints)")
        origin = _origin(account_id)
        cp = store.get_latest_tlog_checkpoint(origin)
        if cp is None or old_size < 0 or new_size > cp["tree_size"] or old_size > new_size:
            raise HTTPException(404, "size out of range")
        leaves = store.get_tlog_leaf_hashes(origin, 0, new_size)
        return {"old_size": old_size, "new_size": new_size,
                "proof_hashes": _t.make_consistency_proof(old_size, new_size, leaves)}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app


def _aud_str(aud: Any) -> str:
    """OIDC aud may be a string or a list; use the first entry to route to the org config."""
    return aud[0] if isinstance(aud, list) and aud else (aud if isinstance(aud, str) else "")


def _bundle(store: storage_mod.Storage, stream_id: str) -> dict[str, Any]:
    from .. import tlog
    records = store.get_records(stream_id)
    anchors = store.get_anchors(stream_id)
    bundle = {
        "format": "flightrecorder.bundle/1",
        "stream_id": stream_id,
        "server_head": store.head(stream_id),
        "records": records,
        "anchors": anchors,
    }
    # Attach transparency-log inclusion proofs against the latest published checkpoint, so an
    # offline verifier can confirm each anchor is in the witnessed append-only log.
    prefix = getattr(store, "tlog_origin_prefix", tlog.DEFAULT_ORIGIN_PREFIX)
    origin = store.origin_for_stream(stream_id, prefix)
    latest = store.get_latest_tlog_checkpoint(origin)
    if latest is not None and anchors:
        from .. import scitt
        tree_size = latest["tree_size"]
        leaf_hashes = store.get_tlog_leaf_hashes(origin, 0, tree_size)
        ts_key = store.get_or_create_signing_key("tlog_log_key_pem")
        bundle["tlog_schema_version"] = 1
        bundle["scitt_schema_version"] = 1
        for a in anchors:
            leaf = store.find_tlog_leaf(origin, stream_id, a["anchor_seq"])
            if leaf is None or leaf["leaf_index"] >= tree_size:
                continue
            a["tlog_inclusion"] = {
                "kind": "tlog_inclusion",
                "log_origin": origin,
                "leaf_index": leaf["leaf_index"],
                "tree_size": tree_size,
                "proof_hashes": tlog.make_inclusion_proof(leaf["leaf_index"], leaf_hashes),
                "checkpoint": latest["signed_note"],
            }
            # SCITT-aligned COSE receipt (draft-ietf-scitt-architecture profile): the same
            # tlog inclusion, re-expressed as a standards-format receipt any SCITT-aware
            # auditor tool can verify independently. SPEC section 18.
            a["scitt_receipt"] = scitt.build_receipt(
                ts_key, leaf["leaf_index"], leaf_hashes, subject=stream_id)
        proofs = []
        for cp in store.get_tlog_checkpoints(origin):
            if cp.get("consistency_proof"):
                proofs.append(json.loads(cp["consistency_proof"]))
        if proofs:
            bundle["tlog_consistency_proofs"] = proofs

    # Embed signed agent-identity (KYA) assertions for any device key in this bundle that is
    # registered, so an offline verifier with the registry public key can bind key to agent.
    reg_key = getattr(store, "registry_key", None)
    owner = store.stream_owner(stream_id)
    if reg_key is not None and owner is not None:
        from .. import registry as reg
        seen = set()
        assertions = []
        for r in records:
            pk = r["record"].get("pubkey")
            if not pk or pk in seen:
                continue
            seen.add(pk)
            row = store.find_agent_by_pubkey(owner, pk)
            if row is None:
                continue
            body = reg.assertion_body(owner, row["agent_id"], pk, row["status"],
                                      row["registered_at"], row["revoked_at"])
            assertions.append(reg.sign_assertion(body, reg_key))
        if assertions:
            bundle["agent_registry"] = assertions
    return bundle


_ACTION_LABEL = {
    "lifecycle.session_start": "Session started", "lifecycle.session_end": "Session sealed",
    "lifecycle.heartbeat": "Heartbeat", "model_call": "Model call", "tool_call": "Tool call",
    "mcp_call": "MCP call", "decision": "Decision", "data_access": "Data access",
    "human_oversight": "Human oversight", "policy.decision": "Policy decision",
}


def _proof_event_label(rec: dict) -> tuple[str, str]:
    """(label, extra css class) for one event on the public proof page.

    A blocked action is the strongest possible content for a page whose job is "do not take
    our word for it": it shows the guardrails were live, enforcement happened, and the
    evidence of it is inside the same signed chain being verified. So a denial is labelled
    and coloured, never rendered as an opaque type name."""
    at = rec.get("action_type", "")
    if at != "policy.decision":
        return _ACTION_LABEL.get(at, at), ""
    payload = rec.get("payload") or {}
    effect = str(payload.get("effect", "")).lower()
    target = str(payload.get("target") or payload.get("event_type") or "")
    if effect == "deny":
        return (f"Policy blocked: {target}" if target else "Policy blocked an action"), " ev-deny"
    return (f"Policy allowed: {target}" if target else "Policy decision"), ""


def _render_proof(stream_id: str, records: list[dict], anchors: list[dict], report,
                  share_token: str | None = None) -> str:
    client_records = [r["record"] for r in records]
    actions: dict[str, int] = {}
    for r in client_records:
        a = r.get("action_type", "unknown")
        actions[a] = actions.get(a, 0) + 1
    verified = bool(getattr(report, "ok", False))
    findings = getattr(report, "findings", [])
    warns = sum(1 for f in findings if f.severity == "warn")
    codes = {f.code for f in findings}
    # A clean verify with no independent third-party time anchor is real integrity, but a
    # weaker claim than a trusted timestamp. Show it amber, not green, so the distinction is
    # never oversold on the public page.
    weak_anchor = verified and ("local_anchor_only" in codes or "no_anchor" in codes)
    witnessed = verified and "tlog_inclusion_witnessed_ok" in codes
    witness_count = sum(1 for f in findings if f.code == "tlog_cosig_valid")
    has_proofs = verified and ("tlog_inclusion_unwitnessed" in codes or witnessed)
    rfc_times = [a["receipt"].get("gen_time") for a in anchors
                 if a.get("receipt", {}).get("kind") == "rfc3161"]
    trusted_time = html.escape(rfc_times[-1]) if rfc_times else None
    redacted_commits: set[str] = set()
    for r in client_records:
        for c in redaction.walk_commitments(r):
            redacted_commits.add(c)
    n_redacted = len(redacted_commits)
    pubkey = client_records[0].get("pubkey", "")[:16] if client_records else ""
    recv_ts = [r.get("recv_ts") for r in records if r.get("recv_ts")]
    window = f"{html.escape(min(recv_ts))} to {html.escape(max(recv_ts))}" if recv_ts else "n/a"

    def _item(r: dict) -> str:
        rec = r["record"]
        label, extra = _proof_event_label(rec)
        return (
            f'<li class="ev ev-{html.escape(rec.get("action_type","").split(".")[0])}{extra}">'
            f'<div class="ev-h"><span class="ev-t">{html.escape(label)}</span>'
            f'<time>{html.escape((rec.get("ts_utc","") or "")[11:23])}</time></div>'
            f'<code class="hash">{html.escape(rec.get("record_hash","")[:24])}</code></li>')

    items = "".join(_item(r) for r in records)
    chips = "".join(
        f'<span class="chip">{html.escape(_ACTION_LABEL.get(k,k))}: {v}</span>'
        for k, v in sorted(actions.items())
    )
    if not verified:
        badge = '<span class="badge bad">Tampering detected</span>'
    elif witnessed:
        plural = "party" if witness_count == 1 else "parties"
        badge = (f'<span class="badge ok">Integrity verified, witnessed by {witness_count} '
                 f'independent {plural}</span>')
    elif weak_anchor:
        badge = '<span class="badge amber">Integrity verified, no trusted timestamp</span>'
    else:
        badge = '<span class="badge ok">Integrity verified</span>'
    anchor_line = (f"Anchored to a trusted timestamp at {trusted_time}" if trusted_time
                   else "Anchored locally (no third-party time proof on this stream yet)")
    if witnessed:
        witness_line = (f"In the public transparency log, witnessed by {witness_count} "
                        f"independent {'party' if witness_count == 1 else 'parties'} "
                        f"(append-only, cannot be equivocated).")
    elif has_proofs:
        witness_line = ("In the public transparency log with append-only proofs, "
                        "not yet witnessed by an independent party.")
    else:
        witness_line = None

    privacy_block = ""
    if n_redacted:
        field_word = "field" if n_redacted == 1 else "fields"
        shield = ('<svg viewBox="0 0 24 24" width="17" height="17" fill="none" '
                  'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
                  'stroke-linejoin="round" aria-hidden="true">'
                  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>')
        privacy_block = (
            '<div class="card privacy">'
            f'<div class="ph">{shield}<b>{n_redacted} privacy-protected {field_word}</b></div>'
            'Sensitive values were committed to this record as a salted hash and never stored '
            'in cleartext on this server. The operator can disclose any one of them later by '
            'revealing the original value, which is checked against the committed hash, or erase '
            'it permanently by destroying the opening. Integrity holds either way.'
            '</div>'
        )

    badge_block = ""
    if share_token:
        tok_esc = html.escape(share_token)
        md = f"[![Provenrail](/badge/{tok_esc}.svg)](/share/{tok_esc})"
        badge_block = (
            '<div class="card verify">'
            '<b>Embed a live badge.</b> Drop this into a README or status page. It re-verifies '
            'on every load and turns amber or red if the record ever stops verifying.'
            f'<p style="margin:.6rem 0"><img src="/badge/{tok_esc}.svg" alt="Provenrail integrity badge" height="20"></p>'
            f'<code>{html.escape(md)}</code>'
            '</div>'
        )

    jsonld = json.dumps({
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": "AI agent activity proof",
        "description": "Tamper-evident, independently verifiable record of an AI agent's activity.",
        "identifier": stream_id,
    })

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent activity proof</title>
<meta name="description" content="A tamper-evident, independently verifiable record of what an AI agent did.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap" rel="stylesheet">
<script type="application/ld+json">{jsonld}</script>
<style>
:root{{color-scheme:light dark; --bg:#0a0b0e; --fg:#f3f5f7; --mut:#99a2af; --line:#20242c;
--card:#0f1115; --ok:#2ee6a6; --bad:#f06a5d; --amber:#f0b23a; --accent:#2ee6a6;
--mono:'DM Mono','Fira Code',ui-monospace,SFMono-Regular,Menlo,monospace}}
@media (prefers-color-scheme:light){{:root{{--bg:#fbfcfd;--fg:#0c0f14;--mut:#515b67;
--line:#e4e8ee;--card:#ffffff;--ok:#07a06a;--accent:#07a06a}}}}
*{{box-sizing:border-box}}
body{{font:16px/1.55 'DM Sans',system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);
color:var(--fg);padding:1.25rem;max-width:760px;margin-inline:auto}}
header{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:.25rem}}
h1{{font-size:1.35rem;margin:0;letter-spacing:-.01em}}
.badge{{font-size:.8rem;font-weight:700;padding:.28rem .6rem;border-radius:999px;color:#fff}}
.badge.ok{{background:var(--ok)}} .badge.bad{{background:var(--bad)}} .badge.amber{{background:var(--amber)}}
.sub{{color:var(--mut);margin:.25rem 0 1.1rem}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:1rem 1.1rem;margin-bottom:1rem}}
.meta{{display:grid;grid-template-columns:1fr;gap:.35rem;font-size:.92rem}}
.meta b{{color:var(--mut);font-weight:600;margin-right:.4rem}}
.chips{{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.6rem}}
.chip{{font-size:.78rem;background:color-mix(in srgb,var(--accent) 14%,transparent);
border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);color:var(--fg);
padding:.2rem .55rem;border-radius:999px}}
ol.timeline{{list-style:none;margin:0;padding:0}}
.ev{{padding:.6rem 0;border-bottom:1px solid var(--line)}}
.ev:last-child{{border-bottom:0}}
.ev-h{{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}}
.ev-t{{font-weight:600}} time{{color:var(--mut);font-variant-numeric:tabular-nums;font-size:.85rem}}
.ev-deny .ev-t{{color:var(--bad)}}
.hash{{color:var(--mut);font-size:.72rem;word-break:break-all}}
code{{font-family:var(--mono)}}
.verify{{font-size:.9rem}} .verify code{{display:block;background:var(--bg);border:1px solid var(--line);
padding:.55rem .7rem;border-radius:10px;margin:.4rem 0;overflow-x:auto}}
.fine{{color:var(--mut);font-size:.82rem;margin-top:1rem}}
.privacy{{font-size:.9rem;border-color:color-mix(in srgb,var(--accent) 30%,var(--line))}}
.privacy .ph{{display:flex;align-items:center;gap:.45rem;margin-bottom:.45rem;color:var(--accent)}}
.privacy .ph b{{color:var(--fg)}}
a{{color:var(--accent)}}
</style></head><body>
<header><h1>Agent activity proof</h1>{badge}</header>
<p class="sub">A tamper-evident, independently verifiable record of what an AI agent did.</p>

<div class="card">
  <div class="meta">
    <div><b>Stream</b><code>{html.escape(stream_id)}</code></div>
    <div><b>Agent key</b><code>{html.escape(pubkey)}...</code></div>
    <div><b>Window</b>{window}</div>
    <div><b>Records</b>{len(records)}</div>
    <div><b>Integrity</b>{'verified, ' + str(warns) + ' advisory note(s)' if verified else 'TAMPERING DETECTED'}</div>
    <div><b>Anchor</b>{anchor_line}</div>
    {f'<div><b>Witness</b>{html.escape(witness_line)}</div>' if witness_line else ''}
  </div>
  <div class="chips">{chips}</div>
</div>

<div class="card">
  <ol class="timeline">{items}</ol>
</div>
{privacy_block}
<div class="card verify">
  <b>Do not take our word for it.</b> Export the bundle and verify it yourself with the
  open-source tool, or drop it into the <a href="/verify">hosted verifier</a>. It trusts
  neither the agent nor this server.
  <code>pr verify bundle.json</code>
</div>
{badge_block}

<p class="fine">Integrity is guaranteed from the moment each record reached this off-box sink.
Completeness, that nothing was withheld before being recorded, is never claimed. This page is read-only.</p>
<a href="/" style="display:inline-flex;align-items:center;gap:.45rem;margin-top:1.4rem;color:var(--mut);font-size:.82rem;text-decoration:none">
  <svg width="18" height="18" viewBox="0 0 32 32" fill="none" aria-hidden="true">
    <rect x="2.5" y="2.5" width="27" height="27" rx="8" fill="none" stroke="var(--ok)" stroke-opacity=".5" stroke-width="1.5"/>
    <path d="M9 17l4.4 4.4L23 11" stroke="var(--ok)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="9" cy="17" r="1.9" fill="var(--ok)"/><circle cx="23" cy="11" r="1.9" fill="var(--ok)"/>
  </svg>
  Verified with <b style="color:var(--fg);font-weight:600">Provenrail</b>
</a>
</body></html>"""


# module-level app for `uvicorn provenrail.server.app:app`
app = create_app()


def run():
    import uvicorn
    uvicorn.run("provenrail.server.app:app", host="127.0.0.1", port=8000, reload=False)
