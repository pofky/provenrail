"""Standalone verifier. Trusts neither the agent nor the Provenrail server.

Given an exported bundle it independently recomputes every hash, signature, chain link,
Merkle anchor, and timestamp relationship, and reports exactly what it can and cannot
attest. It depends only on the public Ed25519 key embedded in the records and on public
anchor receipts, so an auditor can run it offline.

What a clean result attests:
  - the recorded client chain is internally consistent and signed by one device key
  - the server received those exact bytes, in a consistent order, with no deletion/insertion
  - records covered by an anchor existed no later than the anchor's trusted time
What it can NEVER attest: completeness (that nothing was withheld before being recorded).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

from .. import GENESIS_PREV_HASH
from ..anchor import merkle_root
from ..canonical import canonicalize, sha256_hex
from ..chain import (
    DATA_ACCESS,
    GENESIS,
    HEARTBEAT,
    HUMAN_OVERSIGHT,
    MCP_CALL,
    MODEL_CALL,
    SEAL,
    TOOL_CALL,
    verify_client_chain,
)
from ..keys import verify_signature

# NIST digest OIDs used in RFC 3161 message imprints
_DIGEST_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
}

# TSA gen_time is floored to whole seconds and client/server/TSA clocks skew slightly.
# Allow this much before flagging a time as implausibly late.
ANCHOR_SKEW_TOLERANCE_S = 5.0


def _parse_ts(s: str):
    from datetime import datetime
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None


def _seconds_after(a: str, b: str) -> float:
    """How many seconds a is after b. Negative/0 if a <= b. inf if unparseable."""
    ta, tb = _parse_ts(a), _parse_ts(b)
    if ta is None or tb is None:
        return float("inf")
    return (ta - tb).total_seconds()


# Failure codes that mean "a trust anchor YOU, the verifier, supplied does not match this
# bundle" rather than "the recorded data was altered". They are cryptographically unambiguous:
# each is a key-IDENTITY mismatch (the key id embedded in the proof differs from the key the
# caller passed), so the only explanations are (a) you pasted the wrong/stale key, or (b) this
# proof comes from a different log/witness than the one you trust. Neither is record tampering,
# whose own hash chain, signatures, and inclusion proof are checked independently. Reporting
# these as "TAMPERING DETECTED" is a false accusation that destroys user trust, so the headline
# treats a report whose ONLY failures are in this set as NOT CONFIRMED, not tampered.
ATTESTATION_FAIL_CODES = frozenset({
    "tlog_log_key_id_mismatch",     # --tlog-pubkey is for a different log key
    "tlog_cosig_key_id_mismatch",   # a --witness-pubkeys key does not match that witness
    "scitt_key_mismatch",           # --tlog-pubkey does not match the SCITT receipt's key id
})

# Failures that mean "this input is not a Provenrail bundle at all" (wrong file, wrong JSON
# shape) rather than "a real bundle that failed verification". Pointing `pr verify` at the
# wrong file is a common slip; calling that "TAMPERING DETECTED" is both wrong and alarming.
FORMAT_ERROR_CODES = frozenset({
    "not_a_bundle",   # the JSON is not even an object (a list, string, number, ...)
    "bad_format",     # an object, but missing/unknown bundle format field
})


@dataclass
class Finding:
    severity: str  # "fail" | "warn" | "info"
    code: str
    detail: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, code: str, detail: str) -> None:
        self.findings.append(Finding(severity, code, detail))

    @property
    def ok(self) -> bool:
        return not any(f.severity == "fail" for f in self.findings)

    @property
    def result(self) -> str:
        """Three-way headline verdict, finer than `ok`:
        - "verified": no failures.
        - "unconfirmed": failures exist but every one is a verifier-supplied-key mismatch
          (see ATTESTATION_FAIL_CODES). The record's own integrity is intact; a key you passed
          did not match. NOT tampering.
        - "tampered": at least one failure indicates the recorded data itself does not verify.
        """
        fails = [f.code for f in self.findings if f.severity == "fail"]
        if not fails:
            return "verified"
        if any(code in FORMAT_ERROR_CODES for code in fails):
            return "malformed"
        # An empty bundle (no records) is its own case: there is nothing to have tampered with.
        # The usual cause is exporting before the agent recorded anything, or the agent never
        # connecting to the recorder. Calling that "tampering" is a false alarm. (If a pin or
        # anchor is present, records were genuinely stripped, which the other checks below catch
        # before this; a bare empty bundle reaches here.)
        if fails == ["empty"]:
            return "empty"
        if all(code in ATTESTATION_FAIL_CODES for code in fails):
            return "unconfirmed"
        return "tampered"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "result": self.result,
            "fail": sum(f.severity == "fail" for f in self.findings),
            "warn": sum(f.severity == "warn" for f in self.findings),
            "findings": [f.__dict__ for f in self.findings],
        }


def _by_arrival_sid(server_records: list[dict[str, Any]]) -> dict[Any, list[Any]]:
    """Client seq values per session, in arrival order. Sessions may interleave (two
    writers on one stream); emission order is only meaningful within a session."""
    out: dict[Any, list[Any]] = {}
    for sr in server_records:
        rec = sr.get("record", {})
        out.setdefault(rec.get("session_id"), []).append(rec.get("seq"))
    return out


def verify_bundle(bundle: dict[str, Any], pin: dict[str, Any] | None = None,
                  tlog_log_key: str | None = None,
                  witness_pubkeys: dict[str, str] | None = None,
                  max_cosig_age_days: float = 30.0,
                  now_utc: str | None = None,
                  audit_trail: bool = False,
                  registry_pubkey: str | None = None,
                  disclosure_openings: dict[str, Any] | None = None,
                  bitcoin_headers: dict[int, str] | None = None) -> Report:
    rep = Report()
    if not isinstance(bundle, dict):
        rep.add("fail", "not_a_bundle",
                f"this file is valid JSON but a {type(bundle).__name__}, not a Provenrail "
                f"bundle (a JSON object). Check you pointed at the right file.")
        return rep
    if bundle.get("format") != "flightrecorder.bundle/1":
        rep.add("fail", "bad_format", f"unexpected bundle format {bundle.get('format')!r}")
        return rep

    server_records = bundle.get("records", [])
    if not server_records:
        rep.add("fail", "empty", "bundle has no records")
        return rep

    if pin is not None:
        _verify_pin(bundle, server_records, pin, rep)

    # --- 1. server receipt chain (arrival order, server-controlled) ---
    # Recompute every value from the record bytes and the prior recomputed link; never trust
    # a derived field in the bundle. `recomputed_srh` is the verifier's own receipt chain and
    # is what the Merkle anchor check (step 4) is built over.
    prev = GENESIS_PREV_HASH
    recomputed_srh: list[str] = []
    for i, sr in enumerate(server_records):
        if sr.get("recv_seq") != i:
            rep.add("fail", "recv_gap", f"recv_seq gap at index {i}: got {sr.get('recv_seq')}")
        recv_hash = sha256_hex(canonicalize(sr.get("record")))
        if recv_hash != sr.get("recv_hash"):
            rep.add("fail", "recv_hash_mismatch",
                    f"recv_seq {sr.get('recv_seq')}: stored record bytes do not match recv_hash")
        srh = sha256_hex(canonicalize({
            "recv_seq": sr.get("recv_seq"),
            "recv_ts": sr.get("recv_ts"),
            "recv_hash": recv_hash,            # recomputed, not the bundle's recv_hash
            "server_prev_hash": prev,          # recomputed prior link, not the bundle's
        }))
        if srh != sr.get("server_record_hash"):
            rep.add("fail", "server_chain_break",
                    f"recv_seq {sr.get('recv_seq')}: server receipt chain broken (delete/reorder)")
        recomputed_srh.append(srh)
        prev = srh

    # --- 2. client chain (emission order, agent-controlled) ---
    # A stream holds one session per run; each session is its own genesis-rooted chain
    # (seq from 0, prev_hash from genesis). Group by session_id in arrival order and
    # verify every session independently: reuse of a stream across runs is the normal
    # quickstart shape, not tampering.
    client_records = [sr["record"] for sr in server_records]
    sessions: list[list[dict[str, Any]]] = []
    _by_sid: dict[Any, list[dict[str, Any]]] = {}
    for r in client_records:
        sid = r.get("session_id")
        if sid not in _by_sid:
            _by_sid[sid] = []
            sessions.append(_by_sid[sid])
        _by_sid[sid].append(r)
    multi = len(sessions) > 1
    for sess in sessions:
        sess.sort(key=lambda r: r.get("seq", 1 << 30))
        label = f"session {sess[0].get('session_id')}: " if multi else ""
        for issue in verify_client_chain(sess):
            rep.add("fail", f"client_{issue.code}", f"{label}seq={issue.seq}: {issue.detail}")
    ordered = [r for sess in sessions for r in sess]

    # --- 3. arrival order matches emission order (replay/reorder at sink), per session ---
    for sid, arrived in _by_arrival_sid(server_records).items():
        label = f"session {sid}: " if multi else ""
        if arrived != sorted(arrived, key=lambda s: s if isinstance(s, int) else 1 << 30):
            rep.add("fail", "arrival_reorder",
                    f"{label}records did not arrive in emission order "
                    "(possible replay or reordering)")
        if len(set(arrived)) != len(arrived):
            rep.add("fail", "duplicate_seq", f"{label}duplicate client seq values (replay)")

    # --- 4. anchors ---
    anchors = bundle.get("anchors", [])
    if not anchors:
        rep.add("warn", "no_anchor",
                "no external anchor present; records are not bound to a trusted external time")
    elif all(a.get("receipt", {}).get("kind") == "local" for a in anchors):
        rep.add("warn", "local_anchor_only",
                "only LOCAL anchors present; these carry no independent third-party time proof. "
                "Use an RFC 3161 anchor for evidence that must stand against the sink operator.")
    covering_time: dict[int, str] = {}  # recv_seq -> earliest TRUSTED covering anchor gen_time
    for a in anchors:
        receipt = a.get("receipt", {})
        covers = a.get("covers_up_to", -1)
        try:
            leaves = [recomputed_srh[sr["recv_seq"]] for sr in server_records
                      if sr["recv_seq"] <= covers and sr["recv_seq"] < len(recomputed_srh)]
            root = merkle_root(leaves)
        except (ValueError, KeyError, TypeError) as e:
            rep.add("fail", "anchor_malformed", f"anchor {a.get('anchor_seq')}: malformed receipt chain: {e}")
            continue
        if root != receipt.get("merkle_root"):
            rep.add("fail", "anchor_root_mismatch",
                    f"anchor {a.get('anchor_seq')}: Merkle root does not cover the receipt chain")
            continue
        status = _verify_anchor_receipt(receipt, rep, a.get("anchor_seq"))
        if status == "fail":
            continue
        # Only a fully verified (trusted) anchor binds records to a trusted external time.
        if status == "trusted":
            gt = receipt.get("gen_time")
            for sr in server_records:
                if sr["recv_seq"] <= covers and sr["recv_seq"] not in covering_time:
                    covering_time[sr["recv_seq"]] = gt

    # --- 5. time plausibility (soft) ---
    # ts_utc integrity is already hard-protected by the record hash + signature: any edit
    # breaks the chain (a 'fail' above). These checks only surface clock-skew / implausible
    # times as warnings. TSA gen_time is floored to whole seconds, so we allow a tolerance.
    for sr in server_records:
        gt = covering_time.get(sr["recv_seq"])
        if gt is None:
            continue
        ts = sr["record"].get("ts_utc", "")
        if ts and _seconds_after(ts, gt) > ANCHOR_SKEW_TOLERANCE_S:
            rep.add("warn", "ts_after_anchor",
                    f"recv_seq {sr['recv_seq']}: client ts_utc {ts} is well after its anchor time {gt} "
                    f"(clock skew or backdating; record hash is intact)")
        if _seconds_after(sr.get("recv_ts", ""), gt) > ANCHOR_SKEW_TOLERANCE_S:
            rep.add("warn", "recv_after_anchor",
                    f"recv_seq {sr['recv_seq']}: server recv_ts is well after the covering anchor")

    # --- 7 + 8. transparency log (inclusion + consistency), if present ---
    _verify_tlog(bundle, rep, tlog_log_key, witness_pubkeys or {},
                 max_cosig_age_days, now_utc, audit_trail)

    # --- 9. agent identity (KYA), if a registry assertion is present ---
    _verify_registry(bundle, client_records, rep, registry_pubkey)

    # --- 10. active policy: prove which guardrails were committed and that no executed action
    #         violates a re-verifiable deny / limit / spend rule ---
    for sess in sessions:
        _verify_policy(sess, rep)

    # --- 11. coherence / anomaly signals (heuristic, surfaced as warn/info, never a hard fail) ---
    from ..coherence import detect as _detect_anomalies
    for sess in sessions:
        for sig in _detect_anomalies(sess):
            rep.add(sig["severity"], sig["code"], sig["detail"])

    # --- 12. selective-disclosure redaction: count redactable fields and check any disclosed
    #         openings against their committed values (a forged disclosure is a hard fail) ---
    _verify_redactions(ordered, rep, disclosure_openings)

    # --- 13. SCITT receipts: if anchors carry standards-format COSE receipts, verify each
    #         against the transparency-service key (a forged receipt is a hard fail) ---
    _verify_scitt(bundle, rep, tlog_log_key)

    # --- 14. Bitcoin anchoring: if the bundle carries OpenTimestamps proofs over checkpoint
    #         roots, verify each offline. A proof that does not commit to our root, or that
    #         contradicts a supplied Bitcoin header, is a hard fail; a confirmed proof is the
    #         strong public-history claim; a pending or unchecked proof is surfaced, never failed ---
    _verify_ots(bundle, rep, bitcoin_headers)

    # --- 6. completeness signals (surfaced, never a pass/fail on their own) ---
    for sess in sessions:
        if not sess or sess[-1].get("action_type") != SEAL:
            label = f"session {sess[0].get('session_id')}: " if (multi and sess) else ""
            rep.add("warn", "unsealed",
                    f"{label}session is not sealed; it may have crashed or be in progress. "
                    "Completeness unknown.")
    n_hb = sum(1 for r in client_records if r.get("action_type") == HEARTBEAT)
    rep.add("info", "summary",
            f"{len(server_records)} records, {len(anchors)} anchors, {n_hb} heartbeats. "
            f"Completeness is never attested by this tool.")
    return rep


def _verify_scitt(bundle: dict[str, Any], rep: Report, log_key: str | None) -> None:
    """Step 13: verify SCITT-aligned COSE receipts attached to anchors.

    A receipt is the tlog inclusion re-expressed as a standards-format COSE_Sign1 signed by the
    transparency-service (tlog) key. A present-but-forged receipt is a hard fail; a present
    receipt with no known TS key is surfaced as info (re-run with --tlog-pubkey to check it)."""
    from .. import scitt, tlog
    stream_id = bundle.get("stream_id", "")
    anchors = bundle.get("anchors", [])
    receipts = [a for a in anchors if a.get("scitt_receipt")]
    if not receipts:
        return
    if not log_key:
        rep.add("info", "scitt_receipt_present",
                f"{len(receipts)} SCITT COSE receipt(s) present but unverified; re-run with "
                f"--tlog-pubkey to verify them against the transparency service")
        return
    n_ok = 0
    for a in receipts:
        receipt = a.get("receipt", {})
        token_or_sig = (receipt.get("token_b64") if receipt.get("kind") == "rfc3161"
                        else receipt.get("signature")) or ""
        try:
            commit = tlog.compute_anchor_commit(
                stream_id, a.get("anchor_seq"), a.get("covers_up_to"),
                receipt.get("merkle_root", ""), receipt.get("gen_time", ""),
                receipt.get("kind", ""), token_or_sig).hex()
        except Exception:
            rep.add("fail", "scitt_receipt_invalid",
                    f"anchor {a.get('anchor_seq')}: cannot recompute commitment for its SCITT receipt")
            continue
        v = scitt.verify_receipt(a["scitt_receipt"], commit, log_key)
        if v["ok"]:
            n_ok += 1
        elif v["inclusion_ok"] and not v["signature_ok"] and v.get("kid_match") is False:
            # Inclusion proof is intact but the COSE signature does not verify, and the receipt's
            # key id differs from the --tlog-pubkey supplied: this is the wrong/stale TS key, not
            # a forged receipt. A forged receipt keeps its key id, so kid_match would be True and
            # it falls through to the hard-fail branch below.
            rep.add("fail", "scitt_key_mismatch",
                    f"anchor {a.get('anchor_seq')}: the --tlog-pubkey you supplied does not match "
                    f"this SCITT receipt's key id; cannot confirm it (wrong or stale key). The "
                    f"receipt's inclusion proof is intact.")
        else:
            rep.add("fail", "scitt_receipt_invalid",
                    f"anchor {a.get('anchor_seq')}: SCITT receipt failed verification "
                    f"(signature_ok={v['signature_ok']}, inclusion_ok={v['inclusion_ok']}, "
                    f"error={v.get('error')})")
    if n_ok:
        rep.add("info", "scitt_receipt_ok",
                f"{n_ok} SCITT COSE receipt(s) verified against the transparency service "
                f"(standards-aligned, independently checkable per draft-ietf-scitt-architecture)")


def _verify_ots(bundle: dict[str, Any], rep: Report, headers: dict[int, str] | None) -> None:
    """Step 14: verify OpenTimestamps (Bitcoin) proofs over transparency-log checkpoint roots.

    Each `ots_proofs` entry is {tree_size, root_hex, ots_b64}: an OpenTimestamps proof whose stamped
    data is the raw checkpoint Merkle root, binding the log's state to Bitcoin proof-of-work. Offline
    we can prove the proof commits to OUR root and replay it to the block Merkle root it claims; we
    can only *confirm* that block when given a trusted Bitcoin header (`bitcoin_headers`). So a proof
    that does not commit to our root, or that contradicts a supplied header, is a hard fail; a header-
    confirmed proof is `ots_bitcoin_confirmed`; an attested-but-unchecked or still-pending proof is
    surfaced (info), never failed, since Bitcoin confirmation legitimately lags by hours."""
    import base64
    import hashlib

    from .. import ots

    proofs = bundle.get("ots_proofs") or []
    if not proofs:
        return
    for p in proofs:
        tree_size = p.get("tree_size")
        root_hex = p.get("root_hex", "")
        try:
            proof_bytes = base64.b64decode(p.get("ots_b64", ""))
            stamped = hashlib.sha256(bytes.fromhex(root_hex)).hexdigest()
        except Exception:
            rep.add("fail", "ots_invalid",
                    f"OTS proof for tree_size {tree_size}: malformed proof or root")
            continue
        v = ots.verify_ots(proof_bytes, stamped, bitcoin_block_merkle_roots=headers)
        if not v["structurally_valid"]:
            rep.add("fail", "ots_invalid",
                    f"OTS proof for tree_size {tree_size}: not a valid OpenTimestamps proof "
                    f"({v.get('error')})")
            continue
        if not v["data_matches"]:
            rep.add("fail", "ots_wrong_target",
                    f"OTS proof for tree_size {tree_size}: does not commit to the checkpoint root")
            continue
        if any(b["confirmed"] is False for b in v["bitcoin"]):
            heights = ", ".join(str(b["height"]) for b in v["bitcoin"] if b["confirmed"] is False)
            rep.add("fail", "ots_block_mismatch",
                    f"OTS proof for tree_size {tree_size}: replayed root does not match the trusted "
                    f"Bitcoin header at block {heights}")
            continue
        confirmed = [b["height"] for b in v["bitcoin"] if b["confirmed"] is True]
        if confirmed:
            rep.add("info", "ots_bitcoin_confirmed",
                    f"checkpoint (tree_size {tree_size}) anchored in Bitcoin block(s) "
                    f"{', '.join(map(str, confirmed))}, confirmed against a trusted header")
        elif v["bitcoin_attested"]:
            heights = ", ".join(str(b["height"]) for b in v["bitcoin"])
            rep.add("info", "ots_bitcoin_attested",
                    f"checkpoint (tree_size {tree_size}) is Bitcoin-attested at block(s) {heights}; "
                    f"supply a trusted header to confirm it against the chain")
        elif v["pending"]:
            rep.add("info", "ots_pending",
                    f"checkpoint (tree_size {tree_size}) submitted to OpenTimestamps calendar(s), "
                    f"Bitcoin confirmation pending")


def _verify_policy(ordered: list[dict[str, Any]], rep: Report) -> None:
    """Step 10: if the session committed an active policy, prove it was not tampered with and
    that the recorded run is consistent with it.

    Two checkable properties, framed without overclaiming:
      1. Commitment integrity: the policy embedded in the signed session-start record hashes to
         the committed policy_sha256. Any edit to the guardrails breaks this (and the record's
         own signature). This is what makes "these were the guardrails in force" evidence.
      2. Enforcement consistency: replaying the committed deny / limit / spend rules over the
         recorded events, no EXECUTED action should match a rule that would have denied it. An
         executed action that a re-verifiable rule denies means the stated policy was not actually
         enforced for that call (a real governance finding), reported as a warning.

    Content gates (arg_contains) cannot be re-evaluated once arguments are hashed; they are
    reported as enforced-but-not-offline-reverifiable rather than silently trusted.
    """
    if not ordered:
        return
    genesis = ordered[0]
    if genesis.get("action_type") != GENESIS:
        return
    meta = (genesis.get("payload", {}) or {}).get("meta", {}) or {}
    policy_dict = meta.get("policy")
    committed = meta.get("policy_sha256")
    if policy_dict is None:
        return  # no active policy was committed; nothing to verify

    from ..policy import (
        ALLOW,
        Policy,
        SessionState,
        _estimate_cost,
    )

    policy = Policy.from_dict(policy_dict)
    if committed is not None and policy.policy_id() != committed:
        rep.add("fail", "policy_commit_mismatch",
                "the committed policy hash does not match the embedded policy (the recorded "
                "guardrails were altered after the session started)")
        return

    # A verifier-only policy with content gates removed, since arg text is not in the bundle,
    # and with cross-session budgets removed: a `day` or `total` cap was evaluated against spend
    # recorded in *other* sessions, which this bundle does not contain. Replaying it here would
    # manufacture false "policy not enforced" findings out of missing history, so it is reported
    # as enforced-but-not-offline-reverifiable, the same treatment content gates get.
    from ..policy import SESSION
    session_budgets = [b for b in policy.budgets if b.scope == SESSION]
    cross_session_budgets = len(policy.budgets) - len(session_budgets)
    reverifiable = Policy(rules=[r for r in policy.rules if not r.content_based],
                          budgets=session_budgets,
                          session_spend_cap_usd=policy.session_spend_cap_usd)
    content_rules = sum(1 for r in policy.rules if r.content_based)

    event_for = {MODEL_CALL: "model_call", TOOL_CALL: "tool_call",
                 MCP_CALL: "mcp_call", DATA_ACCESS: "data_access"}
    state = SessionState()
    checked = 0
    violations = 0
    recorded_denies = sum(1 for r in ordered
                          if r.get("action_type") == "policy.decision"
                          and (r.get("payload", {}) or {}).get("effect") == "deny")
    for rec in ordered:
        action = rec.get("action_type")
        if action == HUMAN_OVERSIGHT:
            state.had_oversight = True
            continue
        ev = event_for.get(action)
        if ev is None:
            continue
        payload = rec.get("payload", {}) or {}
        ctx = {"provider": payload.get("provider", ""), "model": payload.get("model", ""),
               "usage": payload.get("usage"), "tool": payload.get("tool", ""),
               "resource": payload.get("resource", "")}
        decision = reverifiable.decide(ev, ctx, state)
        checked += 1
        if decision.effect != ALLOW:
            violations += 1
            rep.add("warn", "policy_not_enforced",
                    f"seq {rec.get('seq')}: an executed {action} matches policy rule "
                    f"{decision.rule_id!r} which would deny it ({decision.reason}); the committed "
                    f"policy was not enforced for this call")
        # Mirror the SDK's post-call spend accounting so the spend cap replays correctly.
        if action == MODEL_CALL:
            state.spend_usd += _estimate_cost(ctx)

    if violations == 0:
        detail = (f"committed policy {committed[:12] if committed else 'present'} verified: "
                  f"{checked} re-verifiable events consistent with the guardrails, "
                  f"{recorded_denies} recorded enforcement denials")
        if content_rules:
            detail += (f"; {content_rules} content-gate rule(s) were enforced but cannot be "
                       f"re-checked offline because arguments are hashed")
        if cross_session_budgets:
            detail += (f"; {cross_session_budgets} cross-session budget(s) were enforced but "
                       f"cannot be re-checked from this bundle alone, which covers one session")
        rep.add("info", "policy_verified", detail)


def load_openings(obj: dict[str, Any] | None) -> dict[str, Any]:
    """Accept either a raw {commit: opening} map or the SDK keystore {format, openings}."""
    if not obj:
        return {}
    return obj.get("openings", obj) if isinstance(obj, dict) else {}


def _verify_redactions(ordered: list[dict[str, Any]], rep: Report,
                       disclosure_openings: dict[str, Any] | None) -> None:
    """Step 12: count selective-disclosure commitments and validate any supplied openings.

    A redactable field appears in the signed record as a salted commitment, never cleartext, so
    the base verification (steps 1 to 2) already proves it is authentic and untampered. Here we
    additionally, when an operator supplies openings, confirm each disclosed value really does
    open its commitment. A disclosed opening that does not match is a forged disclosure and a hard
    fail. Commitments with no opening are reported as withheld or erased, never as an error: that
    is the right-to-erasure path and the record stays valid without them.
    """
    from .. import redaction

    openings = load_openings(disclosure_openings)
    total = disclosed = invalid = 0
    for rec in ordered:
        for c in redaction.walk_commitments(rec.get("payload", {})):
            total += 1
            op = openings.get(c)
            if op is None:
                continue
            if redaction.verify_opening(c, op.get("value"), op.get("salt", "")):
                disclosed += 1
            else:
                invalid += 1
                rep.add("fail", "redaction_disclosure_invalid",
                        f"a supplied opening does not match its commitment {c[:16]} "
                        f"(forged disclosure: the revealed value is not what was committed)")
    if total:
        withheld = total - disclosed - invalid
        detail = (f"{total} redactable field(s): {disclosed} disclosed and verified, "
                  f"{withheld} withheld or erased")
        if invalid:
            detail += f", {invalid} INVALID disclosure(s)"
        rep.add("info", "redaction_summary", detail)


def _checkpoint_root_b64(body: str) -> str | None:
    """The base64 Merkle root is the third line of a checkpoint body."""
    lines = body.split("\n")
    return lines[2] if len(lines) >= 3 else None


def _verify_tlog(bundle: dict[str, Any], rep: Report, log_key: str | None,
                 witness_pubkeys: dict[str, str], max_cosig_age_days: float,
                 now_utc: str | None, audit_trail: bool) -> None:
    """Steps 7 (inclusion) and 8 (consistency) of SPEC.md section 11.

    Recomputes the anchor commitment from the bundle's own fields, verifies the RFC 6962
    inclusion proof against the signed checkpoint root, checks the log-key signature and any
    witness cosignatures, and verifies that the checkpoints present grew append-only. A
    checkpoint with no valid witness cosignature is amber (warn), never green."""
    from datetime import datetime

    from .. import tlog

    has_schema = bundle.get("tlog_schema_version") is not None
    anchors = bundle.get("anchors", [])
    stream_id = bundle.get("stream_id")
    now = now_utc or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    max_age_s = max_cosig_age_days * 86400.0

    # Collect checkpoint roots seen across inclusion proofs, for the consistency step.
    seen_roots: dict[int, str] = {}

    for a in anchors:
        incl = a.get("tlog_inclusion")
        if incl is None:
            # Legacy bundle: silence. New (schema-bearing) bundle: a missing proof is notable.
            sev = "warn" if has_schema else "info"
            rep.add(sev, "tlog_no_inclusion",
                    f"anchor {a.get('anchor_seq')}: no transparency-log inclusion proof present")
            continue
        receipt = a.get("receipt", {})
        token_or_sig = (receipt.get("token_b64") if receipt.get("kind") == "rfc3161"
                        else receipt.get("signature")) or ""
        try:
            commit = tlog.compute_anchor_commit(
                stream_id, a.get("anchor_seq"), a.get("covers_up_to"),
                receipt.get("merkle_root", ""), receipt.get("gen_time", ""),
                receipt.get("kind", ""), token_or_sig).hex()
        except Exception as e:
            rep.add("fail", "tlog_inclusion_fail",
                    f"anchor {a.get('anchor_seq')}: cannot recompute anchor commitment: {e}")
            continue

        note = incl.get("checkpoint", "")
        parsed = tlog.parse_signed_note(note)
        body = parsed["body"]
        root_b64 = _checkpoint_root_b64(body)
        origin = body.split("\n")[0] if body else ""
        try:
            tree_size = int(body.split("\n")[1])
        except (IndexError, ValueError):
            tree_size = incl.get("tree_size", -1)
        if root_b64 is None:
            rep.add("fail", "tlog_inclusion_fail",
                    f"anchor {a.get('anchor_seq')}: malformed checkpoint body")
            continue
        seen_roots[tree_size] = root_b64

        if not tlog.verify_inclusion(commit, incl.get("leaf_index", -1),
                                     incl.get("tree_size", tree_size),
                                     incl.get("proof_hashes", []), root_b64):
            rep.add("fail", "tlog_inclusion_fail",
                    f"anchor {a.get('anchor_seq')}: inclusion proof does not verify against "
                    f"the checkpoint root (the anchor is not provably in the log)")
            continue

        # Log-key signature: the first 68-byte payload signed by the origin key.
        sigs = parsed["signatures"]
        log_sig = next((s for s in sigs if len(s["payload"]) == 68), None)
        if log_key is None:
            rep.add("warn", "tlog_log_key_unknown",
                    f"anchor {a.get('anchor_seq')}: no log public key configured, the "
                    f"checkpoint signature was not validated")
        elif log_sig is None:
            rep.add("fail", "tlog_log_key_invalid",
                    f"anchor {a.get('anchor_seq')}: checkpoint carries no log-key signature")
        else:
            status = tlog.verify_log_signature(body, log_sig["payload"], log_key, origin)
            if status == "key_id_mismatch":
                rep.add("fail", "tlog_log_key_id_mismatch",
                        f"anchor {a.get('anchor_seq')}: checkpoint key id does not match the "
                        f"configured log key for {origin!r}")
            elif status != "ok":
                rep.add("fail", "tlog_log_key_invalid",
                        f"anchor {a.get('anchor_seq')}: checkpoint log-key signature invalid")

        # Witness cosignatures: 76-byte payloads. Count only valid, in-window, known ones.
        valid_cosigs = 0
        for s in sigs:
            if len(s["payload"]) != 76:
                continue  # not a cosignature (log sig or unknown algorithm: skip)
            name = s["key_name"]
            pub = witness_pubkeys.get(name)
            if pub is None:
                rep.add("info", "tlog_cosig_unrecognized",
                        f"anchor {a.get('anchor_seq')}: cosignature from unconfigured witness "
                        f"{name!r} (not counted)")
                continue
            # Distinguish "you supplied the wrong key for this witness" (key id differs = a
            # verifier-input problem, not tampering) from "the cosignature itself is invalid
            # under the right key" (forgery). The cosignature payload begins with a 4-byte key
            # id derived from (name, pubkey); if it does not match the supplied pubkey, no
            # signature check can succeed, and saying "invalid" would read as tampering.
            expected_kid = tlog.key_id(name, bytes.fromhex(pub), tlog._ALG_COSIGNATURE_V1)
            if s["payload"][:4] != expected_kid:
                rep.add("fail", "tlog_cosig_key_id_mismatch",
                        f"anchor {a.get('anchor_seq')}: the witness key you supplied for {name!r} "
                        f"does not match this cosignature (wrong or stale key, or a different "
                        f"witness). The record itself is unaffected.")
                continue
            ok, ts = tlog.verify_cosignature(s["payload"], pub, body, name)
            if not ok:
                rep.add("fail", "tlog_cosig_invalid",
                        f"anchor {a.get('anchor_seq')}: witness {name!r} cosignature invalid")
                continue
            ts_iso = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            if _seconds_after(ts_iso, now) > ANCHOR_SKEW_TOLERANCE_S:
                rep.add("fail", "tlog_cosig_invalid",
                        f"anchor {a.get('anchor_seq')}: witness {name!r} cosignature is "
                        f"timestamped in the future ({ts_iso})")
                continue
            if _seconds_after(receipt.get("gen_time", ""), ts_iso) > ANCHOR_SKEW_TOLERANCE_S:
                rep.add("warn", "tlog_cosig_stale",
                        f"anchor {a.get('anchor_seq')}: witness {name!r} cosigned at {ts_iso}, "
                        f"before the anchor time (not counted toward witnessing)")
                continue
            if _seconds_after(now, ts_iso) > max_age_s:
                rep.add("warn", "tlog_cosig_stale",
                        f"anchor {a.get('anchor_seq')}: witness {name!r} cosignature older than "
                        f"{max_cosig_age_days} days (not counted)")
                continue
            rep.add("info", "tlog_cosig_valid",
                    f"anchor {a.get('anchor_seq')}: witness {name!r} cosignature valid at {ts_iso}")
            valid_cosigs += 1

        if valid_cosigs >= 1:
            rep.add("info", "tlog_inclusion_witnessed_ok",
                    f"anchor {a.get('anchor_seq')}: in the transparency log and witnessed by "
                    f"{valid_cosigs} independent part{'y' if valid_cosigs == 1 else 'ies'}")
        else:
            sev = "fail" if audit_trail else "warn"
            rep.add(sev, "tlog_inclusion_unwitnessed",
                    f"anchor {a.get('anchor_seq')}: in the transparency log but not witnessed "
                    f"(append-only proofs present, no independent cosignature)")

    # --- step 8: consistency between checkpoints present in the bundle ---
    for cp in bundle.get("tlog_consistency_proofs", []):
        old_size, new_size = cp.get("old_size"), cp.get("new_size")
        old_root, new_root = seen_roots.get(old_size), seen_roots.get(new_size)
        if old_root is None or new_root is None:
            rep.add("info", "tlog_consistency_skipped",
                    f"consistency {old_size}->{new_size}: a checkpoint root for this span is "
                    f"not in the bundle, hop not checked")
            continue
        from .. import tlog as _t
        if not _t.verify_consistency(old_size, old_root, new_size, new_root,
                                     cp.get("proof_hashes", [])):
            rep.add("fail", "tlog_consistency_fail",
                    f"consistency {old_size}->{new_size}: the log is not a strict append-only "
                    f"extension (fork or truncation)")


def _verify_registry(bundle: dict[str, Any], client_records: list[dict[str, Any]], rep: Report,
                     registry_pubkey: str | None) -> None:
    """Step 9: confirm the device key that signed the records is the one registered for the
    agent (SPEC.md section 12). Needs the registry public key; otherwise skipped silently."""
    from .. import registry as reg

    pubkeys = {r.get("pubkey") for r in client_records if r.get("pubkey")}
    assertions = bundle.get("agent_registry")
    if registry_pubkey is None:
        if assertions:
            rep.add("info", "kya_registry_unchecked",
                    "agent registry assertions present but no registry public key was supplied "
                    "to validate them (pass --registry-pubkey)")
        return
    if not assertions:
        rep.add("warn", "kya_unregistered",
                "no agent identity assertion in the bundle: records are signed by a consistent "
                "key, but it is not bound to a registered agent")
        return
    valid_for: dict[str, dict[str, Any]] = {}
    for a in assertions:
        if not reg.verify_assertion(a, registry_pubkey):
            rep.add("fail", "kya_assertion_invalid",
                    f"agent registry assertion for {a.get('agent_id')!r} is not validly signed "
                    f"by the registry key")
            continue
        valid_for[a.get("pubkey")] = a
    for pk in pubkeys:
        a = valid_for.get(pk)
        if a is None:
            rep.add("warn", "kya_key_unregistered",
                    f"device key {pk[:16]}... is not covered by any valid registry assertion")
            continue
        if a.get("status") == "revoked":
            rep.add("warn", "kya_key_revoked",
                    f"device key for agent {a.get('agent_id')!r} was registered but later "
                    f"revoked at {a.get('revoked_at')} (records may predate revocation)")
        else:
            rep.add("info", "kya_registered",
                    f"device key is the registered key for agent {a.get('agent_id')!r} "
                    f"in account {a.get('account_id')}")


def _verify_pin(bundle: dict[str, Any], server_records: list[dict[str, Any]],
                pin: dict[str, Any], rep: Report) -> None:
    """Check an export against a client-held pin to detect malicious tail-truncation.

    The pin is an independent, signed checkpoint the agent kept: 'the sink had at least
    N records ending in hash H'. If the export drops below N, the sink truncated history.
    """
    body = {k: pin[k] for k in pin if k != "pin_sig"}
    if not verify_signature(pin.get("pubkey", ""), canonicalize(body), pin.get("pin_sig", "")):
        rep.add("fail", "pin_bad_signature", "pin signature invalid; pin cannot be trusted")
        return
    if pin.get("stream_id") != bundle.get("stream_id"):
        rep.add("fail", "pin_wrong_stream", "pin is for a different stream")
        return
    pinned_seq = pin.get("recv_seq")
    match = next((r for r in server_records if r.get("recv_seq") == pinned_seq), None)
    if match is None:
        rep.add("fail", "pin_truncated",
                f"export is missing recv_seq {pinned_seq} that the client pinned: the sink "
                f"truncated history after it was recorded")
        return
    if match.get("server_record_hash") != pin.get("server_record_hash"):
        rep.add("fail", "pin_forked",
                f"recv_seq {pinned_seq} has a different hash than the client pinned: the sink "
                f"rewrote history")
        return
    rep.add("info", "pin_ok",
            f"client pin confirmed: sink still holds the record set up to recv_seq {pinned_seq}")


def _verify_anchor_receipt(receipt: dict[str, Any], rep: Report, seq: Any) -> str:
    """Return "trusted" (third-party RFC3161 timestamp validated), "untrusted"
    (signature good but no external trust anchor, e.g. local anchor or unknown TSA),
    or "fail" (the receipt is broken or does not cover this root)."""
    kind = receipt.get("kind")
    root = receipt.get("merkle_root", "")
    if kind == "local":
        ok = verify_signature(
            receipt.get("anchor_pubkey", ""),
            (root + "|" + receipt.get("gen_time", "")).encode("utf-8"),
            receipt.get("signature", ""),
        )
        if not ok:
            rep.add("fail", "anchor_bad_sig", f"anchor {seq}: local anchor signature invalid")
            return "fail"
        rep.add("warn", "anchor_local_only",
                f"anchor {seq}: LOCAL anchor only (no third-party trusted timestamp); "
                f"time {receipt.get('gen_time')} is self-asserted and not externally provable")
        return "untrusted"
    if kind == "rfc3161":
        try:
            import base64
            import hashlib

            try:
                from rfc3161_client import decode_timestamp_response
            except ModuleNotFoundError:
                # rfc3161-client is a core dependency as of 0.2.2; only a stale or partial
                # install lands here. Give an actionable message, not a raw import error.
                rep.add("fail", "rfc3161_support_missing",
                        f"anchor {seq}: this proof carries an RFC 3161 trusted timestamp but the "
                        f"verifier cannot decode it. Reinstall to get trusted-time support: "
                        f"uv tool install --reinstall provenrail (or pip install -U 'provenrail').")
                return "fail"
            raw = base64.b64decode(receipt["token_b64"])
            tst = decode_timestamp_response(raw)
            mi = tst.tst_info.message_imprint
            oid = getattr(mi.hash_algorithm, "dotted_string", "") or getattr(mi.hash_algorithm, "_name", "")
            alg = _DIGEST_OIDS.get(oid, oid).lower()
            if alg not in hashlib.algorithms_available:
                rep.add("fail", "anchor_bad_alg", f"anchor {seq}: unsupported imprint algorithm {oid!r}")
                return "fail"
            expected = hashlib.new(alg, bytes.fromhex(root)).digest()
            if mi.message != expected:
                rep.add("fail", "anchor_imprint_mismatch",
                        f"anchor {seq}: RFC3161 token does not cover this Merkle root")
                return "fail"

            # Full verification: CMS signature + cert chain to a bundled TSA root.
            from rfc3161_client import VerifierBuilder

            from ..trust import root_for_tsa
            ca = root_for_tsa(receipt.get("tsa_url"))
            if ca is None:
                rep.add("warn", "anchor_unverified_tsa",
                        f"anchor {seq}: imprint matches but TSA {receipt.get('tsa_url')!r} root is "
                        f"not in the trust store, so the TSA signature was not validated")
                return "untrusted"
            try:
                verifier = VerifierBuilder().add_root_certificate(ca).build()
                if not verifier.verify_message(tst, bytes.fromhex(root)):
                    rep.add("fail", "anchor_sig_invalid",
                            f"anchor {seq}: RFC3161 signature or cert chain did not validate")
                    return "fail"
            except Exception as e:
                rep.add("fail", "anchor_verify_error", f"anchor {seq}: TSA verification error: {e}")
                return "fail"
            rep.add("info", "anchor_rfc3161",
                    f"anchor {seq}: RFC3161 trusted timestamp from {receipt.get('tsa_url')} "
                    f"at {receipt.get('gen_time')}, signature and cert chain validated")
            return "trusted"
        except Exception as e:  # pragma: no cover
            rep.add("fail", "anchor_decode_error", f"anchor {seq}: cannot decode RFC3161 token: {e}")
            return "fail"
    rep.add("fail", "anchor_unknown_kind", f"anchor {seq}: unknown anchor kind {kind!r}")
    return "fail"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pr-verify", description="Verify a Provenrail bundle.")
    p.add_argument("bundle", help="path to exported bundle JSON, or '-' for stdin")
    p.add_argument("--pin", help="path to a client-held pin file to detect tail-truncation")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--tlog-pubkey", help="hex Ed25519 public key of the transparency log "
                   "(required to validate the checkpoint signature)")
    p.add_argument("--witness-pubkeys", help="comma-separated name=hexpubkey pairs of trusted "
                   "transparency-log witnesses")
    p.add_argument("--max-cosig-age", type=float, default=30.0,
                   help="reject witness cosignatures older than this many days (default 30)")
    p.add_argument("--registry-pubkey", help="hex Ed25519 public key of the agent identity "
                   "registry, to confirm the device key is the registered key for the agent")
    p.add_argument("--tsa-root", action="append", metavar="HOST=CERT.pem",
                   help="trust an extra TSA root: HOST is a substring of the TSA URL, CERT.pem "
                   "the root certificate. Repeatable. Lets you verify timestamps from a TSA "
                   "Provenrail does not bundle.")
    p.add_argument("--openings", help="path to a redaction openings keystore; disclosed fields "
                   "are checked against their committed values")
    p.add_argument("--bitcoin-header", action="append", metavar="HEIGHT=MERKLE_ROOT",
                   help="a trusted Bitcoin block header as height=merkle_root_hex (repeatable), to "
                   "confirm an OpenTimestamps proof anchors to the real chain")
    args = p.parse_args(argv)

    openings = (json.loads(open(args.openings, encoding="utf-8").read())
                if args.openings else None)

    if args.tsa_root:
        from .. import trust
        for pair in args.tsa_root:
            if "=" not in pair:
                print(f"--tsa-root expects HOST=CERT.pem, got {pair!r}")
                return 2
            host, cert_path = pair.split("=", 1)
            trust.add_root(host.strip(), cert_path.strip())

    raw = sys.stdin.read() if args.bundle == "-" else open(args.bundle, encoding="utf-8").read()
    bundle = json.loads(raw)
    pin = json.loads(open(args.pin, encoding="utf-8").read()) if args.pin else None
    witnesses: dict[str, str] = {}
    if args.witness_pubkeys:
        for pair in args.witness_pubkeys.split(","):
            if "=" in pair:
                name, hexkey = pair.split("=", 1)
                witnesses[name.strip()] = hexkey.strip()
    bitcoin_headers: dict[int, str] = {}
    if args.bitcoin_header:
        for pair in args.bitcoin_header:
            if "=" in pair:
                height, root = pair.split("=", 1)
                bitcoin_headers[int(height.strip())] = root.strip()
    rep = verify_bundle(bundle, pin=pin, tlog_log_key=args.tlog_pubkey,
                        witness_pubkeys=witnesses, max_cosig_age_days=args.max_cosig_age,
                        registry_pubkey=args.registry_pubkey, disclosure_openings=openings,
                        bitcoin_headers=bitcoin_headers or None)

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        for f in rep.findings:
            mark = {"fail": "FAIL", "warn": "warn", "info": "info"}[f.severity]
            print(f"[{mark}] {f.code}: {f.detail}")
        if rep.result == "verified":
            print("\nRESULT: VERIFIED")
            if any(f.severity == "warn" for f in rep.findings):
                # A first-time free-tier run prints several warn lines (local anchor, not
                # witnessed, ...) above a clean pass. Without this, that reads as "lots of
                # problems" when the verdict is green. Only fails ever change the verdict.
                print("The warn/info lines above are advisory context, not failures: the "
                      "record's integrity is fully proven. Only TAMPERING DETECTED is a failure.")
        elif rep.result == "malformed":
            print("\nRESULT: NOT A PROVENRAIL BUNDLE. This file is valid JSON but is not a "
                  "Provenrail bundle (no recognized format). Check you pointed `pr verify` at the "
                  "right file (for example one made by `pr demo` or `pr export`).")
        elif rep.result == "empty":
            print("\nRESULT: NO RECORDS. This bundle is empty: nothing was recorded (or every "
                  "record was stripped). If you expected events, your agent may not have connected "
                  "to the recorder, or you exported before it ran.")
        elif rep.result == "unconfirmed":
            print("\nRESULT: NOT CONFIRMED. The record's own integrity is intact, but a key "
                  "you supplied did not match (see the FAIL lines above: wrong or stale key, or a "
                  "proof from a different log or witness). This is not evidence of tampering.")
        else:
            print("\nRESULT: TAMPERING DETECTED")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
