"""Automatic anchoring.

The tamper-evidence window equals the time since the last external anchor, so a real sink
must anchor on its own, not wait for a manual call. This scheduler periodically anchors
every stream that has new records past its anchor cursor, bounding the window without any
client action.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict
from typing import Any

from ..anchor import Anchor, LocalAnchor, merkle_root  # noqa: F401  (merkle_root used indirectly)
from ..keys import SigningKey
from . import plans

_log = logging.getLogger("provenrail.tlog")


class AnchorScheduler:
    def __init__(self, store, anchor: Anchor, interval_s: float = 60.0,
                 on_anchor: Any | None = None, tlog_log_key: SigningKey | None = None,
                 tlog_origin_prefix: str | None = None, witnesses: list | None = None,
                 witness_threshold: int = 0, plan_lookup: Any | None = None):
        self.store = store
        self.anchor = anchor
        self.interval = interval_s
        # optional callback(stream_id) run after a successful anchor, e.g. integrity alerting.
        # Never allowed to break the anchor loop.
        self.on_anchor = on_anchor
        # Transparency-log publishing. The log key signs each checkpoint; it is auto-generated
        # if not supplied so the log always has a stable identity for the process lifetime.
        from ..tlog import DEFAULT_ORIGIN_PREFIX
        self.tlog_log_key = tlog_log_key or SigningKey.generate()
        self.tlog_origin_prefix = tlog_origin_prefix or DEFAULT_ORIGIN_PREFIX
        self.witnesses = witnesses or []
        self.witness_threshold = witness_threshold
        # plan_lookup(account_id) -> plan string. Gates two paid entitlements: the RFC 3161
        # trusted timestamp (trusted_time) and the independently witnessed checkpoint status
        # (witnessed). A stream with no owner (open/dev mode) is never downgraded.
        self.plan_lookup = plan_lookup
        # Fallback backend for plans without trusted_time: hash-chain anchoring only, no TSA
        # round-trip, so a free-plan anchor never carries an RFC 3161 trusted timestamp.
        self.local_anchor = LocalAnchor()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def anchor_stream(self, stream_id: str) -> dict[str, Any]:
        """Anchor the current receipt-chain head of one stream. Returns the stored receipt.

        The TSA call is a network round-trip and must not be held under the lock, or a slow
        TSA would serialize and stall anchoring for every other stream. We snapshot the
        leaves under the lock, release it for the network call, then re-take it to store.
        """
        with self._lock:
            records = self.store.get_records(stream_id)
            if not records:
                raise ValueError("nothing to anchor")
            leaves = [r["server_record_hash"] for r in records]
            covers = records[-1]["recv_seq"]
        # Trusted-time gate: only plans that include trusted_time get the RFC 3161 backend.
        # Free (and any plan without it) anchors with the hash-chain-only local backend, so the
        # claim "trusted timestamps, Builder and up" is true in the bytes, not just on the page.
        backend = self.anchor
        if self.plan_lookup is not None:
            owner_plan = self.plan_lookup(self.store.stream_owner(stream_id))
            if owner_plan is not None and not plans.feature(owner_plan, "trusted_time"):
                backend = self.local_anchor
        receipt = backend.anchor(leaves)  # network round-trip (if any), no lock held
        with self._lock:
            seq = self.store.store_anchor(stream_id, asdict(receipt), covers,
                                          origin_prefix=self.tlog_origin_prefix)
            self.store.set_last_anchor_seq(stream_id, covers)
            result = {"anchor_seq": seq, "covers_up_to": covers, "receipt": asdict(receipt)}
        # Publish a transparency-log checkpoint over the account's anchor leaves. Failure here
        # must never undo the anchor (which is already committed), so it is best-effort.
        try:
            self.publish_checkpoint(stream_id)
        except Exception:  # pragma: no cover - defensive
            _log.exception("tlog checkpoint publish failed for stream %s", stream_id)
        if self.on_anchor is not None:
            try:
                self.on_anchor(stream_id)  # e.g. integrity alerting; must not break anchoring
            except Exception:
                pass
        return result

    def publish_checkpoint(self, stream_id: str) -> dict[str, Any]:
        """Append the account's transparency-log head as a signed, consistency-proved checkpoint.

        Builds the RFC 6962 root over every anchor leaf in this account's log shard, signs the
        C2SP checkpoint with the log key, records a consistency proof from the previous head,
        and (if witnesses are configured) collects independent cosignatures. The checkpoint is
        what an auditor's bundle embeds and what witnesses countersign."""
        from .. import tlog
        origin = self.store.origin_for_stream(stream_id, self.tlog_origin_prefix)
        leaves = self.store.get_tlog_leaf_hashes(origin)
        size = len(leaves)
        root = tlog.merkle_root_from_leaf_hashes(leaves)
        body = tlog.build_checkpoint(origin, size, root)
        note = tlog.sign_checkpoint(body, self.tlog_log_key, origin)

        prev = self.store.get_latest_tlog_checkpoint(origin)
        consistency = None
        if prev is not None and prev["tree_size"] < size:
            proof = tlog.make_consistency_proof(prev["tree_size"], size, leaves)
            consistency = json.dumps(
                {"old_size": prev["tree_size"], "new_size": size, "proof_hashes": proof})

        witnessed = 0
        status = "final"
        if self.witnesses:
            from .witness import collect_cosignatures
            prev_size = prev["tree_size"] if prev else 0
            proof = tlog.make_consistency_proof(prev_size, size, leaves) if prev_size < size else []
            note, witnessed = collect_cosignatures(self.witnesses, note, proof, body)
        if self.witness_threshold >= 1 and witnessed < self.witness_threshold:
            plan = self.plan_lookup(self.store.stream_owner(stream_id)) if self.plan_lookup else None
            if plan is not None and plans.feature(plan, "witnessed"):
                status = "pending_witness"
                _log.critical("witnessed-plan checkpoint for %s at size %d has %d/%d witnesses",
                              origin, size, witnessed, self.witness_threshold)
        self.store.store_tlog_checkpoint(origin, size, root, note, consistency, witnessed, status)
        return {"origin": origin, "tree_size": size, "witnessed": witnessed, "status": status}

    def tick(self) -> int:
        anchored = 0
        for sid in self.store.streams_needing_anchor():
            try:
                self.anchor_stream(sid)
                anchored += 1
            except Exception:
                continue  # a TSA hiccup must not kill the loop; next tick retries
        return anchored

    def start(self) -> None:
        if self.interval <= 0 or self._thread is not None:
            return

        def loop():
            while not self._stop.wait(self.interval):
                self.tick()

        self._thread = threading.Thread(target=loop, daemon=True, name="fr-anchor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None
