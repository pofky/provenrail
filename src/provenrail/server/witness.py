"""Witness layer: independent cosigners that defeat split-view (equivocation).

The transparency log (tlog.py) proves the sink's anchor history is internally append-only.
That alone does not stop a dishonest sink from keeping TWO consistent histories and showing
a different one to a customer than to a regulator (a split view). The defense is independent
witnesses: each witness remembers the last checkpoint size it cosigned for a log, refuses to
cosign anything that is not a consistency-proved extension of it, and countersigns the head.
Because a witness will not sign two forks, a sink cannot get a quorum of cosignatures on two
different histories without compromising the witnesses themselves.

Honesty boundary (SPEC.md 9.8): a witness cosignature does NOT confer completeness or
semantic correctness. It only proves the head it signed is a strict append-only extension of
what that witness saw before. Residual trust in witness non-collusion is irreducible; the
customer must pick witnesses independent of the sink operator.

Two implementations:
  - LocalWitness: the witness logic in-process. It is the reference witness (self-host a
    second-party witness with it) and is what the test suite and the bundled demo exercise.
  - WitnessClient: the C2SP tlog-witness HTTP client (POST /add-checkpoint) for a remote
    witness, including the 409 stored-size reconciliation with rollback / split-view alarms.
"""

from __future__ import annotations

from fastapi import Request  # module-level so the route annotation resolves under future-annotations

from .. import tlog
from ..keys import SigningKey


class WitnessError(Exception):
    """A witness refused the checkpoint for a recoverable reason (bad request, forbidden)."""


class WitnessRollbackError(WitnessError):
    """A witness reported a size BELOW what it last cosigned for us: its state went backwards."""


class WitnessSplitViewAlert(WitnessError):
    """A witness reported a size ABOVE our current tree: it saw a head we never published."""


class InsufficientWitnessesError(Exception):
    """Fewer cosignatures were collected than the configured threshold."""


class LocalWitness:
    """An in-process witness. Stateful: remembers the last size it cosigned per log origin.

    cosign() verifies the new checkpoint is a consistency-proved append-only extension of the
    last head this witness signed for that origin, and only then returns a cosignature line."""

    def __init__(self, name: str, signing_key: SigningKey | None = None, clock=None):
        self.name = name
        self._key = signing_key or SigningKey.generate()
        # origin -> (size, root_b64) last cosigned
        self._seen: dict[str, tuple[int, str]] = {}
        # injectable clock returning a posix int (tests pin it; default real time)
        self._clock = clock

    def public_key_hex(self) -> str:
        return self._key.public_key_hex()

    def _now(self) -> int:
        if self._clock is not None:
            return self._clock()
        from datetime import UTC, datetime
        return int(datetime.now(UTC).timestamp())

    def cosign(self, signed_note: str, consistency_proof: list[str] | None) -> str:
        """Return a cosignature line for the checkpoint, or raise on an inconsistent extension."""
        parsed = tlog.parse_signed_note(signed_note)
        body = parsed["body"]
        lines = body.split("\n")
        origin, size_s, root_b64 = lines[0], lines[1], lines[2]
        size = int(size_s)
        prev = self._seen.get(origin)
        if prev is not None:
            prev_size, prev_root = prev
            if size < prev_size:
                raise WitnessRollbackError(
                    f"checkpoint size {size} is below last cosigned {prev_size} for {origin}")
            if size > prev_size:
                if not tlog.verify_consistency(prev_size, prev_root, size, root_b64,
                                               consistency_proof or []):
                    raise WitnessError(
                        f"checkpoint at {size} is not a consistent extension of {prev_size}")
            elif root_b64 != prev_root:
                # Same size, different root: the sink equivocated. Never cosign.
                raise WitnessError(f"equivocation at size {size} for {origin}")
        line = tlog.make_cosignature_line(body, self._key, self.name, self._now())
        self._seen[origin] = (size, root_b64)
        return line

    def last_cosigned_size(self, origin: str) -> int:
        prev = self._seen.get(origin)
        return 0 if prev is None else prev[0]


class WitnessClient:
    """C2SP tlog-witness HTTP client. `http` is any object with a .post(url, content, headers).

    The 409 path is the security-critical branch: a witness that already holds a later size
    returns it so the sink can supply the right consistency proof. We never trust that size
    blindly: it must lie within [our last recorded size for this witness, our current tree
    size]. Below that range is a rollback; above it is a split-view signal (the witness saw a
    head we never produced)."""

    def __init__(self, url: str, pubkey_hex: str, name: str, store=None, http=None,
                 timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.pubkey_hex = pubkey_hex
        self.name = name
        self._store = store
        self._http = http
        self.timeout = timeout

    def _post(self, content: bytes):
        if self._http is not None:
            return self._http.post(self.url + "/add-checkpoint", content=content,
                                   headers={"Content-Type": "text/plain"})
        import httpx
        return httpx.post(self.url + "/add-checkpoint", content=content,
                          headers={"Content-Type": "text/plain"}, timeout=self.timeout)

    @staticmethod
    def _build_body(old_size: int, consistency_proof: list[str], signed_note: str) -> bytes:
        head = f"old {old_size}\n" + "".join(h + "\n" for h in consistency_proof) + "\n"
        return head.encode("utf-8") + signed_note.encode("utf-8")

    def cosign(self, origin: str, old_size: int, consistency_proof: list[str],
               signed_note: str, current_size: int) -> str | None:
        """Submit the checkpoint, return a cosignature line, or None if no progress was made.

        Raises WitnessRollbackError / WitnessSplitViewAlert on a dangerous 409 size."""
        resp = self._post(self._build_body(old_size, consistency_proof, signed_note))
        code = resp.status_code
        if code == 200:
            line = resp.text if resp.text.startswith("\u2014") else resp.text.strip()
            return line if line else None
        if code == 409:
            stored = self._parse_stored_size(resp)
            last = self._store.get_tlog_witness_state(self.url, origin) if self._store else 0
            if stored < last:
                raise WitnessRollbackError(
                    f"witness {self.name} reports size {stored} below last cosigned {last}")
            if stored > current_size:
                raise WitnessSplitViewAlert(
                    f"witness {self.name} reports size {stored} above our tree {current_size}")
            return None  # caller resupplies a consistency proof from `stored`
        raise WitnessError(f"witness {self.name} rejected checkpoint with status {code}")

    @staticmethod
    def _parse_stored_size(resp) -> int:
        # C2SP returns the witness's known tree size; accept a header or a "size N" body line.
        hdr = resp.headers.get("X-Tree-Size") if hasattr(resp, "headers") else None
        if hdr is not None:
            try:
                return int(hdr)
            except ValueError:
                pass
        for ln in (getattr(resp, "text", "") or "").splitlines():
            if ln.lower().startswith("size "):
                try:
                    return int(ln.split(" ", 1)[1])
                except ValueError:
                    pass
        return 0


class WitnessStore:
    """Durable state for a standalone witness: its signing key and, per log origin, the last
    (size, root) it cosigned. A witness MUST persist this: its whole job is to remember what it
    has already signed so it can refuse a fork or a rollback. A witness that forgot its history
    on restart would happily cosign an equivocating head and provide no protection."""

    def __init__(self, path: str = ":memory:"):
        import sqlite3
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS witness_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS witness_seen ("
            "  origin TEXT PRIMARY KEY, size INTEGER NOT NULL, root TEXT NOT NULL);"
        )
        self._db.commit()

    def get_key_pem(self) -> str | None:
        row = self._db.execute("SELECT v FROM witness_meta WHERE k='key_pem'").fetchone()
        return None if row is None else row["v"]

    def set_key_pem(self, pem: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO witness_meta(k, v) VALUES ('key_pem', ?)", (pem,))
        self._db.commit()

    def load_seen(self) -> dict[str, tuple[int, str]]:
        out: dict[str, tuple[int, str]] = {}
        for row in self._db.execute("SELECT origin, size, root FROM witness_seen"):
            out[row["origin"]] = (row["size"], row["root"])
        return out

    def save_seen(self, origin: str, size: int, root: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO witness_seen(origin, size, root) VALUES (?,?,?)",
                         (origin, size, root))
        self._db.commit()


class PersistentWitness(LocalWitness):
    """A LocalWitness whose key and per-origin seen-state survive restarts (WitnessStore).

    Optionally pinned to the log public keys it witnesses (origin -> pubkey hex). When pinned,
    it verifies the checkpoint really is signed by that log before cosigning, so it cannot be
    tricked into cosigning a note it cannot attribute. An UNPINNED witness accepts any note and
    therefore provides no real protection; production witnesses MUST pin their logs."""

    def __init__(self, name: str, store: WitnessStore, log_keys: dict[str, str] | None = None,
                 clock=None):
        from ..keys import SigningKey
        pem = store.get_key_pem()
        if pem is None:
            key = SigningKey.generate()
            store.set_key_pem(key.to_pem())
        else:
            key = SigningKey.from_pem(pem)
        super().__init__(name, signing_key=key, clock=clock)
        self._store = store
        self._seen = store.load_seen()
        self.log_keys = log_keys or {}

    def cosign(self, signed_note: str, consistency_proof: list[str] | None) -> str:
        parsed = tlog.parse_signed_note(signed_note)
        origin = parsed["body"].split("\n", 1)[0]
        if self.log_keys:
            pub = self.log_keys.get(origin)
            if pub is None:
                raise WitnessError(f"witness does not witness log origin {origin!r}")
            ok = any(s["key_name"] == origin
                     and tlog.verify_log_signature(parsed["body"], s["payload"], pub, origin) == "ok"
                     for s in parsed["signatures"])
            if not ok:
                raise WitnessError(f"checkpoint is not validly signed by log {origin!r}")
        line = super().cosign(signed_note, consistency_proof)
        size, root = self._seen[origin]  # super().cosign updated this on success
        self._store.save_seen(origin, size, root)
        return line


class RemoteWitness:
    """Adapter that makes an out-of-process C2SP witness usable wherever the sink expects an
    in-process witness (collect_cosignatures calls `.cosign(signed_note, proof)`).

    It talks HTTP via the witness server, persists the last size it got cosigned for each origin
    in the sink store, and regenerates the consistency proof from the sink's own leaf hashes, so
    a witness that fell behind is re-synced from its true position rather than trusted blindly.
    This is what lets a hosted sink deliver the witnessed (green) path against a witness running
    on independent infrastructure."""

    def __init__(self, url: str, pubkey_hex: str, name: str, store, http=None,
                 timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.name = name
        self.pubkey_hex = pubkey_hex
        self._store = store
        self._client = WitnessClient(self.url, pubkey_hex, name, store=store, http=http,
                                     timeout=timeout)

    def public_key_hex(self) -> str:
        return self.pubkey_hex

    def _proof(self, origin: str, old: int, size: int) -> list[str]:
        if old <= 0 or old >= size:
            return []
        leaves = self._store.get_tlog_leaf_hashes(origin)[:size]
        return tlog.make_consistency_proof(old, size, leaves)

    def cosign(self, signed_note: str, consistency_proof: list[str] | None) -> str | None:
        parsed = tlog.parse_signed_note(signed_note)
        lines = parsed["body"].split("\n")
        origin, size = lines[0], int(lines[1])
        old = self._store.get_tlog_witness_state(self.url, origin)
        resp = self._client._post(
            WitnessClient._build_body(old, self._proof(origin, old, size), signed_note))
        if resp.status_code == 200:
            line = resp.text if resp.text.startswith("\u2014") else resp.text.strip()
            if line:
                self._store.update_tlog_witness_state(self.url, origin, size)
            return line or None
        if resp.status_code == 409:
            wsize = WitnessClient._parse_stored_size(resp)
            if wsize < old:
                raise WitnessRollbackError(
                    f"witness {self.name} reports size {wsize} below last cosigned {old}")
            if wsize > size:
                raise WitnessSplitViewAlert(
                    f"witness {self.name} reports size {wsize} above our tree {size}")
            # The witness is at a known size between old and current; resupply a proof from there.
            resp2 = self._client._post(
                WitnessClient._build_body(wsize, self._proof(origin, wsize, size), signed_note))
            if resp2.status_code == 200 and resp2.text.strip():
                line = resp2.text if resp2.text.startswith("\u2014") else resp2.text.strip()
                self._store.update_tlog_witness_state(self.url, origin, size)
                return line
            return None
        raise WitnessError(f"witness {self.name} rejected checkpoint with status {resp.status_code}")


def create_witness_app(witness):
    """A standalone C2SP tlog-witness HTTP server exposing POST /add-checkpoint.

    This is the real, out-of-process witness a hosted deployment runs on infrastructure
    independent of the sink, so the witnessed (green) path is available to customers who do
    not run their own witness. The endpoint speaks the C2SP add-checkpoint protocol that the
    sink's WitnessClient already talks, including the 409 known-size reconciliation."""
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse, Response

    app = FastAPI(title="Provenrail Witness", version="0.1.0")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/witness")
    def info():
        return {"name": witness.name, "pubkey": witness.public_key_hex(),
                "witnesses": sorted(getattr(witness, "log_keys", {}) or {})}

    @app.post("/add-checkpoint")
    async def add_checkpoint(request: Request):
        raw = await request.body()
        try:
            old_size, proof, note = _parse_add_checkpoint(raw)
        except Exception:
            return PlainTextResponse("malformed add-checkpoint request", status_code=400)
        origin = tlog.parse_signed_note(note)["body"].split("\n", 1)[0]
        stored = witness.last_cosigned_size(origin)
        if old_size != stored:
            # C2SP: the submitter's idea of our size is stale; tell it our size so it can
            # resupply a consistency proof from there.
            return Response(f"size {stored}\n", status_code=409,
                            headers={"X-Tree-Size": str(stored)}, media_type="text/plain")
        try:
            line = witness.cosign(note, proof)
        except WitnessError as e:
            return PlainTextResponse(f"cosign refused: {e}", status_code=409,
                                     headers={"X-Tree-Size": str(witness.last_cosigned_size(origin))})
        return PlainTextResponse(line, status_code=200)

    return app


def _parse_add_checkpoint(raw: bytes) -> tuple[int, list[str], str]:
    """Parse a C2SP add-checkpoint body: 'old N', proof hashes, a blank line, then the note."""
    text = raw.decode("utf-8")
    lines = text.split("\n")
    if not lines[0].startswith("old "):
        raise ValueError("missing 'old <size>' line")
    old_size = int(lines[0][4:].strip())
    proof: list[str] = []
    i = 1
    while i < len(lines) and lines[i] != "":
        proof.append(lines[i])
        i += 1
    i += 1  # skip the blank separator
    note = "\n".join(lines[i:])
    return old_size, proof, note


def collect_cosignatures(witnesses: list, signed_note: str, consistency_proof: list[str] | None,
                         body: str) -> tuple[str, int]:
    """Gather cosignatures from in-process witnesses, appending each line to the note.

    Returns (note_with_cosignatures, count). A witness that raises is skipped (its failure
    must not block the others), except that rollback / split-view alarms are surfaced by the
    caller via the witness raising; here we count only successful cosignatures."""
    note = signed_note
    count = 0
    for w in witnesses:
        try:
            line = w.cosign(signed_note, consistency_proof)
        except WitnessError:
            continue
        if line:
            note += line
            count += 1
    return note, count
