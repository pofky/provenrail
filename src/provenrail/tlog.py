"""Transparency log: a second-level append-only Merkle log over anchor receipts.

The per-stream anchor (anchor.py) bounds a stream's tamper window with an RFC 3161
timestamp. This module adds the layer above it: one account-wide append-only log whose
leaves are commitments to those anchor receipts. Its job is to make a dishonest sink
unable to equivocate (show one anchor history to a customer and a different one to a
regulator) or to silently drop anchors that were already published, WITHOUT the
customer having to trust us. That property comes from two RFC 6962 proofs an offline
verifier recomputes (inclusion = the anchor is in the log; consistency = the log only
ever grew) plus independent witness cosignatures on the log head (witness.py / Step 4).

Threat-model note (honesty discipline): witnessing moves a checkpoint from amber toward
green, it never confers completeness. A checkpoint with no witness cosignature is amber,
not green. See SPEC.md section 9.8 for the normative non-guarantees.

Wire formats are the C2SP transparency-log specs (tlog-checkpoint, signed-note,
tlog-cosignature) adopted verbatim so the log interoperates with the existing witness
ecosystem; only the leaf content diverges (it commits to an anchor receipt, not an
artifact signature). All Merkle math is RFC 6962 with the standard 0x00 leaf / 0x01 node
domain separation, reusing the node hash from anchor.py.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any

from .anchor import _node  # RFC 6962 internal node hash: SHA-256(0x01 || left || right)
from .canonical import canonicalize
from .keys import verify_signature

# Domain-separation label mixed into the tlog leaf so a tlog leaf hash can never collide
# with a per-stream anchor Merkle leaf hash, even though both use the RFC 6962 0x00 prefix.
# (SPEC.md 9.1; closes the leaf-confusion / receipt-substitution attack from the crypto review.)
LEAF_DOMAIN = b"flightrecorder.io/v1/tlog-leaf:"

# RFC 6962 empty-tree Merkle Tree Hash is SHA-256 of the empty string, never 64 zeros.
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()

DEFAULT_ORIGIN_PREFIX = "flightrecorder.io/v1/anchors"

# C2SP signed-note algorithm identifiers.
_ALG_ED25519 = 0x01           # plain Ed25519 note signature (the log key)
_ALG_COSIGNATURE_V1 = 0x04    # timestamped Ed25519 cosignature (a witness)

# C2SP signed-note signature lines begin with U+2014 then a space. Written as an escape
# (not the literal glyph) so the protocol byte is exact and the repo stays glyph-free.
_EM_DASH = "\u2014"


# --------------------------------------------------------------------------------------
# Leaf and Merkle tree (RFC 6962)
# --------------------------------------------------------------------------------------

def compute_anchor_commit(stream_id: str, anchor_seq: int, covers_up_to: int,
                          merkle_root: str, gen_time: str, kind: str,
                          token_b64_or_sig: str) -> bytes:
    """Commit to the full anchor receipt, not just its Merkle root.

    Binding stream_id/anchor_seq/covers_up_to and the RFC 3161 token bytes (or local
    signature) into the leaf means a witness cosignature vouches for the specific receipt
    a verifier later checks, so a sink cannot swap one valid receipt for another at the
    same tree position (the receipt-substitution attack)."""
    return hashlib.sha256(canonicalize({
        "stream_id": stream_id,
        "anchor_seq": anchor_seq,
        "covers_up_to": covers_up_to,
        "merkle_root": merkle_root,
        "gen_time": gen_time,
        "kind": kind,
        "token_b64_or_sig": token_b64_or_sig,
    })).digest()


def compute_leaf_hash(anchor_commit: bytes) -> str:
    """RFC 6962 leaf hash with the tlog domain label: SHA-256(0x00 || LEAF_DOMAIN || commit)."""
    return hashlib.sha256(b"\x00" + LEAF_DOMAIN + anchor_commit).hexdigest()


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly less than n (n > 1). RFC 6962 split point k."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash over a list of already-computed leaf hashes (RFC 6962 sec 2.1)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_root_from_leaf_hashes(leaf_hashes_hex: list[str]) -> str:
    """Root over already-hashed leaves (the values from compute_leaf_hash). Hex."""
    if not leaf_hashes_hex:
        return EMPTY_ROOT
    return _mth([bytes.fromhex(h) for h in leaf_hashes_hex]).hex()


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 PATH(m, D[n]) inclusion proof for leaf index m (sec 2.1.1)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    """RFC 6962 SUBPROOF(m, D[n], b) (sec 2.1.2)."""
    n = len(leaves)
    if m == n:
        return [] if b else [_mth(leaves)]
    k = _largest_pow2_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def make_inclusion_proof(leaf_index: int, leaf_hashes_hex: list[str]) -> list[str]:
    """Inclusion proof siblings (leaf-to-root), base64-encoded 32-byte hashes."""
    proof = _path(leaf_index, [bytes.fromhex(h) for h in leaf_hashes_hex])
    return [base64.b64encode(p).decode("ascii") for p in proof]


def make_consistency_proof(old_size: int, new_size: int, leaf_hashes_hex: list[str]) -> list[str]:
    """Consistency proof PROOF(old_size, new_size), base64-encoded hashes."""
    if old_size == 0 or old_size == new_size:
        return []
    proof = _subproof(old_size, [bytes.fromhex(h) for h in leaf_hashes_hex], True)
    return [base64.b64encode(p).decode("ascii") for p in proof]


def verify_inclusion(anchor_commit_hex: str, leaf_index: int, tree_size: int,
                     proof_b64: list[str], root_b64: str) -> bool:
    """Recompute the root from leaf + proof and compare (RFC 6962 sec 2.1.1, iterative).

    Independent of make_inclusion_proof: the generator uses the recursive PATH spec, this
    uses the iterative verification spec, so the conformance tests cross-check both."""
    try:
        leaf = bytes.fromhex(compute_leaf_hash(bytes.fromhex(anchor_commit_hex)))
        proof = [base64.b64decode(p) for p in proof_b64]
        root = base64.b64decode(root_b64)
    except Exception:
        return False
    if leaf_index < 0 or tree_size < 0 or leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = leaf
    for p in proof:
        if len(p) != 32:
            return False
        if (fn & 1) or (fn == sn):
            r = _node(p, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _is_pow2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def verify_consistency(old_size: int, old_root_b64: str, new_size: int,
                       new_root_b64: str, proof_b64: list[str]) -> bool:
    """Verify the new tree is an append-only extension of the old (RFC 6962 sec 2.1.2)."""
    try:
        old_root = base64.b64decode(old_root_b64)
        new_root = base64.b64decode(new_root_b64)
        proof = [base64.b64decode(p) for p in proof_b64]
    except Exception:
        return False
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0
    if old_size == 0:
        return len(proof) == 0  # every tree is consistent with the empty tree
    if any(len(p) != 32 for p in proof):
        return False
    # If old_size is an exact power of two, old_root is the first node and is not sent.
    if _is_pow2(old_size):
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


# --------------------------------------------------------------------------------------
# Checkpoint (C2SP tlog-checkpoint) and signed note (C2SP signed-note)
# --------------------------------------------------------------------------------------

def build_checkpoint(origin: str, tree_size: int, root_hex: str) -> str:
    """The three-line checkpoint body: origin, decimal size, base64 root, each \\n-terminated."""
    root_b64 = base64.b64encode(bytes.fromhex(root_hex)).decode("ascii")
    return f"{origin}\n{tree_size}\n{root_b64}\n"


def key_id(key_name: str, pubkey: bytes, alg: int = _ALG_ED25519) -> bytes:
    """C2SP signed-note key id: SHA-256(name || 0x0A || alg || pubkey)[:4]."""
    return hashlib.sha256(key_name.encode("utf-8") + b"\n" + bytes([alg]) + pubkey).digest()[:4]


def sign_checkpoint(body: str, signing_key, key_name: str) -> str:
    """Wrap a checkpoint body in a signed note carrying one Ed25519 log-key signature.

    signing_key is a keys.SigningKey. The signature is over the body bytes (type 0x01)."""
    pubkey = bytes.fromhex(signing_key.public_key_hex())
    sig = bytes.fromhex(signing_key.sign(body.encode("utf-8")))
    blob = base64.b64encode(key_id(key_name, pubkey) + sig).decode("ascii")
    return f"{body}\n{_EM_DASH} {key_name} {blob}\n"


def cosignature_message(body: str, posix_ts: int) -> bytes:
    """The exact bytes a witness signs for a timestamped cosignature (C2SP cosignature/v1)."""
    return b"cosignature/v1\ntime " + str(posix_ts).encode("ascii") + b"\n" + body.encode("utf-8")


def make_cosignature_line(body: str, witness_key, witness_name: str, posix_ts: int) -> str:
    """Produce a witness cosignature signature line (used by tests and the local witness)."""
    pubkey = bytes.fromhex(witness_key.public_key_hex())
    sig = bytes.fromhex(witness_key.sign(cosignature_message(body, posix_ts)))
    payload = key_id(witness_name, pubkey, _ALG_COSIGNATURE_V1) + struct.pack(">Q", posix_ts) + sig
    blob = base64.b64encode(payload).decode("ascii")
    return f"{_EM_DASH} {witness_name} {blob}\n"


def parse_signed_note(note_text: str) -> dict[str, Any]:
    """Split a signed note into its body and signature lines.

    Returns {body, signatures: [{key_name, key_id, payload}]}. key_name is the primary
    identifier (a verifier looks up the pubkey by name, then checks key_id agrees); this
    prevents a crafted key_id collision from being confused for a known signer."""
    # A signed note is <body ending in \n><blank line><signature lines>. The signature
    # block is the trailing run of lines that begin with the em-dash marker; the body is
    # everything before the single blank separator line preceding that block.
    raw_lines = (note_text[:-1] if note_text.endswith("\n") else note_text).split("\n")
    i = len(raw_lines)
    while i > 0 and raw_lines[i - 1].startswith(_EM_DASH + " "):
        i -= 1
    sig_lines = raw_lines[i:]
    body_lines = raw_lines[:i]
    if not sig_lines:
        return {"body": note_text, "signatures": []}
    if body_lines and body_lines[-1] == "":
        body_lines = body_lines[:-1]  # drop the blank separator line
    body = "\n".join(body_lines) + "\n"
    sigs = []
    for line in sig_lines:
        rest = line[len(_EM_DASH) + 1:]
        sp = rest.rfind(" ")
        if sp < 0:
            continue
        name = rest[:sp]
        try:
            payload = base64.b64decode(rest[sp + 1:])
        except Exception:
            continue
        if len(payload) < 4:
            continue
        sigs.append({"key_name": name, "key_id": payload[:4], "payload": payload})
    return {"body": body, "signatures": sigs}


def verify_log_signature(body: str, payload: bytes, pubkey_hex: str, key_name: str) -> str:
    """Verify a log-key signature line. Returns 'ok', 'key_id_mismatch', or 'bad_sig'."""
    pubkey = bytes.fromhex(pubkey_hex)
    expected_id = key_id(key_name, pubkey, _ALG_ED25519)
    if payload[:4] != expected_id:
        return "key_id_mismatch"
    sig = payload[4:]
    if len(sig) != 64 or not verify_signature(pubkey_hex, body.encode("utf-8"), sig.hex()):
        return "bad_sig"
    return "ok"


def verify_cosignature(payload: bytes, pubkey_hex: str, body: str,
                       key_name: str) -> tuple[bool, int]:
    """Verify a witness cosignature payload (key_id || 8-byte ts || 64-byte sig).

    Returns (valid, posix_ts). valid is True only if the key_id matches the looked-up
    pubkey AND the Ed25519 signature over the cosignature/v1 message verifies."""
    if len(payload) != 4 + 8 + 64:
        return False, 0
    pubkey = bytes.fromhex(pubkey_hex)
    if payload[:4] != key_id(key_name, pubkey, _ALG_COSIGNATURE_V1):
        return False, 0
    posix_ts = struct.unpack(">Q", payload[4:12])[0]
    sig = payload[12:]
    msg = cosignature_message(body, posix_ts)
    return verify_signature(pubkey_hex, msg, sig.hex()), posix_ts
