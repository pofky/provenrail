"""SCITT-aligned COSE receipts over the Provenrail transparency log.

A Provenrail SCITT receipt is a COSE_Sign1 (RFC 9052) signed by the Transparency Service
(the same Ed25519 log/identity key that signs tlog checkpoints) asserting that a given
anchor-commit leaf is included, at a given leaf index, in an append-only RFC 6962 Merkle log
whose signed tree head (root) at `tree_size` is the COSE payload. Anyone can verify it offline
with just the receipt, the anchor commit, and the TS public key:

  1. verify the COSE_Sign1 EdDSA signature over Sig_structure(protected, payload=root);
  2. recompute the Merkle root from the leaf + the embedded inclusion proof (RFC 6962);
  3. confirm the recomputed root equals the signed payload.

This follows the structure of draft-ietf-scitt-architecture-22 (Transparency Service +
Receipt) and draft-ietf-cose-merkle-tree-proofs (the RFC9162_SHA256 verifiable data
structure, header label -111 = 1, inclusion proofs under unprotected label -222 / -1). It is
a faithful PROFILE of those in-progress IETF drafts, not a claim of conformance to a finished
RFC; the exact label and CBOR layout are frozen in SPEC.md section 18 so any SCITT-aware
implementer can verify a Provenrail receipt. The moat is standards alignment: a Provenrail
receipt is verifiable by the broader SCITT/COSE ecosystem, not only by our own verifier.
"""

from __future__ import annotations

import base64
from typing import Any

from . import cbor, tlog
from .keys import verify_signature

# COSE / SCITT label constants.
_COSE_ALG = 1            # protected header: algorithm
_COSE_KID = 4            # protected header: key id
_COSE_CWT_CLAIMS = 15    # protected header: CWT claims (iss=1, sub=2)
_ALG_EDDSA = -8          # COSE algorithm: EdDSA (Ed25519)
_VDS_LABEL = -111        # verifiable data structure type (draft-ietf-cose-merkle-tree-proofs)
_VDS_RFC9162_SHA256 = 1  # RFC 6962 SHA-256 Merkle tree
_PROOFS_LABEL = -222     # unprotected header: verifiable proofs
_INCLUSION_TYPE = -1     # inclusion proof type within the proofs map
_CWT_ISS = 1
_CWT_SUB = 2
_COSE_SIGN1_TAG = 18

DEFAULT_ISSUER = "provenrail.io"


def _kid_for(pubkey_hex: str) -> bytes:
    """A stable, informational key id for the TS key (raw 32-byte Ed25519 public key)."""
    return bytes.fromhex(pubkey_hex)


def build_receipt(signing_key, leaf_index: int, leaf_hashes_hex: list[str],
                  subject: str, issuer: str = DEFAULT_ISSUER) -> str:
    """Build a base64 COSE_Sign1 SCITT receipt for the leaf at `leaf_index`.

    signing_key is the TS keys.SigningKey (the tlog/identity key). leaf_hashes_hex is the full
    ordered list of tlog leaf hashes (defines the tree); the receipt commits to the current
    tree of size len(leaf_hashes_hex). `subject` identifies the statement (e.g. stream id)."""
    tree_size = len(leaf_hashes_hex)
    root_hex = tlog.merkle_root_from_leaf_hashes(leaf_hashes_hex)
    root = bytes.fromhex(root_hex)
    pubkey_hex = signing_key.public_key_hex()

    protected = {
        _COSE_ALG: _ALG_EDDSA,
        _COSE_KID: _kid_for(pubkey_hex),
        _VDS_LABEL: _VDS_RFC9162_SHA256,
        _COSE_CWT_CLAIMS: {_CWT_ISS: issuer, _CWT_SUB: subject},
    }
    protected_bstr = cbor.encode(protected)

    path_b64 = tlog.make_inclusion_proof(leaf_index, leaf_hashes_hex)
    path = [base64.b64decode(p) for p in path_b64]
    inclusion = cbor.encode([tree_size, leaf_index, path])
    unprotected = {_PROOFS_LABEL: {_INCLUSION_TYPE: [inclusion]}}

    sig_structure = cbor.encode(["Signature1", protected_bstr, b"", root])
    signature = bytes.fromhex(signing_key.sign(sig_structure))

    cose = cbor.CBORTag(_COSE_SIGN1_TAG, [protected_bstr, unprotected, root, signature])
    return base64.b64encode(cbor.encode(cose)).decode("ascii")


def verify_receipt(receipt_b64: str, anchor_commit_hex: str, ts_pubkey_hex: str) -> dict[str, Any]:
    """Verify a SCITT receipt offline. Returns a verdict dict; `ok` is the overall result.

    Checks: (1) it is a COSE_Sign1 with EdDSA + the RFC9162_SHA256 VDS; (2) the TS signature
    over the Sig_structure verifies against ts_pubkey_hex; (3) the embedded RFC 6962 inclusion
    proof recomputes the signed root for the given anchor commit."""
    verdict: dict[str, Any] = {
        "ok": False, "signature_ok": False, "inclusion_ok": False,
        # kid_match lets a caller tell "the verifier supplied the wrong TS key" (kid differs,
        # benign / wrong-log) apart from "the signature was forged under the right key"
        # (kid matches, signature fails = real tampering). None until the kid is read.
        "kid_match": None,
        "issuer": None, "subject": None, "tree_size": None, "leaf_index": None,
        "root_hex": None, "error": None,
    }
    try:
        cose = cbor.decode(base64.b64decode(receipt_b64))
        if not isinstance(cose, cbor.CBORTag) or cose.tag != _COSE_SIGN1_TAG:
            verdict["error"] = "not_cose_sign1"
            return verdict
        arr = cose.value
        if not isinstance(arr, list) or len(arr) != 4:
            verdict["error"] = "malformed_cose_sign1"
            return verdict
        protected_bstr, unprotected, payload, signature = arr
        protected = cbor.decode(protected_bstr)
        verdict["kid_match"] = protected.get(_COSE_KID) == _kid_for(ts_pubkey_hex)
        if protected.get(_COSE_ALG) != _ALG_EDDSA:
            verdict["error"] = "unexpected_alg"
            return verdict
        if protected.get(_VDS_LABEL) != _VDS_RFC9162_SHA256:
            verdict["error"] = "unexpected_vds"
            return verdict
        claims = protected.get(_COSE_CWT_CLAIMS, {}) or {}
        verdict["issuer"] = claims.get(_CWT_ISS)
        verdict["subject"] = claims.get(_CWT_SUB)
        if not isinstance(payload, bytes) or len(payload) != 32:
            verdict["error"] = "bad_payload"
            return verdict
        verdict["root_hex"] = payload.hex()

        sig_structure = cbor.encode(["Signature1", protected_bstr, b"", payload])
        verdict["signature_ok"] = bool(
            isinstance(signature, bytes)
            and verify_signature(ts_pubkey_hex, sig_structure, signature.hex())
        )

        proofs = (unprotected or {}).get(_PROOFS_LABEL, {}) or {}
        incl_list = proofs.get(_INCLUSION_TYPE) or []
        if not incl_list:
            verdict["error"] = "no_inclusion_proof"
            return verdict
        tree_size, leaf_index, path = cbor.decode(incl_list[0])
        verdict["tree_size"] = tree_size
        verdict["leaf_index"] = leaf_index
        proof_b64 = [base64.b64encode(p).decode("ascii") for p in path]
        root_b64 = base64.b64encode(payload).decode("ascii")
        verdict["inclusion_ok"] = bool(
            tlog.verify_inclusion(anchor_commit_hex, leaf_index, tree_size, proof_b64, root_b64)
        )
    except Exception as e:  # noqa: BLE001 - verification must never raise, only fail closed
        verdict["error"] = f"exception:{type(e).__name__}"
        return verdict

    verdict["ok"] = verdict["signature_ok"] and verdict["inclusion_ok"]
    return verdict
