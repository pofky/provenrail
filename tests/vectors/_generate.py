"""Generate the frozen conformance vectors.

Run once to (re)produce the golden bundles under tests/vectors/ and their manifest. The vectors
are committed and treated as frozen: tests/test_conformance.py reads them and asserts the verifier
reaches the recorded verdict, so any drift in verification behavior is caught. Third parties
building an independent verifier can run their implementation against the same bundles + manifest.

Mutations are derived from a single clean bundle so each tampered vector differs from clean by
exactly one well-understood edit, mapping to one defining failure.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from provenrail.anchor import LocalAnchor
from provenrail.ingest_client import provision_stream
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app
from provenrail.verifier.verify import verify_bundle

HERE = Path(__file__).parent


def _clean_bundle() -> dict:
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)

    @fr.tool("web_search")
    def web_search(q):
        return {"hits": 2}

    with fr.session({"agent": "conformance", "task": "golden vector"}):
        fr.record_model_call("anthropic", "claude-opus-4-8",
                             request={"prompt": "summarize X"}, response={"text": "ok"},
                             usage={"input": "120", "output": "40"})
        web_search("what is X")
        fr.record_human_oversight("approved", approver="auditor@example.com")
        fr.record_decision("answer grounded; returning")
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


def _multi_session_bundle() -> dict:
    """A stream reused across three runs (the quickstart shape): three sessions, one shared
    device key, one continuous server receipt chain. Must verify clean."""
    from provenrail.keys import SigningKey
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    key = SigningKey.generate()
    for note in ("run one", "run two", "run three"):
        fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c, key=key)
        with fr.session({"agent": "conformance", "task": "multi-session vector"}):
            fr.record_decision(note)
        fr.close()
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    return c.get(f"/v1/streams/{prov['stream_id']}/export",
                 headers={"Authorization": f"Bearer {prov['read_token']}"}).json()


def _mut_tamper_payload(b: dict) -> dict:
    b = copy.deepcopy(b)
    for sr in b["records"]:
        rec = sr["record"]
        if rec.get("action_type") == "decision":
            rec["payload"]["summary"] = "TAMPERED after the fact"  # hash no longer matches
            break
    return b


def _mut_delete_record(b: dict) -> dict:
    b = copy.deepcopy(b)
    mid = len(b["records"]) // 2
    del b["records"][mid]  # leaves a recv_seq gap
    return b


def _mut_reorder(b: dict) -> dict:
    b = copy.deepcopy(b)
    i = len(b["records"]) // 2
    b["records"][i], b["records"][i + 1] = b["records"][i + 1], b["records"][i]
    return b


def _mut_bad_sig(b: dict) -> dict:
    b = copy.deepcopy(b)
    rec = b["records"][2]["record"]
    sig = rec["record_sig"]
    rec["record_sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]  # corrupt one nibble
    return b


def _mut_strip_anchor(b: dict) -> dict:
    b = copy.deepcopy(b)
    b["anchors"] = []  # valid records, just no external time binding (weaker, not tampered)
    return b


# A second source bundle that exercises the full spec: an independent witness cosignature on
# the transparency-log checkpoint, a SCITT COSE receipt per anchor, and a selective-disclosure
# redactable field. Verifying these requires context (the log key, the witness key, a fixed
# clock, and the disclosure openings), so the manifest entries carry a `verify` block. The
# witness and verification time are pinned so the vectors are deterministic.
_WITNESS_CLOCK = 1_900_000_000
_NOW_UTC = "2030-03-17T18:20:00.000000Z"  # ~ _WITNESS_CLOCK + 50000s, within cosig max age


def _rich_source() -> dict:
    import provenrail as prmod
    from provenrail.server.witness import LocalWitness

    witness = LocalWitness("witness-A", clock=lambda: _WITNESS_CLOCK)
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False,
                     tlog_witnesses=[witness])
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session({"agent": "conformance", "task": "rich golden vector"}):
        fr.record_decision("ship it", note=prmod.redactable("SSN 078-05-1120"))
    c.post(f"/v1/streams/{prov['stream_id']}/anchor",
           headers={"Authorization": f"Bearer {prov['read_token']}"})
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle").json()
    meta = c.get("/v1/meta").json()
    return {
        "bundle": bundle,
        "tlog_log_key": meta["tlog_pubkey"],
        "witness_pubkeys": {"witness-A": witness.public_key_hex()},
        "openings": fr.openings(),
    }


def _mut_scitt_forged(b: dict) -> dict:
    import base64
    b = copy.deepcopy(b)
    raw = bytearray(base64.b64decode(b["anchors"][0]["scitt_receipt"]))
    raw[-1] ^= 0x01  # flip the last byte of the COSE_Sign1 signature
    b["anchors"][0]["scitt_receipt"] = base64.b64encode(bytes(raw)).decode()
    return b


# Each entry: (mutation, the portable expect_ok contract, one defining code a conformant
# verifier should surface, and a human description). expect_ok is the interoperable guarantee
# every verifier must agree on; defining_code is the canonical signal (our verifier always emits
# it; a third-party verifier SHOULD).
MUTATIONS = {
    "clean": (lambda b: copy.deepcopy(b), True, None,
              "an untampered, anchored run; verifies clean"),
    "tamper_payload": (_mut_tamper_payload, False, "client_hash_mismatch",
                       "a record payload edited after signing; the record hash no longer matches"),
    "delete_record": (_mut_delete_record, False, "server_chain_break",
                      "a record removed mid-stream; the server receipt chain breaks"),
    "reorder": (_mut_reorder, False, "arrival_reorder",
                "two records swapped; arrival order no longer matches emission order"),
    "bad_signature": (_mut_bad_sig, False, "client_bad_signature",
                      "a record signature corrupted; the device-key signature fails"),
    "strip_anchor": (_mut_strip_anchor, True, "no_anchor",
                     "valid records with no external anchor; weaker, not tampered"),
}


def _verify_kwargs(ctx: dict | None) -> dict:
    """Map a vector's `verify` block to verify_bundle keyword arguments."""
    if not ctx:
        return {}
    return {
        "tlog_log_key": ctx.get("tlog_log_key"),
        "witness_pubkeys": ctx.get("witness_pubkeys") or {},
        "now_utc": ctx.get("now_utc"),
        "disclosure_openings": ctx.get("openings"),
    }


def main() -> None:
    clean = _clean_bundle()
    manifest: dict[str, dict] = {}

    # 1. Base-chain vectors (no verification context needed).
    for name, (mut, expect_ok, defining, desc) in MUTATIONS.items():
        bundle = mut(clean)
        (HERE / f"{name}.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        rep = verify_bundle(bundle).to_dict()
        assert rep["ok"] == expect_ok, f"{name}: verifier ok={rep['ok']} expected {expect_ok}"
        codes = {f["code"] for f in rep["findings"]}
        if defining is not None:
            assert defining in codes, f"{name}: expected defining code {defining}, got {sorted(codes)}"
        manifest[name] = {"file": f"{name}.json", "expect_ok": expect_ok,
                          "defining_code": defining, "description": desc}

    # 1.5. Multi-session vector: stream reuse across runs is the normal quickstart shape;
    # a verifier that assumes one session per stream wrongly flags it as tampered.
    ms = _multi_session_bundle()
    (HERE / "multi_session.json").write_text(json.dumps(ms, indent=2), encoding="utf-8")
    rep = verify_bundle(ms).to_dict()
    assert rep["ok"], f"multi_session: {[f for f in rep['findings'] if f['severity'] == 'fail']}"
    manifest["multi_session"] = {
        "file": "multi_session.json", "expect_ok": True, "defining_code": None,
        "description": "three sealed sessions on one reused stream, one device key; verifies clean"}

    # 2. Full-spec vectors (witnessed tlog + SCITT receipt + selective-disclosure redaction).
    rich = _rich_source()
    src, log_key = rich["bundle"], rich["tlog_log_key"]
    witnesses, openings = rich["witness_pubkeys"], rich["openings"]
    tlog_ctx = {"tlog_log_key": log_key, "witness_pubkeys": witnesses, "now_utc": _NOW_UTC}
    forged_openings = {c: {**o, "value": "WRONG"} for c, o in openings.items()}

    # (file, mutation, verify-ctx, expect_ok, defining_code, description)
    rich_vectors = [
        ("rich_witnessed.json", lambda b: copy.deepcopy(b), tlog_ctx, True,
         "tlog_inclusion_witnessed_ok",
         "tlog inclusion proof cosigned by an independent witness; verifies green"),
        ("scitt_valid.json", lambda b: copy.deepcopy(b), tlog_ctx, True,
         "scitt_receipt_ok",
         "a SCITT COSE receipt that verifies against the transparency-service key"),
        ("scitt_forged.json", _mut_scitt_forged, tlog_ctx, False,
         "scitt_receipt_invalid",
         "a SCITT receipt whose COSE signature was altered; hard fail"),
        ("redacted.json", lambda b: copy.deepcopy(b),
         {**tlog_ctx, "openings": openings}, True, "redaction_summary",
         "a redactable field disclosed with valid openings; commitments recompute"),
        ("redacted.json", lambda b: copy.deepcopy(b),
         {**tlog_ctx, "openings": forged_openings}, False, "redaction_disclosure_invalid",
         "a redactable field with a forged opening; the commitment does not match"),
    ]
    entry_names = ["tlog_witnessed", "scitt_valid", "scitt_forged",
                   "redacted_disclosed", "redacted_forged"]
    written: set[str] = set()
    for entry_name, vec in zip(entry_names, rich_vectors, strict=True):
        fname, mut, ctx, expect_ok, defining, desc = vec
        bundle = mut(src)
        if fname not in written:
            (HERE / fname).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            written.add(fname)
        rep = verify_bundle(bundle, **_verify_kwargs(ctx)).to_dict()
        assert rep["ok"] == expect_ok, f"{entry_name}: ok={rep['ok']} expected {expect_ok}"
        codes = {f["code"] for f in rep["findings"]}
        assert defining in codes, f"{entry_name}: expected {defining}, got {sorted(codes)}"
        manifest[entry_name] = {"file": fname, "expect_ok": expect_ok,
                                "defining_code": defining, "description": desc, "verify": ctx}

    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("wrote vectors:", ", ".join(manifest))
    for k, v in manifest.items():
        print(f"  {k}: ok={v['expect_ok']} defining={v['defining_code']}")


if __name__ == "__main__":
    main()
