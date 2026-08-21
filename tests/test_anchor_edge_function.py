"""The hosted anchor service must mint receipts the Python verifier accepts.

The service runs as a Supabase edge function on Deno, not as the Python server, because the whole
job is "receive 32 bytes, sign them, never lose them" and that fits the free tier. Two
implementations of one signature format is exactly the situation where they drift apart silently
and nobody notices until a customer's auditor cannot check a receipt.

So this holds them together at the only place it matters: a receipt minted by the Deno code must
verify under `verify_signature` and must satisfy `pr anchor-verify` against a real bundle.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from provenrail.keys import verify_signature

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
MINTER = HERE / "js" / "anchor_receipt.mjs"
EDGE_FN = ROOT / "supabase" / "functions" / "anchor" / "index.ts"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _seed_and_pub() -> tuple[str, str]:
    """A raw Ed25519 seed and its public key, in the hex the edge function expects."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw).hex()
    return seed, pub


def _mint(root: str) -> tuple[dict, str]:
    seed, pub = _seed_and_pub()
    res = subprocess.run(
        ["node", str(MINTER), json.dumps({"seed": seed, "pub": pub, "root": root})],
        capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(res.stdout), pub


def test_a_receipt_minted_in_deno_verifies_in_python():
    """The signature covers `${root}|${gen_time}`, hex-encoded, over a raw Ed25519 key. If either
    side changes that string, every receipt the service has ever issued stops verifying."""
    root = "ab" * 32
    receipt, pub = _mint(root)
    assert receipt["kind"] == "local"
    assert receipt["merkle_root"] == root
    assert receipt["anchor_pubkey"] == pub
    assert verify_signature(pub, f"{root}|{receipt['gen_time']}".encode(), receipt["signature"])


def test_the_timestamp_is_the_shape_python_writes():
    """Python's LocalAnchor formats gen_time with microseconds ("%Y-%m-%dT%H:%M:%S.%fZ"). The
    string is inside the signature, so a millisecond timestamp from Deno would still verify
    against itself and look wrong beside every receipt the Python server ever wrote."""
    receipt, _ = _mint("cd" * 32)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", receipt["gen_time"]), \
        receipt["gen_time"]

    from provenrail.anchor import LocalAnchor
    native = LocalAnchor().anchor_root("cd" * 32).gen_time
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", native)


def test_a_receipt_from_the_hosted_service_satisfies_anchor_verify(tmp_path, capsys):
    """End to end: a bundle produced by the real sink, a receipt minted by the Deno signer, and
    the auditor's offline command agreeing that the two describe the same history."""
    from test_anchor_only import _real_bundle

    from provenrail.anchor import merkle_root
    from provenrail.cli import main as cli_main

    bundle_path, bundle = _real_bundle(tmp_path)
    leaves = [r["server_record_hash"] for r in bundle["records"]]
    root = merkle_root(leaves)
    receipt, _ = _mint(root)

    envelope = {"anchor_id": "anc_hosted", "stream_id": bundle["stream_id"],
                "merkle_root": root, "covers_up_to": len(leaves), "receipt": receipt,
                "created_at": receipt["gen_time"]}
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")

    capsys.readouterr()
    assert cli_main(["anchor-verify", str(bundle_path), str(receipt_path)]) == 0
    assert "RESULT: VERIFIED" in capsys.readouterr().out


def test_the_deployed_function_signs_the_same_string_as_the_test_minter():
    """The minter above is a copy of the function's signing lines, because the function cannot be
    imported (it calls Deno.serve at module scope). A copy that drifts proves nothing, so the
    payload format is asserted against the real file."""
    src = EDGE_FN.read_text(encoding="utf-8")
    assert "`${root}|${genTime}`" in src, "the edge function no longer signs root|gen_time"
    assert '"302e020100300506032b657004220420"' in src, "PKCS8 Ed25519 prefix changed"
    assert 'iso.slice(0, -1) + "000Z"' in src, "gen_time is no longer microsecond-shaped"
    assert '"Ed25519"' in src


def test_the_edge_function_cannot_receive_a_record():
    """The privacy guarantee is structural: the handler reads exactly three fields off the body.
    A fourth would be the moment this service starts holding customer data, which is the line the
    operator cannot cross without a company."""
    src = EDGE_FN.read_text(encoding="utf-8")
    read_fields = set(re.findall(r"body\.([a-z_]+)", src))
    assert read_fields == {"stream_id", "merkle_root", "covers_up_to"}, read_fields


def test_the_edge_function_never_returns_the_account():
    """An anchor id is public. If the response carried account_id, handing an auditor a receipt
    would also hand them a customer identifier, and correlating two receipts would reveal that
    two streams belong to one company."""
    src = EDGE_FN.read_text(encoding="utf-8")
    # The public GET selects an explicit column list; account_id must not be in it.
    select = re.search(r'\.select\(\s*"([^"]*anchor_id[^"]*)"\s*\)', src)
    assert select, "could not find the public select"
    assert "account_id" not in select.group(1)
    # And both POST responses strip it rather than relying on it being absent.
    assert src.count("account_id: _") == 2, "a POST response no longer strips account_id"


def test_the_service_refuses_to_invent_a_signing_key():
    """A service that generated a key when the secret was missing would issue receipts that stop
    verifying after the next cold start, and the customer would find out when an auditor did."""
    src = EDGE_FN.read_text(encoding="utf-8")
    assert "ANCHOR_SIGNING_KEY must be 32 hex-encoded bytes" in src
    assert "generateKey" not in src


def test_coverage_rules_match_the_python_service_word_for_word():
    """Two implementations, one contract. A customer who hits the same refusal from the hosted
    service and from their own sink must be told the same thing, or one of the two is wrong and
    they cannot tell which."""
    # Whitespace-normalised: both sources wrap these sentences to fit their line length, and a
    # test that depends on where a line breaks fails on reflow rather than on drift.
    flat = lambda t: " ".join(t.split())  # noqa: E731
    src = flat(EDGE_FN.read_text(encoding="utf-8"))
    py = flat((ROOT / "src" / "provenrail" / "server" / "storage.py").read_text(encoding="utf-8"))
    for phrase in ("would drop the tail", "same prefix cannot have two histories"):
        assert phrase in src, f"edge function lost: {phrase}"
        assert phrase in py, f"python service lost: {phrase}"


def test_a_self_signed_receipt_can_never_wear_a_trusted_label():
    """The fallback is the dangerous part of this design.

    When the timestamp authority is unreachable the service still anchors, self-signed, because a
    customer's chain going unanchored during someone else's outage is the worse failure. That is
    only defensible while the weaker receipt is honestly labelled: `kind` must be "local", so
    every verifier warns that the time is self-asserted and the auditor page shows it amber.

    A fallback that produced kind "rfc3161" with no token would be a service telling an auditor a
    third party vouched for a date when none did, and nothing downstream would catch it.
    """
    src = " ".join(EDGE_FN.read_text(encoding="utf-8").split())
    # The rfc3161 label is set only where a token was actually obtained, inside the try.
    assert 'kind: "rfc3161", merkle_root: root, gen_time: genTime, token_b64: tokenB64' in src
    # ...and the catch hands back the self-signed receipt rather than patching a label on.
    catch = src[src.index("} catch (e) { console.error(\"trusted timestamp unavailable"):]
    assert "return await selfSigned(root);" in catch[:400], catch[:400]
    assert 'kind: "rfc3161"' not in catch[:400]
    # selfSigned is the only other producer, and it is local.
    assert 'kind: "local", merkle_root: root, gen_time: genTime, token_b64: null' in src


def test_the_service_prefers_a_third_party_timestamp():
    """The whole reason to send a root to someone else is to get a time you could not assert
    yourself. If the trusted path were ever reordered behind the self-signed one, every receipt
    would silently become the weaker kind and every test above would still pass."""
    src = " ".join(EDGE_FN.read_text(encoding="utf-8").split())
    body = src[src.index("async function mintReceipt"):]
    assert body.index("trustedTimestamp(") < body.index("selfSigned(root)"), \
        "the self-signed path is no longer the fallback"
    assert "AbortSignal.timeout(" in body, "a hanging authority would hang the anchor request"


@pytest.mark.skipif(shutil.which("deno") is None, reason="deno not installed")
def test_the_free_trial_anchor_gate_behaves():
    """The "one free anchor, ever" rule, driven against the real decision function.

    It is a rule about money rather than about hashes, which is the kind that gets written on a
    pricing page and never exercised: the failure mode is either a paying customer cut off after
    one anchor, or an unlimited free tier nobody notices until the abuse arrives. The cases live
    in tests/deno/anchor_gate_test.ts because the function they drive is TypeScript."""
    res = subprocess.run(
        ["deno", "test", "--allow-env", "--allow-net", "--allow-read",
         str(ROOT / "tests" / "deno" / "anchor_gate_test.ts")],
        capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.skipif(shutil.which("deno") is None, reason="deno not installed")
def test_the_edge_function_typechecks():
    """`supabase functions deploy` bundles without type-checking, so a function with a genuine
    type error deploys happily and fails at the first request that reaches the broken line. The
    tests above read the source as text and would not notice. This runs the compiler."""
    fns = ROOT / "supabase" / "functions"
    res = subprocess.run(
        ["deno", "check", str(EDGE_FN), str(fns / "anchor" / "account.ts"),
         str(fns / "trial-license" / "index.ts"), str(fns / "_shared" / "license-mint.ts"),
         str(fns / "polar-webhook" / "index.ts")],
        capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0, res.stdout + res.stderr
