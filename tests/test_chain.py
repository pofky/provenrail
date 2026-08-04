from provenrail.chain import MODEL_CALL, TOOL_CALL, Chain, verify_client_chain
from provenrail.keys import SigningKey


def build_chain(n_tools=3):
    c = Chain(stream_id="s1", key=SigningKey.generate())
    recs = [c.start({"agent": "test"})]
    recs.append(c.append(MODEL_CALL, {"model": "x", "request": {"hash": "h"}}))
    for i in range(n_tools):
        recs.append(c.append(TOOL_CALL, {"tool": f"t{i}", "args": {"hash": "a"}}))
    recs.append(c.seal())
    return recs


def test_valid_chain_has_no_issues():
    recs = build_chain()
    assert verify_client_chain(recs) == []


def test_tampered_payload_detected():
    recs = build_chain()
    recs[1]["payload"]["model"] = "evil"  # alter content without fixing hash/sig
    issues = {i.code for i in verify_client_chain(recs)}
    assert "hash_mismatch" in issues
    assert "bad_signature" in issues


def test_deleted_record_detected():
    recs = build_chain()
    del recs[2]  # remove a middle record -> link + seq break
    issues = {i.code for i in verify_client_chain(recs)}
    assert "broken_link" in issues
    assert "seq_gap" in issues


def test_reordered_records_detected():
    recs = build_chain()
    recs[2], recs[3] = recs[3], recs[2]
    issues = {i.code for i in verify_client_chain(recs)}
    assert "broken_link" in issues or "seq_gap" in issues


def test_swapped_signature_key_detected():
    recs = build_chain()
    other = SigningKey.generate()
    # re-sign a record with a different key but keep its pubkey field -> sig invalid
    recs[1]["record_sig"] = other.sign(b"whatever")
    issues = {i.code for i in verify_client_chain(recs)}
    assert "bad_signature" in issues


def test_key_load_warns_on_loose_permissions(tmp_path):
    import os
    import warnings
    if not hasattr(os, "geteuid"):
        return  # POSIX-only check
    p = tmp_path / "device.pem"
    SigningKey.generate().save(str(p))  # save() chmods to 600, no warning
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        SigningKey.load(str(p))
    assert not w, "tight permissions should not warn"
    os.chmod(p, 0o644)  # make it group/other-readable
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        SigningKey.load(str(p))
    assert any("forge" in str(x.message) for x in w)
