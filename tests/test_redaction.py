"""Core selective-disclosure redaction: salted commitments, disclosure, and erasure."""

from __future__ import annotations

from provenrail import redaction as rd
from provenrail.redaction import Redactable, redactable


def test_commit_and_verify_opening_roundtrip():
    salt = rd.new_salt()
    c = rd.commit({"email": "a@b.com"}, salt)
    assert rd.verify_opening(c, {"email": "a@b.com"}, salt)
    assert not rd.verify_opening(c, {"email": "other@b.com"}, salt)  # binding: value bound
    assert not rd.verify_opening(c, {"email": "a@b.com"}, rd.new_salt())  # wrong salt


def test_salt_makes_commitments_unique_and_hiding():
    a = rd.commit("yes", rd.new_salt())
    b = rd.commit("yes", rd.new_salt())
    assert a != b  # same value, different salt -> different commitment (hiding low-entropy values)


def test_extract_replaces_marker_and_hides_cleartext():
    openings: dict = {}
    payload = {"prompt": redactable("patient SSN 123-45-6789"), "model": "gpt-4o"}
    out = rd.extract(payload, openings)
    assert out["model"] == "gpt-4o"               # non-redactable passes through
    assert rd.is_commitment(out["prompt"])        # redactable became a commitment
    assert "123-45-6789" not in str(out)          # cleartext is gone from the recorded structure
    assert len(openings) == 1                      # exactly one opening stashed
    c = rd.commit_of(out["prompt"])
    assert c in openings and openings[c]["value"] == "patient SSN 123-45-6789"


def test_extract_is_recursive():
    openings: dict = {}
    payload = {"msgs": [{"role": "user", "content": redactable("secret")}, {"role": "system"}]}
    out = rd.extract(payload, openings)
    assert rd.is_commitment(out["msgs"][0]["content"])
    assert out["msgs"][1] == {"role": "system"}
    assert rd.walk_commitments(out) == [rd.commit_of(out["msgs"][0]["content"])]


def test_disclose_reveals_with_valid_opening():
    openings: dict = {}
    out = rd.extract({"x": redactable("hello")}, openings)
    disclosed = rd.disclose(out, openings)
    assert disclosed == {"x": "hello"}


def test_disclose_withholds_when_erased():
    openings: dict = {}
    out = rd.extract({"x": redactable("hello")}, openings)
    # erasure = destroy the opening; the value can no longer be recovered from the record
    erased: dict = {}
    disclosed = rd.disclose(out, erased)
    assert list(disclosed.keys()) == ["x"]
    assert "__withheld__" in disclosed["x"]
    assert disclosed["x"]["__withheld__"]  # a stable, non-reversible marker, not the value


def test_disclose_ignores_tampered_opening():
    openings: dict = {}
    out = rd.extract({"x": redactable("real")}, openings)
    c = rd.commit_of(out["x"])
    bad = {c: {"alg": "sha256", "salt": openings[c]["salt"], "value": "FAKE"}}  # lie about the value
    disclosed = rd.disclose(out, bad)
    assert "__withheld__" in disclosed["x"]  # a forged opening is never substituted


def test_redactable_repr_does_not_leak():
    assert "secret" not in repr(redactable("secret"))
    assert isinstance(redactable("x"), Redactable)
