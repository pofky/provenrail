import unicodedata

import pytest

from provenrail.canonical import CanonicalError, canonicalize, hash_value

# Built from explicit code points so the on-disk encoding cannot collapse the two forms:
# precomposed e-acute (U+00E9) vs decomposed "e" + combining acute (U+0301).
PRECOMPOSED = "café"
DECOMPOSED = "café"


def test_key_order_deterministic():
    a = {"b": 1, "a": 2, "c": {"y": 1, "x": 2}}
    b = {"c": {"x": 2, "y": 1}, "a": 2, "b": 1}
    assert canonicalize(a) == canonicalize(b)
    assert hash_value(a) == hash_value(b)


def test_compact_no_whitespace():
    assert canonicalize({"a": [1, 2, 3]}) == b'{"a":[1,2,3]}'


def test_floats_rejected():
    with pytest.raises(CanonicalError):
        canonicalize({"x": 1.5})


def test_big_int_rejected():
    with pytest.raises(CanonicalError):
        canonicalize({"id": 2**60})
    # but as a string it is fine
    canonicalize({"id": str(2**60)})


def test_unicode_value_preserved():
    # non-ASCII values are kept raw (JCS), bool handled before int
    out = canonicalize({"name": PRECOMPOSED, "flag": True, "n": 0})
    assert PRECOMPOSED in out.decode("utf-8")


def test_nfc_normalization_collapses_equivalent_forms():
    assert PRECOMPOSED != DECOMPOSED  # genuinely different Python strings
    assert unicodedata.normalize("NFC", DECOMPOSED) == PRECOMPOSED
    assert canonicalize({"name": PRECOMPOSED}) == canonicalize({"name": DECOMPOSED})
    assert hash_value({"name": PRECOMPOSED}) == hash_value({"name": DECOMPOSED})


def test_nfc_normalization_applies_to_keys():
    assert canonicalize({PRECOMPOSED: 1}) == canonicalize({DECOMPOSED: 1})
