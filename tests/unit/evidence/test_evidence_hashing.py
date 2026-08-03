"""Digest determinism. Everything downstream rests on this.

If canonical_json is not stable, manifest digests differ between runs, every
chain appears broken, and the failure looks like tampering.
"""

from __future__ import annotations

from asip.modules.evidence.domain.hashing import (
    canonical_json,
    digest_of,
    is_hash_hex,
    sha256_hex,
)


def test_sha256_matches_the_published_empty_string_digest() -> None:
    """A fixed external value, so a broken hashlib cannot agree with itself."""
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_canonical_json_is_independent_of_key_order() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_canonical_json_has_no_insignificant_whitespace() -> None:
    assert canonical_json({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


def test_canonical_json_preserves_non_ascii_rather_than_escaping() -> None:
    """Georgian is first-class and the original is always preserved.

    Escaping would still be deterministic, but it would make stored digest
    input unreadable in exactly the language the product exists to handle.
    """
    assert canonical_json({"text": "საქართველო"}) == '{"text":"საქართველო"}'.encode()


def test_digest_of_is_stable_across_equivalent_structures() -> None:
    assert digest_of({"x": 1, "y": "z"}) == digest_of({"y": "z", "x": 1})


def test_digest_of_changes_when_any_value_changes() -> None:
    assert digest_of({"x": 1}) != digest_of({"x": 2})


def test_is_hash_hex_accepts_a_real_digest() -> None:
    assert is_hash_hex(sha256_hex(b"anything"))


def test_is_hash_hex_rejects_wrong_length_and_uppercase() -> None:
    """Uppercase is rejected on purpose: one hash, one spelling."""
    assert not is_hash_hex("abc")
    assert not is_hash_hex(sha256_hex(b"anything").upper())
    assert not is_hash_hex("g" * 64)
