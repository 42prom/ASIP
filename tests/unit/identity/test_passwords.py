"""Password and session-token handling.

The interesting tests are the negative ones. A hashing function that returns
True for the right password is easy; one that returns False for every wrong
input, every malformed record, and every unknown algorithm is the part that
decides whether authentication can be bypassed.
"""

from __future__ import annotations

import pytest

from asip.modules.identity.domain.passwords import (
    PasswordError,
    StoredHash,
    hash_password,
    needs_rehash,
    new_session_token,
    token_fingerprint,
    verify_password,
)

#: Low cost so the suite stays fast. Production uses the module default; these
#: tests are about behaviour, and the cost parameter is asserted separately.
FAST = {"n": 1024, "r": 8, "p": 1}


def test_the_right_password_verifies() -> None:
    stored = hash_password("correct horse battery staple", **FAST)
    assert verify_password("correct horse battery staple", stored)


def test_the_wrong_password_does_not() -> None:
    stored = hash_password("correct horse battery staple", **FAST)
    assert not verify_password("Correct horse battery staple", stored)
    assert not verify_password("", stored)
    assert not verify_password("correct horse battery stapl", stored)


def test_the_same_password_hashes_differently_every_time() -> None:
    """A fresh salt per hash. Without it, identical passwords are visibly
    identical in a dump, and one cracked hash cracks every account sharing it."""
    first = hash_password("same", **FAST)
    second = hash_password("same", **FAST)

    assert first != second
    assert verify_password("same", first)
    assert verify_password("same", second)


def test_the_plaintext_never_appears_in_the_stored_form() -> None:
    stored = hash_password("sentinel-plaintext-value", **FAST)
    assert "sentinel-plaintext-value" not in stored


def test_an_empty_password_is_refused_at_hashing_time() -> None:
    """Refused where it can still be reported, rather than silently stored as a
    hash that something might later verify against."""
    with pytest.raises(PasswordError):
        hash_password("")


# ── the format is what makes the KDF replaceable ────────────────────────────


def test_the_stored_form_carries_its_algorithm_and_parameters() -> None:
    """Verification dispatches on what is stored, not on what is current.

    This is what lets argon2 be adopted later without a password reset for
    every existing user.
    """
    stored = hash_password("x", **FAST)
    parsed = StoredHash.parse(stored)

    assert parsed.algorithm == "scrypt"
    assert parsed.parameters == FAST
    assert stored.startswith("scrypt$")


def test_a_round_trip_through_the_stored_form_is_lossless() -> None:
    stored = hash_password("x", **FAST)
    assert StoredHash.parse(stored).serialise() == stored


def test_an_unknown_algorithm_verifies_as_false_and_never_raises() -> None:
    """A hash written by a future version must not become an authentication
    bypass in any caller that treats an exception as "not our problem"."""
    future = "argon2id$m=65536,t=3,p=4$c2FsdA==$ZGlnZXN0"
    assert verify_password("anything", future) is False


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-a-hash",
        "scrypt$n=16384$onlythreeparts",
        "scrypt$n=abc,r=8,p=1$c2FsdA==$ZGlnZXN0",
        "scrypt$$c2FsdA==$ZGlnZXN0",
        "scrypt$n=16384,r=8,p=1$!!!notbase64!!!$ZGlnZXN0",
    ],
)
def test_a_malformed_stored_hash_verifies_as_false(malformed: str) -> None:
    assert verify_password("anything", malformed) is False


def test_a_weaker_stored_cost_is_flagged_for_rehash() -> None:
    """Cost is raised over time by rehashing at login, which is the only moment
    the plaintext is legitimately in hand."""
    weak = hash_password("x", n=1024, r=8, p=1)

    assert needs_rehash(weak, n=16384)
    assert not needs_rehash(hash_password("x", n=16384, r=8, p=1), n=16384)


def test_an_unreadable_hash_is_flagged_for_rehash() -> None:
    assert needs_rehash("garbage")


# ── session tokens ──────────────────────────────────────────────────────────


def test_session_tokens_are_unique_and_long() -> None:
    tokens = {new_session_token() for _ in range(200)}

    assert len(tokens) == 200
    assert all(len(t) >= 40 for t in tokens)


def test_the_fingerprint_is_what_gets_stored_and_the_token_is_not_recoverable() -> None:
    token = new_session_token()
    fingerprint = token_fingerprint(token)

    assert token not in fingerprint
    assert len(fingerprint) == 64
    assert fingerprint == token_fingerprint(token), "lookup requires determinism"


def test_two_tokens_do_not_share_a_fingerprint() -> None:
    assert token_fingerprint(new_session_token()) != token_fingerprint(new_session_token())
