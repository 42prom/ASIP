"""Invariant 2 — the chain is unbroken.

D-21's claim is that altering one record breaks the chain visibly. These tests
are the claim, stated executably: tamper with an entry, assert it is reported.
"""

from __future__ import annotations

from dataclasses import replace
from itertools import pairwise
from uuid import UUID, uuid4

import pytest

from asip.contracts.evidence import GENESIS_PREV_HASH, ChainEntry
from asip.modules.evidence.domain.chain import (
    ChainError,
    compute_entry_hash,
    link,
    verify_chain,
)
from asip.modules.evidence.domain.hashing import sha256_hex

TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")


def build_chain(length: int, tenant_id: UUID = TENANT) -> list[ChainEntry]:
    entries: list[ChainEntry] = []
    previous: ChainEntry | None = None
    for i in range(length):
        previous = link(previous, tenant_id, uuid4(), sha256_hex(f"bundle-{i}".encode()))
        entries.append(previous)
    return entries


def test_genesis_entry_starts_at_index_zero_from_the_genesis_hash() -> None:
    entry = link(None, TENANT, uuid4(), sha256_hex(b"first"))
    assert entry.chain_index == 0
    assert entry.prev_hash == GENESIS_PREV_HASH


def test_each_entry_carries_the_previous_entry_hash() -> None:
    entries = build_chain(4)
    for previous, current in pairwise(entries):
        assert current.prev_hash == previous.entry_hash
        assert current.chain_index == previous.chain_index + 1


def test_an_intact_chain_verifies() -> None:
    assert verify_chain(build_chain(6)) == ()


def test_empty_segment_verifies_trivially() -> None:
    assert verify_chain([]) == ()


def test_altering_a_manifest_digest_breaks_the_entrys_own_hash() -> None:
    """The core claim of D-21, first horn of the dilemma.

    Swap the attested manifest and leave ``entry_hash`` alone: the entry no
    longer hashes to what it stores. The link to the next entry still holds,
    because that entry points at the *stored* hash — which is why the second
    horn below matters just as much.
    """
    entries = build_chain(5)
    entries[2] = replace(entries[2], manifest_sha256=sha256_hex(b"substituted"))

    problems = verify_chain(entries)
    assert any("entry 2 hash does not match its contents" in p for p in problems)


def test_recomputing_the_hash_after_tampering_breaks_the_next_link_instead() -> None:
    """Second horn: repairing the entry moves the break one link along.

    Together these two tests are D-21's actual guarantee. There is no edit that
    satisfies both checks at once without rewriting every subsequent entry —
    which is what makes the chain tamper-*evident* rather than tamper-proof.
    """
    entries = build_chain(5)
    forged_digest = sha256_hex(b"substituted")
    forged = replace(
        entries[2],
        manifest_sha256=forged_digest,
        entry_hash=compute_entry_hash(
            entries[2].tenant_id,
            entries[2].chain_index,
            entries[2].prev_hash,
            forged_digest,
            entries[2].bundle_id,
        ),
    )
    entries[2] = forged

    problems = verify_chain(entries)
    assert not any("entry 2 hash does not match" in p for p in problems)
    assert any("entry 3 does not link to entry 2" in p for p in problems)


def test_reordering_entries_is_detected() -> None:
    entries = build_chain(5)
    entries[1], entries[2] = entries[2], entries[1]
    problems = verify_chain(entries)
    assert any("missing or reordered" in p for p in problems)


def test_removing_an_entry_is_detected() -> None:
    entries = build_chain(5)
    del entries[2]
    problems = verify_chain(entries)
    assert any("missing or reordered" in p for p in problems)


def test_genesis_entry_with_a_forged_predecessor_is_detected() -> None:
    entries = build_chain(3)
    entries[0] = replace(entries[0], prev_hash=sha256_hex(b"invented history"))
    problems = verify_chain(entries)
    assert any("must start from the genesis hash" in p for p in problems)


def test_an_entry_cannot_be_replayed_into_another_tenants_chain() -> None:
    """V-7 — tenant_id is inside the hashed preimage, not merely beside it."""
    entries = build_chain(3)
    entries[1] = replace(entries[1], tenant_id=OTHER_TENANT)
    problems = verify_chain(entries)
    assert any("belongs to tenant" in p for p in problems)


def test_linking_onto_another_tenants_head_is_refused() -> None:
    head = link(None, TENANT, uuid4(), sha256_hex(b"first"))
    with pytest.raises(ChainError, match="another tenant's chain"):
        link(head, OTHER_TENANT, uuid4(), sha256_hex(b"second"))


def test_two_tenants_chains_are_independent() -> None:
    """Each tenant starts at index 0; neither reveals the other's volume."""
    a = build_chain(3, TENANT)
    b = build_chain(2, OTHER_TENANT)
    assert [e.chain_index for e in a] == [0, 1, 2]
    assert [e.chain_index for e in b] == [0, 1]
    assert verify_chain(a) == ()
    assert verify_chain(b) == ()


def test_malformed_manifest_digest_is_refused_at_link_time() -> None:
    with pytest.raises(ChainError, match="malformed manifest digest"):
        link(None, TENANT, uuid4(), "not-a-hash")


def test_entry_hash_is_bound_to_the_bundle_identity() -> None:
    """The same manifest re-attested under a different bundle must differ."""
    manifest_digest = sha256_hex(b"same manifest")
    one = compute_entry_hash(TENANT, 0, GENESIS_PREV_HASH, manifest_digest, uuid4())
    two = compute_entry_hash(TENANT, 0, GENESIS_PREV_HASH, manifest_digest, uuid4())
    assert one != two
