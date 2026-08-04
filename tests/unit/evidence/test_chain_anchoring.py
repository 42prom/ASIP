"""Anchoring closes the gap a hash chain leaves open.

A chain detects an *edited* record. It does not detect a chain **rebuilt from
genesis** — every entry recomputed, every link consistent, history replaced.
These tests are about the anchor's behaviour around that gap, including the
cases where it correctly does nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from asip.modules.evidence.application.anchor_chain import AnchorChain
from asip.modules.evidence.domain.chain import link
from asip.modules.evidence.domain.hashing import sha256_hex

from .fakes import FakeRepository, FakeTimestampAuthority, FixedClock

TENANT = UUID("aaaaaaaa-0000-4000-8000-00000000000a")
AUTHORITY = "https://tsa.example.org"


def anchorer(repo: FakeRepository, tsa: FakeTimestampAuthority) -> AnchorChain:
    return AnchorChain(repo, tsa, FixedClock(), AUTHORITY)


def grow_chain(repo: FakeRepository, length: int) -> None:
    previous = None
    for i in range(length):
        previous = link(previous, TENANT, uuid4(), sha256_hex(f"bundle-{i}".encode()))
        repo.chains.setdefault(TENANT, []).append(previous)


def test_an_empty_chain_is_idle_not_failed() -> None:
    """Nothing to attest to is not an error, and must not read like one."""
    result = anchorer(FakeRepository(), FakeTimestampAuthority()).execute(TENANT)
    assert result.status == "idle"
    assert "nothing to anchor" in result.detail.lower()


def test_the_head_is_anchored_and_stored() -> None:
    repo = FakeRepository()
    grow_chain(repo, 4)

    result = anchorer(repo, FakeTimestampAuthority()).execute(TENANT)

    assert result.status == "ok"
    assert result.chain_index == 3
    stored = repo.latest_anchor(TENANT)
    assert stored is not None
    assert stored.chain_index == 3
    assert stored.entry_hash == repo.chains[TENANT][-1].entry_hash
    assert stored.authority_url == AUTHORITY


def test_the_token_covers_the_entry_hash_not_the_manifest() -> None:
    """One token attests to the whole history.

    Entry N's hash commits to entry N-1's, back to genesis — so stamping the
    head transitively covers every bundle sealed before it. Stamping a manifest
    digest instead would attest to one bundle and leave the ordering unproven.
    """
    repo = FakeRepository()
    grow_chain(repo, 3)
    tsa = FakeTimestampAuthority()

    anchorer(repo, tsa).execute(TENANT)

    head = repo.chains[TENANT][-1]
    stored = repo.latest_anchor(TENANT)
    assert stored is not None
    assert stored.token == b"tsa:" + head.entry_hash.encode()


def test_anchoring_twice_without_new_entries_does_nothing() -> None:
    """Anchors are cheap but not free, and a duplicate proves nothing new."""
    repo = FakeRepository()
    grow_chain(repo, 2)
    tsa = FakeTimestampAuthority()

    anchorer(repo, tsa).execute(TENANT)
    second = anchorer(repo, tsa).execute(TENANT)

    assert second.status == "idle"
    assert "already anchored" in second.detail
    assert len(repo.anchors[TENANT]) == 1


def test_a_new_entry_makes_the_chain_anchorable_again() -> None:
    repo = FakeRepository()
    grow_chain(repo, 2)
    tsa = FakeTimestampAuthority()
    anchorer(repo, tsa).execute(TENANT)

    previous = repo.chains[TENANT][-1]
    repo.chains[TENANT].append(link(previous, TENANT, uuid4(), sha256_hex(b"later bundle")))
    result = anchorer(repo, tsa).execute(TENANT)

    assert result.status == "ok"
    assert result.chain_index == 2
    assert len(repo.anchors[TENANT]) == 2


def test_an_unreachable_authority_reports_the_exposure() -> None:
    """The failure message has to say what is now unprotected.

    "Anchoring failed" tells an operator nothing actionable. "The chain is
    unanchored past this point and remains rewritable" tells them what it costs.
    """
    repo = FakeRepository()
    grow_chain(repo, 2)
    tsa = FakeTimestampAuthority()
    tsa.unreachable = True

    result = anchorer(repo, tsa).execute(TENANT)

    assert result.status == "failed"
    assert "rewritable" in result.detail
    assert TENANT not in repo.anchors


def test_a_token_that_does_not_verify_is_not_stored() -> None:
    """An anchor nobody can check is not an anchor."""
    repo = FakeRepository()
    grow_chain(repo, 2)
    tsa = FakeTimestampAuthority()
    tsa.issue_invalid = True

    result = anchorer(repo, tsa).execute(TENANT)

    assert result.status == "failed"
    assert TENANT not in repo.anchors


def test_the_anchor_records_the_algorithm_of_the_head_it_covers() -> None:
    """Algorithm agility reaches the anchors too.

    An anchor over a SHA-256 head must say so, or a future reader cannot tell
    which algorithm the attested hash was produced with.
    """
    repo = FakeRepository()
    grow_chain(repo, 1)

    anchorer(repo, FakeTimestampAuthority()).execute(TENANT)

    stored = repo.latest_anchor(TENANT)
    assert stored is not None
    assert stored.algorithm == "sha256"
    assert stored.anchored_at == datetime(2026, 8, 4, 9, 0, tzinfo=UTC)
