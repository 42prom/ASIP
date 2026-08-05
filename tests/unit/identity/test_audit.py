"""D-51, D-52 — the audit chain, and the reads it must not miss.

T-008 is audit-log tampering and T-009 is undetected reading. The chain answers
the first; recording reads at all answers the second. Both are worthless
unverified, so `verify_chain` is exercised against deliberately corrupted
segments rather than only against good ones.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from asip.modules.identity.domain.audit import (
    AUDIT_PREIMAGE_VERSION,
    GENESIS_PREV_HASH,
    AuditEntry,
    AuditError,
    AuditOutcome,
    compute_entry_hash,
    entry_preimage,
    link,
    verify_chain,
)

TENANT_A = UUID("aaaaaaaa-0000-4000-8000-00000000000a")
TENANT_B = UUID("bbbbbbbb-0000-4000-8000-00000000000b")
ACTOR = UUID("cccccccc-0000-4000-8000-00000000000c")
AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def entry(previous: AuditEntry | None = None, **overrides: object) -> AuditEntry:
    fields: dict[str, object] = {
        "entry_id": uuid4(),
        "tenant_id": TENANT_A,
        "actor_id": ACTOR,
        "action": "read_findings",
        "resource_type": "finding",
        "resource_id": "11111111-0000-4000-8000-000000000001",
        "outcome": AuditOutcome.ALLOWED,
        "occurred_at": AT,
    }
    fields.update(overrides)
    return link(previous, **fields)  # type: ignore[arg-type]


def chain_of(n: int) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    previous: AuditEntry | None = None
    for i in range(n):
        previous = entry(previous, occurred_at=AT + timedelta(seconds=i))
        entries.append(previous)
    return entries


# ── D-52: reads are recorded, and so are denials ────────────────────────────


def test_a_denied_read_is_recorded() -> None:
    """T-007. A log of successes cannot show someone probing for what they
    are not allowed to see."""
    denied = entry(outcome=AuditOutcome.DENIED, reason="not assigned to project")

    assert denied.outcome is AuditOutcome.DENIED
    assert verify_chain([denied]) == ()


def test_the_outcome_is_inside_the_hash() -> None:
    """Otherwise a denial could be edited into an approval without breaking
    the chain, which is the single most useful edit an attacker could make."""
    allowed = entry()
    forged = replace(allowed, outcome=AuditOutcome.DENIED)

    assert verify_chain([forged]), "flipping the outcome left the chain intact"


def test_the_actor_is_inside_the_hash() -> None:
    """ "Who looked" is the fact D-52 exists to preserve."""
    original = entry()
    forged = replace(original, actor_id=uuid4())

    assert verify_chain([forged]), "reassigning the actor left the chain intact"


def test_the_time_is_inside_the_hash() -> None:
    """Unlike evidence, which excludes time because an RFC 3161 token is the
    authoritative claim (D-22). An audit entry has no token, so "when did they
    look" must be covered here or it is editable."""
    original = entry()
    forged = replace(original, occurred_at=AT + timedelta(days=30))

    assert verify_chain([forged]), "moving the timestamp left the chain intact"


def test_the_explanatory_reason_is_not_inside_the_hash() -> None:
    """Deliberate. The facts are fixed; the wording of an explanation may be
    improved without invalidating history."""
    original = entry(reason="original wording")
    reworded = replace(original, reason="clearer wording")

    assert verify_chain([reworded]) == ()


# ── D-51 / T-008: the chain ─────────────────────────────────────────────────


def test_a_clean_chain_verifies() -> None:
    assert verify_chain(chain_of(5)) == ()


def test_genesis_starts_from_the_zero_hash() -> None:
    first = chain_of(1)[0]
    assert first.chain_index == 0
    assert first.prev_hash == GENESIS_PREV_HASH


def test_editing_any_entry_breaks_the_chain_from_there() -> None:
    entries = chain_of(5)
    entries[2] = replace(entries[2], action="read_evidence")

    problems = verify_chain(entries)

    assert problems, "an edited entry verified clean"
    assert any("hash does not match" in p for p in problems)


def test_removing_an_entry_is_visible() -> None:
    """Deletion is the tamper an append-only log most needs to catch — it is
    what someone covering their tracks actually wants to do."""
    entries = chain_of(5)
    del entries[2]

    problems = verify_chain(entries)

    assert any("missing or reordered" in p for p in problems)


def test_reordering_entries_is_visible() -> None:
    entries = chain_of(5)
    entries[1], entries[2] = entries[2], entries[1]

    assert verify_chain(entries)


def test_a_rebuilt_chain_with_a_forged_entry_still_fails_to_link() -> None:
    """Recomputing hashes after an edit is the obvious next attempt.

    It fails because entry 3 stores the *original* entry 2 hash. Rebuilding the
    whole tail would work — which is exactly why the chain head is anchored
    externally (D-90); the chain alone detects edits, not wholesale replacement.
    """
    entries = chain_of(5)
    edited = replace(entries[2], action="read_evidence")
    entries[2] = replace(
        edited,
        entry_hash=compute_entry_hash(
            edited.tenant_id,
            edited.chain_index,
            edited.prev_hash,
            edited.entry_id,
            edited.actor_id,
            edited.action,
            edited.resource_type,
            edited.resource_id,
            edited.outcome,
            edited.occurred_at,
        ),
    )

    problems = verify_chain(entries)

    assert any("does not link" in p for p in problems)


# ── V-7: one chain per tenant ───────────────────────────────────────────────


def test_a_tenants_chain_cannot_be_linked_onto_another_tenants() -> None:
    """One shared chain would mean verifying tenant A's audit log required
    reading tenant B's entries — the leak this system exists to prevent."""
    head = chain_of(1)[0]

    with pytest.raises(AuditError, match="another tenant"):
        entry(head, tenant_id=TENANT_B)


def test_a_mixed_segment_is_reported() -> None:
    entries = chain_of(2)
    entries[1] = replace(entries[1], tenant_id=TENANT_B)

    assert any("belongs to tenant" in p for p in verify_chain(entries))


# ── the preimage ────────────────────────────────────────────────────────────


def test_the_preimage_is_length_prefixed_and_unambiguous() -> None:
    """Without length prefixes, ("ab","c") and ("a","bc") hash identically and
    an attacker controlling two adjacent fields could move the boundary."""
    left = entry_preimage(
        TENANT_A,
        0,
        GENESIS_PREV_HASH,
        UUID(int=1),
        ACTOR,
        "read",
        "finding",
        "ab",
        AuditOutcome.ALLOWED,
        AT,
    )
    right = entry_preimage(
        TENANT_A,
        0,
        GENESIS_PREV_HASH,
        UUID(int=1),
        ACTOR,
        "read",
        "findinga",
        "b",
        AuditOutcome.ALLOWED,
        AT,
    )

    assert left != right


def test_the_preimage_carries_its_own_version_tag() -> None:
    """Domain separation. A future v2 must not be able to produce a v1 digest
    for different content, or the two could not coexist during a migration."""
    raw = entry_preimage(
        TENANT_A,
        0,
        GENESIS_PREV_HASH,
        UUID(int=1),
        ACTOR,
        "read",
        "finding",
        "x",
        AuditOutcome.ALLOWED,
        AT,
    )

    assert AUDIT_PREIMAGE_VERSION.encode() in raw
    assert AUDIT_PREIMAGE_VERSION == "ASIP-AUDIT-v1"


def test_the_same_instant_in_another_timezone_hashes_identically() -> None:
    """A digest that depended on the writer's locale would make a chain
    unverifiable on a machine configured differently from the one that wrote it."""
    tbilisi = timezone(timedelta(hours=4))
    same_moment = AT.astimezone(tbilisi)

    assert compute_entry_hash(
        TENANT_A,
        0,
        GENESIS_PREV_HASH,
        UUID(int=1),
        ACTOR,
        "read",
        "finding",
        "x",
        AuditOutcome.ALLOWED,
        AT,
    ) == compute_entry_hash(
        TENANT_A,
        0,
        GENESIS_PREV_HASH,
        UUID(int=1),
        ACTOR,
        "read",
        "finding",
        "x",
        AuditOutcome.ALLOWED,
        same_moment,
    )


def test_a_naive_timestamp_is_refused_rather_than_assumed_utc() -> None:
    with pytest.raises(AuditError, match="no timezone"):
        compute_entry_hash(
            TENANT_A,
            0,
            GENESIS_PREV_HASH,
            UUID(int=1),
            ACTOR,
            "read",
            "finding",
            "x",
            AuditOutcome.ALLOWED,
            datetime(2026, 8, 5, 12, 0),
        )


def test_the_audit_chain_does_not_share_the_evidence_domain_separator() -> None:
    """D-99. If these were ever refactored into one helper, the evidence
    preimage — frozen, with real bundles chained under it — would be one
    careless commit from unverifiable."""
    from asip.modules.evidence.domain.chain import CHAIN_PREIMAGE_VERSION

    assert AUDIT_PREIMAGE_VERSION != CHAIN_PREIMAGE_VERSION


def test_identity_does_not_import_the_evidence_module() -> None:
    """Module independence, asserted on the source rather than trusted.

    An identity module that imports evidence cannot be deployed without it, and
    evidence cannot be replaced without touching authentication.
    """
    import inspect

    from asip.modules.identity.domain import audit, roles

    for module in (audit, roles):
        source = inspect.getsource(module)
        assert "modules.evidence" not in source, f"{module.__name__} imports evidence (D-99)"
