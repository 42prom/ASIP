"""L1 — the audit log: append-only, hash-chained, and it records reads.

D-51 gives the audit log the same discipline as evidence, and D-52 adds the
part people skip: **reads are audited, not just writes**. In an intelligence
system "who looked at what" matters more than "who changed what" (T-009). An
analyst quietly reading every finding in a tenant they were never assigned to
leaves no trace in a write-only log, and that is the exact scenario the log
exists to catch.

WHY THIS DOES NOT IMPORT THE EVIDENCE CHAIN
The linking logic is deliberately not shared with
`modules/evidence/domain/chain.py`, despite being the same shape. D-99 requires
every module to be independently removable, and an identity module that imports
evidence cannot be deployed without it — nor can evidence be replaced without
touching authentication. Thirty lines of hashing is a cheap price for that.

There is a second reason, and it is the stronger one: the evidence preimage is
FROZEN. Real bundles are chained under `ASIP-CHAIN-v1` and any edit to that
function, however well-intentioned, would invalidate them. Refactoring the two
into one shared helper puts a live evidence chain one careless commit away from
unverifiable. They are different chains over different facts and they get
different domain separators.

    SHA-256( LP("ASIP-AUDIT-v1")
           || LP(hash_algorithm)
           || LP(tenant_id)
           || LP(chain_index, decimal)
           || LP(prev_hash, lowercase hex)
           || LP(entry_id)
           || LP(actor_id)
           || LP(action)
           || LP(resource_type)
           || LP(resource_id)
           || LP(outcome)
           || LP(occurred_at, RFC 3339 UTC) )

where LP(s) is the UTF-8 bytes of s preceded by their length as an 8-byte
big-endian integer. Same four choices as the evidence chain and for the same
reasons: no JSON, a version tag inside the hash, the algorithm as a hashed
field, and human-readable values.

Unlike the evidence chain this one *does* hash a timestamp. Evidence excludes
it because an external RFC 3161 token is the authoritative time and a local
clock would be a weaker competing claim (D-22). An audit entry has no such
token, and "when did they look" is the fact being recorded — leaving it out of
the preimage would let it be edited without breaking the chain.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

#: Domain separator and preimage version. A future v2 mints a new tag; this one
#: is never edited, because entries written under it must stay verifiable.
AUDIT_PREIMAGE_VERSION = "ASIP-AUDIT-v1"

HASH_ALGORITHM = "sha256"

#: The first entry's predecessor. 64 zeros — a value no real digest takes.
GENESIS_PREV_HASH = "0" * 64


class AuditOutcome(StrEnum):
    """Denials are recorded too, and are often the more interesting record.

    A log containing only successes cannot show someone probing for what they
    are not allowed to see (T-007).
    """

    ALLOWED = "allowed"
    DENIED = "denied"


class AuditError(ValueError):
    """An audit entry could not be constructed."""


def _length_prefixed(*values: str) -> bytes:
    """Each value's UTF-8 bytes, preceded by their length as 8 bytes big-endian.

    Length prefixing is what makes the concatenation unambiguous: without it,
    ("ab", "c") and ("a", "bc") hash identically, and an attacker who controls
    two adjacent fields could move a boundary without changing the digest.
    """
    out = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        out.extend(len(encoded).to_bytes(8, "big"))
        out.extend(encoded)
    return bytes(out)


def _rfc3339(moment: datetime) -> str:
    """UTC, to microseconds, with a trailing Z.

    Fixed here rather than taken from the caller's formatting so that the same
    instant always produces the same preimage. A naive datetime is refused
    rather than assumed to be UTC: guessing produces a chain whose hashes depend
    on the timezone of whichever machine wrote them.
    """
    if moment.tzinfo is None:
        raise AuditError(
            f"audit timestamp {moment!r} has no timezone. A naive time would make the "
            "entry hash depend on the writer's locale."
        )
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One recorded action. Never updated, never deleted (D-51)."""

    entry_id: UUID
    tenant_id: UUID
    chain_index: int
    prev_hash: str
    actor_id: UUID
    action: str
    resource_type: str
    resource_id: str
    outcome: AuditOutcome
    occurred_at: datetime
    entry_hash: str
    reason: str = ""
    algorithm: str = HASH_ALGORITHM


def entry_preimage(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    entry_id: UUID,
    actor_id: UUID,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: AuditOutcome,
    occurred_at: datetime,
    algorithm: str = HASH_ALGORITHM,
) -> bytes:
    """The exact bytes hashed to produce ``entry_hash``.

    Its own function so the specification is executable rather than described,
    and so an external auditor can reproduce a digest without running ASIP.

    `reason` is deliberately outside the preimage. It is explanatory text whose
    wording may be improved; the *facts* — who, what, when, allowed or not —
    are what must not change.
    """
    return _length_prefixed(
        AUDIT_PREIMAGE_VERSION,
        algorithm,
        str(tenant_id),
        str(chain_index),
        prev_hash,
        str(entry_id),
        str(actor_id),
        action,
        resource_type,
        resource_id,
        outcome.value,
        _rfc3339(occurred_at),
    )


def compute_entry_hash(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    entry_id: UUID,
    actor_id: UUID,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: AuditOutcome,
    occurred_at: datetime,
    algorithm: str = HASH_ALGORITHM,
) -> str:
    return hashlib.sha256(
        entry_preimage(
            tenant_id,
            chain_index,
            prev_hash,
            entry_id,
            actor_id,
            action,
            resource_type,
            resource_id,
            outcome,
            occurred_at,
            algorithm,
        )
    ).hexdigest()


def link(
    previous: AuditEntry | None,
    *,
    entry_id: UUID,
    tenant_id: UUID,
    actor_id: UUID,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: AuditOutcome,
    occurred_at: datetime,
    reason: str = "",
) -> AuditEntry:
    """Produce the next entry in a tenant's audit chain.

    ``previous`` is that tenant's current head, or None for genesis. Each tenant
    has its own chain: one shared chain would mean verifying tenant A's audit
    log required reading tenant B's entries, which is the leak this system
    exists to prevent (V-7).
    """
    if previous is None:
        chain_index = 0
        prev_hash = GENESIS_PREV_HASH
    else:
        if previous.tenant_id != tenant_id:
            raise AuditError(
                "cannot link onto another tenant's audit chain: "
                f"head belongs to {previous.tenant_id}, entry to {tenant_id}"
            )
        chain_index = previous.chain_index + 1
        prev_hash = previous.entry_hash

    return AuditEntry(
        entry_id=entry_id,
        tenant_id=tenant_id,
        chain_index=chain_index,
        prev_hash=prev_hash,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        occurred_at=occurred_at,
        reason=reason,
        entry_hash=compute_entry_hash(
            tenant_id,
            chain_index,
            prev_hash,
            entry_id,
            actor_id,
            action,
            resource_type,
            resource_id,
            outcome,
            occurred_at,
        ),
        algorithm=HASH_ALGORITHM,
    )


def verify_chain(entries: Sequence[AuditEntry]) -> tuple[str, ...]:
    """Verify a contiguous audit segment. Returns problems, empty if intact.

    T-008. An audit log that is never verified is a log an attacker can edit at
    leisure — the tamper-evidence is only worth what the checking is worth.
    """
    if not entries:
        return ()

    problems: list[str] = []
    tenant_id = entries[0].tenant_id

    for position, entry in enumerate(entries):
        if entry.tenant_id != tenant_id:
            problems.append(
                f"entry {entry.chain_index} belongs to tenant {entry.tenant_id}, "
                f"segment is tenant {tenant_id}"
            )
            continue

        expected = compute_entry_hash(
            entry.tenant_id,
            entry.chain_index,
            entry.prev_hash,
            entry.entry_id,
            entry.actor_id,
            entry.action,
            entry.resource_type,
            entry.resource_id,
            entry.outcome,
            entry.occurred_at,
            entry.algorithm,
        )
        if entry.entry_hash != expected:
            problems.append(
                f"entry {entry.chain_index} hash does not match its contents "
                f"(stored {entry.entry_hash}, recomputed {expected})"
            )

        if position == 0:
            if entry.chain_index == 0 and entry.prev_hash != GENESIS_PREV_HASH:
                problems.append(
                    f"entry 0 must start from the genesis hash, found {entry.prev_hash}"
                )
            continue

        previous = entries[position - 1]

        if entry.chain_index != previous.chain_index + 1:
            problems.append(
                f"chain index jumps from {previous.chain_index} to {entry.chain_index}: "
                "entries are missing or reordered"
            )

        if entry.prev_hash != previous.entry_hash:
            problems.append(
                f"entry {entry.chain_index} does not link to entry {previous.chain_index} "
                f"(expected prev_hash {previous.entry_hash}, found {entry.prev_hash})"
            )

    return tuple(problems)
