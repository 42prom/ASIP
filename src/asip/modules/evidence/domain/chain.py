"""L1 — the append-only hash chain.

Invariant 2 of the evidence subsystem: **the chain is unbroken.** Each entry
carries the previous entry's hash, so altering one record breaks the chain
visibly from that point on (D-21). Never backfill an entry. Never reorder.

Pure: values in, values out. Appending atomically alongside the bundle write
is the application layer's job; this module only decides what a correct link
looks like and whether a sequence of them holds together.

THE PREIMAGE — specified here, and frozen once real evidence exists
--------------------------------------------------------------------
D-21 requires each entry to contain the previous entry's hash and stops there.
The exact bytes that get hashed are specified below, because a chain whose
preimage is only defined by its implementation cannot be verified by anything
except that implementation.

    SHA-256( LP("ASIP-CHAIN-v1")
           || LP(hash_algorithm)
           || LP(tenant_id)
           || LP(chain_index, decimal)
           || LP(prev_hash, lowercase hex)
           || LP(manifest_sha256, lowercase hex)
           || LP(bundle_id) )

where LP(s) is the UTF-8 bytes of s preceded by their length as an 8-byte
big-endian integer.

Four deliberate choices, each aimed at the twenty-year case:

1. **No JSON.** A verifier needs SHA-256, byte concatenation, and big-endian
   integers. Nothing else. No canonicalisation scheme to reimplement and no
   library whose behaviour might drift.

2. **A version tag inside the hash.** "ASIP-CHAIN-v1" is domain separation: a
   future v2 preimage cannot produce a v1 hash for different content, so the
   two schemes can coexist in one chain during a migration. Without this, any
   change to the preimage would require rewriting history — which an
   append-only structure cannot do.

3. **The hash algorithm is a hashed field, not an assumption.** SHA-256 will
   not be the right answer forever. Recording the algorithm inside the
   preimage means a future entry can adopt a stronger one and still link
   correctly onto a SHA-256 predecessor, because the predecessor's hash is
   just an opaque string to the successor.

4. **Values are human-readable text.** A UUID is its canonical lowercase form,
   an index is decimal, a digest is lowercase hex. Someone holding a printed
   chain entry can reconstruct the preimage by hand. Binary packing would save
   a few bytes and cost that.

The preimage deliberately excludes wall-clock time. The authoritative time for
a bundle is the external RFC 3161 token (D-22); a local timestamp inside the
chain would be a second, weaker time claim that a reader might mistake for
proof.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from asip.contracts.evidence import (
    GENESIS_PREV_HASH,
    HASH_ALGORITHM,
    ChainEntry,
)

from .canonical import length_prefixed
from .hashing import is_hash_hex, sha256_hex

#: Domain separator and preimage version. Changing the preimage means minting a
#: new tag, never editing this one — old entries must stay verifiable.
CHAIN_PREIMAGE_VERSION = "ASIP-CHAIN-v1"


class ChainError(ValueError):
    """A chain entry could not be constructed."""


def link_preimage(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    manifest_sha256: str,
    bundle_id: UUID,
    algorithm: str = HASH_ALGORITHM,
) -> bytes:
    """The exact bytes hashed to produce ``entry_hash``.

    Exposed as its own function so that the specification is executable rather
    than described in a comment, and so the standalone verifier can be checked
    against it byte for byte.
    """
    return length_prefixed(
        CHAIN_PREIMAGE_VERSION,
        algorithm,
        str(tenant_id),
        str(chain_index),
        prev_hash,
        manifest_sha256,
        str(bundle_id),
    )


def compute_entry_hash(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    manifest_sha256: str,
    bundle_id: UUID,
    algorithm: str = HASH_ALGORITHM,
) -> str:
    return sha256_hex(
        link_preimage(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id, algorithm)
    )


def link(
    previous: ChainEntry | None,
    tenant_id: UUID,
    bundle_id: UUID,
    manifest_sha256: str,
) -> ChainEntry:
    """Produce the next entry in a tenant's chain.

    ``previous`` is that tenant's current head, or None for the genesis entry.
    """
    if not is_hash_hex(manifest_sha256):
        raise ChainError(f"malformed manifest digest: {manifest_sha256!r}")

    if previous is None:
        chain_index = 0
        prev_hash = GENESIS_PREV_HASH
    else:
        if previous.tenant_id != tenant_id:
            raise ChainError(
                "cannot link onto another tenant's chain: "
                f"head belongs to {previous.tenant_id}, entry to {tenant_id}"
            )
        chain_index = previous.chain_index + 1
        prev_hash = previous.entry_hash

    return ChainEntry(
        tenant_id=tenant_id,
        chain_index=chain_index,
        prev_hash=prev_hash,
        manifest_sha256=manifest_sha256,
        bundle_id=bundle_id,
        entry_hash=compute_entry_hash(
            tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id
        ),
        algorithm=HASH_ALGORITHM,
    )


def verify_chain(entries: Sequence[ChainEntry]) -> tuple[str, ...]:
    """Verify a contiguous chain segment. Returns problems, empty if intact.

    A segment is checked rather than only the whole chain because full-history
    verification is a nightly job (D-90) while an analyst re-verifying one
    bundle needs an answer immediately.

    The segment must start either at genesis or at a known index; entries are
    assumed to be in index order as stored.
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

        expected_hash = compute_entry_hash(
            entry.tenant_id,
            entry.chain_index,
            entry.prev_hash,
            entry.manifest_sha256,
            entry.bundle_id,
            entry.algorithm,
        )
        if entry.entry_hash != expected_hash:
            problems.append(
                f"entry {entry.chain_index} hash does not match its contents "
                f"(stored {entry.entry_hash}, recomputed {expected_hash})"
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
                f"entry {entry.chain_index} does not link to entry "
                f"{previous.chain_index} (expected prev_hash {previous.entry_hash}, "
                f"found {entry.prev_hash})"
            )

    return tuple(problems)
