"""L1 — the append-only hash chain.

Invariant 2 of the evidence subsystem: **the chain is unbroken.** Each entry
carries the previous entry's hash, so altering one record breaks the chain
visibly from that point on (D-21). Never backfill an entry. Never reorder.

Pure: values in, values out. Appending atomically alongside the bundle write
is the application layer's job; this module only decides what a correct link
looks like and whether a sequence of them holds together.

DECISION NEEDING SIGN-OFF — D-21 requires that each entry contain the previous
entry's hash but does not define the preimage. The scheme below is chosen here
and is cheap to change only while no real bundle exists; after that, changing
it invalidates every stored chain. See ``link_preimage``.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from asip.contracts.evidence import GENESIS_PREV_HASH, ChainEntry

from .hashing import digest_of, is_hash_hex


class ChainError(ValueError):
    """A chain entry could not be constructed."""


def link_preimage(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    manifest_sha256: str,
    bundle_id: UUID,
) -> dict[str, object]:
    """The exact structure hashed to produce ``entry_hash``.

    Five fields, all of them necessary:

    - ``tenant_id`` binds the entry to one tenant's chain, so an entry cannot
      be replayed into another tenant's chain (V-7).
    - ``chain_index`` binds it to a position, so two entries cannot be swapped.
    - ``prev_hash`` is the link itself.
    - ``manifest_sha256`` is what the entry attests to.
    - ``bundle_id`` binds it to one bundle, so a manifest cannot be re-attested
      under a different bundle identity.

    Deliberately excluded: any wall-clock time. The authoritative time for a
    bundle is the external RFC 3161 token (D-22), and including a local
    timestamp here would create a second, weaker time claim inside the chain
    that a reader might mistake for proof.
    """
    return {
        "bundle_id": str(bundle_id),
        "chain_index": chain_index,
        "manifest_sha256": manifest_sha256,
        "prev_hash": prev_hash,
        "tenant_id": str(tenant_id),
    }


def compute_entry_hash(
    tenant_id: UUID,
    chain_index: int,
    prev_hash: str,
    manifest_sha256: str,
    bundle_id: UUID,
) -> str:
    return digest_of(link_preimage(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id))


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
