"""L2 — anchor the chain head to an external authority.

THE GAP THIS CLOSES
-------------------
A hash chain proves nobody edited *one* record: editing one breaks every link
after it. It does **not** stop someone with database write access rebuilding
the chain from genesis — every entry recomputed, every link consistent, the
whole history quietly replaced. Nothing inside the chain can detect that,
because the forged chain is internally perfect. D-21 and D-90 both describe
verifying the chain, and a rebuilt chain passes both.

An anchor is an RFC 3161 token over the chain head at a moment in time. Once
one exists, history *before* it cannot be rewritten without producing a head
that disagrees with a third party's signed record of what that head was. The
forger would need the authority's private key, which is the whole point of the
authority being external.

Anchors are cheap: one token per tenant per interval, regardless of how many
bundles were sealed in between. That asymmetry is why this is worth doing on a
schedule rather than per bundle.

WHAT AN ANCHOR DOES NOT DO
--------------------------
It does not protect history written *after* the last anchor. Everything since
is rewritable until the next one runs, so the anchoring interval is the size of
the window an attacker has. Stated plainly here because an anchor that people
believe covers more than it does is worse than none.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from asip.contracts.ports.clock import Clock
from asip.contracts.ports.evidence import EvidenceRepository, TimestampAuthority


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One external attestation of a tenant's chain head."""

    tenant_id: UUID
    anchored_at: datetime
    chain_index: int
    entry_hash: str
    algorithm: str
    authority_url: str
    token: bytes


@dataclass(frozen=True, slots=True)
class AnchorResult:
    """What one anchoring attempt did, including when it did nothing."""

    status: str
    detail: str
    chain_index: int | None = None


class AnchorRepository:
    """Structural note: anchors are stored through the evidence repository.

    Declared here as documentation of the dependency rather than as a second
    port — the concrete repository implements ``append_anchor`` and
    ``latest_anchor``, and adding a parallel port for two methods would be
    ceremony without benefit (CLAUDE.md §3).
    """


class AnchorChain:
    """Obtain an external attestation of where a tenant's chain currently ends."""

    def __init__(
        self,
        repository: EvidenceRepository,
        timestamp_authority: TimestampAuthority,
        clock: Clock,
        authority_url: str,
    ) -> None:
        self._repository = repository
        self._tsa = timestamp_authority
        self._clock = clock
        self._authority_url = authority_url

    def execute(self, tenant_id: UUID) -> AnchorResult:
        head = self._repository.head(tenant_id)
        if head is None:
            # Not a failure. An empty chain has nothing to attest to, and
            # saying so is different from saying the anchor failed (D-68).
            return AnchorResult("idle", "The chain is empty — nothing to anchor yet.")

        latest = self._repository.latest_anchor(tenant_id)
        if latest is not None and latest.chain_index == head.chain_index:
            return AnchorResult(
                "idle",
                f"Chain head {head.chain_index} is already anchored; no new entries since.",
                head.chain_index,
            )

        # The entry hash is what gets stamped, not the manifest digest. It
        # commits to the whole history transitively: entry N's hash covers
        # entry N-1's hash, and so on back to genesis. One token therefore
        # attests to every bundle sealed up to that point.
        try:
            token = self._tsa.stamp(head.entry_hash)
        except Exception as exc:
            return AnchorResult(
                "failed",
                f"Could not reach the timestamping authority: {exc}. The chain is "
                "unanchored past this point and remains rewritable until it is.",
                head.chain_index,
            )

        if self._tsa.can_verify() and not self._tsa.verify(head.entry_hash, token):
            return AnchorResult(
                "failed",
                "The authority returned a token that does not verify against the "
                "chain head. Not stored — an anchor nobody can check is not an anchor.",
                head.chain_index,
            )

        self._repository.append_anchor(
            AnchorRecord(
                tenant_id=tenant_id,
                anchored_at=self._clock.now(),
                chain_index=head.chain_index,
                entry_hash=head.entry_hash,
                algorithm=head.algorithm,
                authority_url=self._authority_url,
                token=token,
            )
        )
        return AnchorResult(
            "ok",
            f"Chain head {head.chain_index} anchored externally. History up to this "
            "point can no longer be rewritten undetectably.",
            head.chain_index,
        )
