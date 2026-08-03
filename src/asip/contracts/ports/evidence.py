"""Evidence ports (D-98).

L2 application code depends on these Protocols. Concrete adapters — MinIO/S3,
Postgres, an RFC 3161 TSA client, a warcio writer — are constructed only in
``entrypoints/composition.py``.

``EvidenceStore`` keeps the signatures given in the contracts document so that
the published interface and the plan cannot drift apart silently.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from asip.contracts.evidence import (
    BundleDraft,
    BundleRef,
    ChainEntry,
    VerificationResult,
)


class ObjectStore(Protocol):
    """Content-addressed blob storage. WORM in production."""

    def put(self, key: str, data: bytes, media_type: str) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...


class TimestampAuthority(Protocol):
    """RFC 3161 timestamping (D-22).

    Implementations must raise rather than return a locally generated token
    when the authority is unreachable. A bundle that cannot be stamped is
    ``tsa_pending``, and the decision to retry belongs to the application
    layer — not to a fallback hidden inside an adapter.
    """

    def stamp(self, digest_hex: str) -> bytes: ...

    def verify(self, digest_hex: str, token: bytes) -> bool: ...


class EvidenceChainRepository(Protocol):
    """Append-only storage for the hash chain (D-21).

    There is no update method and no delete method, and none may be added.
    ``append`` must be atomic with the bundle write it accompanies: a chain
    that can diverge from the bundles it describes is not evidence of anything.
    """

    def append(self, entry: ChainEntry) -> None: ...

    def head(self, tenant_id: UUID) -> ChainEntry | None: ...

    def segment(self, tenant_id: UUID, start: int, end: int) -> tuple[ChainEntry, ...]: ...


class EvidenceStore(Protocol):
    """The evidence module's published capability."""

    def write_bundle(self, bundle: BundleDraft) -> BundleRef: ...

    def verify(self, ref: BundleRef) -> VerificationResult: ...
