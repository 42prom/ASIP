"""Evidence ports (D-98).

L2 application code depends on these Protocols. Concrete adapters — MinIO/S3,
Postgres, an RFC 3161 TSA client, a warcio writer — are constructed only in
``entrypoints/composition.py``.

``EvidenceStore`` keeps the signatures given in the contracts document so that
the published interface and the plan cannot drift apart silently.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol
from uuid import UUID

from asip.contracts.evidence import (
    BundleDraft,
    BundleRecord,
    BundleRef,
    ChainEntry,
    Manifest,
    StoredBundle,
    TimestampRecord,
    VerificationResult,
)


class ObjectStore(Protocol):
    """Content-addressed blob storage. WORM in production."""

    def put(self, key: str, data: bytes, media_type: str) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        """Every key under a prefix.

        Used by retention (D-54), which has to find every object belonging to
        an expired bundle. Verification does not use this: a bundle is one WARC
        object, so discovering what is actually inside it means enumerating the
        archive's records, not the store's keys.
        """
        ...


class BundleArchive(Protocol):
    """A bundle serialised as a single WARC object (D-20).

    A bundle is a WARC file, not a directory of loose blobs. That is the point
    of D-20: the archiving standard means a journalist's forensics tool, or the
    Internet Archive's, opens the evidence without ever having seen this code.
    A custom layout would make the evidence readable only by the software that
    produced it, which defeats the purpose of preserving it.

    ``read`` returns only the artifact records, so a record planted inside the
    archive appears here and is caught by the manifest check. The manifest and
    capture metadata travel as distinct WARC record types precisely so they are
    not mistaken for artifacts.
    """

    def write(
        self,
        key: str,
        manifest: Manifest,
        artifacts: Mapping[str, bytes],
        metadata: Mapping[str, object],
    ) -> None: ...

    def read(self, key: str) -> dict[str, bytes]: ...


class TimestampAuthority(Protocol):
    """RFC 3161 timestamping (D-22).

    Implementations must raise rather than return a locally generated token
    when the authority is unreachable. A bundle that cannot be stamped is
    ``tsa_pending``, and the decision to retry belongs to the application
    layer — not to a fallback hidden inside an adapter.
    """

    def stamp(self, digest_hex: str) -> bytes: ...

    def verify(self, digest_hex: str, token: bytes) -> bool: ...


class EvidenceRepository(Protocol):
    """Append-only storage for bundles, the hash chain, and TSA tokens (D-21).

    There is no update method and no delete method, and none may be added.
    Retention expiry (D-54) is a separate audited job with its own path.

    ``commit_bundle`` takes both the bundle record and its chain entry because
    they must be written **atomically** — a chain entry attesting to a bundle
    that does not exist, or a bundle absent from the chain, is not evidence of
    anything. The port takes them together so that an implementation cannot
    accidentally offer a way to write one without the other.
    """

    def commit_bundle(self, record: BundleRecord, entry: ChainEntry) -> None:
        """Write bundle and chain entry in one transaction. Both or neither."""
        ...

    def append_timestamp(self, stamp: TimestampRecord) -> None:
        """Append an RFC 3161 token. Never replaces an existing one."""
        ...

    def head(self, tenant_id: UUID) -> ChainEntry | None: ...

    def segment(self, tenant_id: UUID, start: int, end: int) -> tuple[ChainEntry, ...]: ...

    def load_bundle(self, tenant_id: UUID, bundle_id: UUID) -> StoredBundle | None: ...


class EvidenceStore(Protocol):
    """The evidence module's published capability."""

    def write_bundle(self, bundle: BundleDraft) -> BundleRef: ...

    def verify(self, ref: BundleRef) -> VerificationResult: ...
