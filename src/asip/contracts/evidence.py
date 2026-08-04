"""L0 — evidence types.

These cross module boundaries: the ports in ``contracts/ports/evidence.py``
are written in terms of them, and anything that holds a bundle reference
(review, export, reporting) depends on this module rather than on the evidence
module itself. That is what keeps evidence removable (D-99).

Every type here is frozen. Captures and bundles are append-only — there is no
UPDATE path and no DELETE path except retention expiry (D-54), which is a
separate audited job. Immutable values make that property hard to violate by
accident rather than merely discouraged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

#: The only hash algorithm in the evidence path. Changing it invalidates every
#: existing chain, so it is a constant rather than a parameter.
HASH_ALGORITHM: Final = "sha256"
HASH_HEX_LENGTH: Final = 64

#: `prev_hash` of the first entry in a tenant's chain. A real hash is never all
#: zeroes, so a genesis entry is unambiguous.
GENESIS_PREV_HASH: Final = "0" * HASH_HEX_LENGTH


class ArtifactKind(StrEnum):
    """The elements of a bundle (D-19)."""

    DOM = "dom"
    SCREENSHOT_VIEWPORT = "screenshot_viewport"
    SCREENSHOT_FULLPAGE = "screenshot_fullpage"
    HAR = "har"
    MEDIA = "media"
    METADATA = "metadata"


class TsaStatus(StrEnum):
    """RFC 3161 timestamp state (D-22).

    There is deliberately no value meaning "we timestamped it ourselves". A
    timestamp we generate proves nothing; only a third-party token does. If the
    TSA is unreachable the bundle stays PENDING and is retried — it is never
    promoted to VERIFIED by any code path.
    """

    PENDING = "tsa_pending"
    VERIFIED = "tsa_verified"
    FAILED = "tsa_failed"


class VerificationOutcome(StrEnum):
    """Result of re-verifying a bundle.

    INCOMPLETE is a first-class outcome, not a soft failure: a bundle whose
    manifest and chain are intact but whose TSA token has not yet arrived is
    neither verified nor broken, and reporting it as either would be a lie.
    """

    VERIFIED = "verified"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class Artifact:
    """One file inside a bundle, with the hash the manifest will carry."""

    name: str
    kind: ArtifactKind
    media_type: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RenderParams:
    """Everything that makes a screenshot reproducible (D-23).

    Two captures of an unchanged page must produce identical pixels. That only
    holds if every one of these is pinned and recorded alongside the capture —
    an unrecorded render is not reproducible even if it was deterministic.
    """

    viewport_width: int
    viewport_height: int
    device_pixel_ratio: float
    locale: str
    timezone: str
    animations_disabled: bool
    network_idle_ms: int
    settle_delay_ms: int
    scroll_sequence: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CaptureBinding:
    """What a manifest attests about the capture itself.

    Inside the manifest, and therefore inside its digest and the hash chain,
    because it has to be. Left in the WARC's ``warcinfo`` record alone — where
    it originally sat — the source URL and capture time were covered by no hash
    at all, and a sealed bundle could be relabelled as a capture of a different
    page at a different time without breaking a single check.
    """

    bundle_id: UUID
    tenant_id: UUID
    capture_id: UUID
    source_url: str
    captured_at: datetime
    trace_id: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """The structured content of a manifest document (D-19).

    The bundle's self-description: what was captured, from where, when, and the
    SHA-256 of every artifact. A file present in the bundle but absent from the
    manifest invalidates the bundle just as surely as a hash mismatch does.

    This is the *input* to a manifest document. The authoritative artifact is
    ``ManifestDocument.raw`` — see there for why the distinction matters.
    """

    algorithm: str
    capture: CaptureBinding
    artifacts: tuple[Artifact, ...]
    render_params: RenderParams | None = None


@dataclass(frozen=True, slots=True)
class ManifestDocument:
    """A manifest as stored: exact bytes, and the digest of those bytes.

    The digest is ``sha256(raw)`` — the hash of the bytes that are physically
    in the archive, never a hash recomputed from a re-serialised structure.

    That distinction is the load-bearing one for long-term verification. If the
    digest were computed from parsed content, every future verifier would have
    to reproduce our JSON canonicalisation exactly: key order, separators,
    Unicode escaping, float formatting. Those are the details canonical-JSON
    implementations are famous for disagreeing about, and a disagreement twenty
    years from now would make valid evidence fail to verify.

    Hashing stored bytes needs none of it. Read the record, hash it, compare.
    """

    raw: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ChainEntry:
    """One link in a tenant's append-only hash chain (D-21).

    ``chain_index`` is scoped to ``tenant_id``: each tenant has its own chain
    starting at 0. A single global chain would let one tenant's entry indices
    reveal another tenant's capture volume, and would make a per-tenant export
    of the chain impossible to produce without leaking (V-7).
    """

    tenant_id: UUID
    chain_index: int
    prev_hash: str
    manifest_sha256: str
    bundle_id: UUID
    entry_hash: str

    #: The digest algorithm used for this entry, recorded rather than assumed.
    #: SHA-256 will not be the right answer forever, and an entry that names its
    #: own algorithm can be succeeded by one using a stronger algorithm without
    #: invalidating anything — the predecessor's hash is an opaque string to its
    #: successor. A chain that hard-codes its algorithm can only be migrated by
    #: rewriting history, which an append-only structure cannot do.
    algorithm: str = HASH_ALGORITHM


@dataclass(frozen=True, slots=True)
class BundleDraft:
    """A bundle about to be written. Carries no chain position yet.

    ``captured_at`` is the collector's clock, one of the three clocks of D-100,
    and is never the authoritative time for detection.
    """

    bundle_id: UUID
    capture_id: UUID
    tenant_id: UUID
    trace_id: str
    source_url: str
    captured_at: datetime
    artifacts: tuple[Artifact, ...]
    render_params: RenderParams | None = None


@dataclass(frozen=True, slots=True)
class BundleRef:
    """A written bundle's identity and chain position."""

    bundle_id: UUID
    tenant_id: UUID
    chain_index: int
    manifest_sha256: str
    tsa_status: TsaStatus


@dataclass(frozen=True, slots=True)
class BundleRecord:
    """The persisted description of a written bundle.

    Holds the manifest itself rather than only its digest, so that a bundle can
    be re-verified from the database plus the object store without parsing the
    WARC first. Append-only: there is no field here that is ever updated.
    """

    bundle_id: UUID
    capture_id: UUID
    tenant_id: UUID
    trace_id: str
    source_url: str
    captured_at: datetime
    manifest_document: ManifestDocument
    object_prefix: str
    render_params: RenderParams | None = None

    @property
    def manifest_sha256(self) -> str:
        """Digest of the stored manifest bytes. Never recomputed from content."""
        return self.manifest_document.sha256


@dataclass(frozen=True, slots=True)
class TimestampRecord:
    """One RFC 3161 token obtained for a bundle's manifest digest (D-22).

    A separate append-only record rather than a column on ``BundleRecord``.
    The token usually arrives after the bundle is committed — if it were a
    field on the bundle, recording it would be an UPDATE against an evidence
    table, and there is no UPDATE path against evidence tables. Appending a
    token instead keeps the whole subsystem write-once, and a bundle's TSA
    state becomes something *derived* from which tokens exist rather than a
    mutable flag that some code path could set without one.
    """

    tenant_id: UUID
    bundle_id: UUID
    manifest_sha256: str
    authority_url: str
    token: bytes
    obtained_at: datetime


@dataclass(frozen=True, slots=True)
class StoredBundle:
    """Everything needed to re-verify a bundle, as read back from storage."""

    record: BundleRecord
    chain_entry: ChainEntry
    timestamps: tuple[TimestampRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Why a bundle did or did not verify.

    ``problems`` is never summarised into a score. An analyst defending a
    published claim needs to say which check failed, not how confident a
    number is.
    """

    outcome: VerificationOutcome
    manifest_ok: bool
    chain_ok: bool
    tsa_ok: bool
    problems: tuple[str, ...] = ()
