"""L3 — bundles serialised as WARC (D-20).

WARC because the evidence has to outlive this software. A journalist defending
a published claim may be doing so years later, with whatever tooling exists
then; a bundle readable only by ASIP is not much better than a screenshot. The
round-trip test opens a bundle with a plain warcio reader that knows nothing
about this module, and that test is the point of choosing the format.

Record layout inside one bundle:

    warcinfo   — capture metadata (D-19): source URL, capture time, trace id,
                 render params. What a reader needs to understand the capture.
    metadata   — manifest.json. A `metadata` record rather than a `resource`
                 one so that enumerating artifacts cannot pick it up: the
                 manifest describes the artifacts and is not one of them.
    resource   — one per artifact, carrying its media type.

`read` returns the resource records only. A record planted inside the archive
therefore surfaces as an artifact absent from the manifest, which is exactly
what invariant 1 exists to catch.
"""

from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any

from warcio.archiveiterator import ArchiveIterator
from warcio.utils import Digester
from warcio.warcwriter import WARCWriter

from asip.contracts.evidence import Manifest, ManifestDocument
from asip.contracts.ports.evidence import ObjectStore

#: WARC-Target-URI scheme for artifacts. A urn keeps the record addressable
#: without implying the artifact is retrievable at some http location.
ARTIFACT_URI_PREFIX = "urn:asip:artifact"
MANIFEST_URI = "urn:asip:manifest"
SEAL_URI = "urn:asip:seal"


class _Sha256WARCWriter(WARCWriter):
    """A WARC writer whose native block digests are SHA-256, not SHA-1.

    warcio defaults to SHA-1 because that is what the format's examples use and
    what most crawlers emit. SHA-1 is broken for collision resistance, and a
    digest header a future reader cannot rely on is worse than useless in a
    forensic archive — someone checking only the WARC-native digest would
    believe they had verified something.

    ``WARC-Block-Digest`` is a labelled field: the algorithm travels with the
    value, so ``sha256:...`` is as conformant as ``sha1:...`` and any compliant
    reader handles it. Every record therefore carries two independent integrity
    mechanisms — the format's own digest and ASIP's manifest — and a tampering
    attempt has to defeat both at once.
    """

    def _create_digester(self) -> Digester:
        return Digester("sha256")


class WarcBundleArchive:
    """Writes and reads bundles as WARC objects in an object store.

    Composes an ObjectStore rather than talking to S3 itself: the WARC format
    and the storage backend are independent concerns, and keeping them apart is
    what lets the round-trip test run against an in-memory store.
    """

    def __init__(self, object_store: ObjectStore) -> None:
        self._objects = object_store

    def write(
        self,
        key: str,
        document: ManifestDocument,
        manifest: Manifest,
        artifacts: Mapping[str, bytes],
    ) -> None:
        buffer = BytesIO()
        writer = _Sha256WARCWriter(buffer, gzip=True)

        writer.write_record(
            writer.create_warcinfo_record(
                filename=key,
                info={
                    "software": "ASIP",
                    "format": "WARC File Format 1.1",
                    "conformsTo": "https://iipc.github.io/warc-specifications/",
                    # Capture metadata is duplicated here for readability only.
                    # The authoritative copy is inside the manifest record,
                    # where it is covered by the manifest digest and therefore
                    # by the chain. Anything read from warcinfo is unverified.
                    "capture": document.raw.decode("utf-8"),
                },
            )
        )

        # The manifest record carries the exact bytes that were hashed. Written
        # verbatim, never re-serialised — the digest belongs to these bytes.
        writer.write_record(
            self._record(writer, MANIFEST_URI, "metadata", document.raw, "application/json")
        )

        for artifact in manifest.artifacts:
            writer.write_record(
                self._record(
                    writer,
                    f"{ARTIFACT_URI_PREFIX}:{artifact.name}",
                    "resource",
                    artifacts[artifact.name],
                    artifact.media_type,
                )
            )

        self._objects.put(key, buffer.getvalue(), "application/warc")

    def append_seal(self, key: str, seal: bytes) -> None:
        """Append a sealed segment carrying the chain entry and TSA token.

        WARC files concatenate: a gzipped WARC is a sequence of independent
        gzip members, so appending a second segment yields a longer file that
        every standard reader accepts. The existing bytes are never rewritten,
        which keeps the archive append-only at the byte level rather than only
        by convention.

        The seal is separate from the manifest because it cannot exist yet when
        the manifest is written — the chain entry needs the manifest digest,
        and the timestamp needs a round trip to a third party that may be slow
        or unreachable.
        """
        buffer = BytesIO()
        writer = _Sha256WARCWriter(buffer, gzip=True)
        writer.write_record(self._record(writer, SEAL_URI, "metadata", seal, "application/json"))
        self._objects.put(key, self._objects.get(key) + buffer.getvalue(), "application/warc")

    @staticmethod
    def _record(writer: Any, uri: str, rec_type: str, payload: bytes, media_type: str) -> Any:
        """Create a record. The writer supplies SHA-256 block digests itself."""
        return writer.create_warc_record(
            uri,
            rec_type,
            payload=BytesIO(payload),
            warc_content_type=media_type,
        )

    def read(self, key: str) -> dict[str, bytes]:
        """Every artifact record in the archive, by name.

        Deliberately returns what is *there* rather than what was expected, so
        that an unlisted record is visible to the caller instead of silently
        skipped.
        """
        found: dict[str, bytes] = {}
        for uri, payload in self._iter_payloads(key):
            if uri.startswith(f"{ARTIFACT_URI_PREFIX}:"):
                found[uri[len(ARTIFACT_URI_PREFIX) + 1 :]] = payload
        return found

    def read_manifest(self, key: str) -> bytes:
        for uri, payload in self._iter_payloads(key):
            if uri == MANIFEST_URI:
                return payload
        raise KeyError(f"no manifest record in {key}")

    def read_seal(self, key: str) -> bytes | None:
        """The most recent seal, or None if the bundle is not sealed yet.

        Last wins: seals are appended, so a re-seal (a second timestamp from
        another authority, say) leaves both in the archive and the latest is
        the current state. Earlier ones stay readable, which is the point of
        appending rather than replacing.
        """
        seal: bytes | None = None
        for uri, payload in self._iter_payloads(key):
            if uri == SEAL_URI:
                seal = payload
        return seal

    def _iter_payloads(self, key: str) -> list[tuple[str, bytes]]:
        """Read every record's URI and payload in one pass.

        Payloads are read *during* iteration and collected eagerly.
        ArchiveIterator streams: a record's content is only readable while it
        is the current one, and collecting records to read later silently
        yields empty bytes.
        """
        payloads: list[tuple[str, bytes]] = []
        for record in ArchiveIterator(BytesIO(self._objects.get(key))):
            uri = record.rec_headers.get_header("WARC-Target-URI") or ""
            payloads.append((uri, record.content_stream().read()))
        return payloads
