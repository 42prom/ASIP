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

import json
from collections.abc import Mapping
from io import BytesIO

from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter

from asip.contracts.evidence import Manifest
from asip.contracts.ports.evidence import ObjectStore

#: WARC-Target-URI scheme for artifacts. A urn keeps the record addressable
#: without implying the artifact is retrievable at some http location.
ARTIFACT_URI_PREFIX = "urn:asip:artifact"
MANIFEST_URI = "urn:asip:manifest"


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
        manifest: Manifest,
        artifacts: Mapping[str, bytes],
        metadata: Mapping[str, object],
    ) -> None:
        buffer = BytesIO()
        writer = WARCWriter(buffer, gzip=True)

        writer.write_record(
            writer.create_warcinfo_record(
                filename=key,
                info={
                    "software": "ASIP",
                    "format": "WARC File Format 1.1",
                    "capture": json.dumps(metadata, sort_keys=True, ensure_ascii=False),
                },
            )
        )

        manifest_json = json.dumps(
            {
                "algorithm": manifest.algorithm,
                "artifacts": [
                    {
                        "kind": str(a.kind),
                        "media_type": a.media_type,
                        "name": a.name,
                        "sha256": a.sha256,
                        "size_bytes": a.size_bytes,
                    }
                    for a in manifest.artifacts
                ],
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")

        writer.write_record(
            writer.create_warc_record(
                MANIFEST_URI,
                "metadata",
                payload=BytesIO(manifest_json),
                warc_content_type="application/json",
            )
        )

        for artifact in manifest.artifacts:
            writer.write_record(
                writer.create_warc_record(
                    f"{ARTIFACT_URI_PREFIX}:{artifact.name}",
                    "resource",
                    payload=BytesIO(artifacts[artifact.name]),
                    warc_content_type=artifact.media_type,
                )
            )

        self._objects.put(key, buffer.getvalue(), "application/warc")

    def read(self, key: str) -> dict[str, bytes]:
        """Every artifact record in the archive, by name.

        Deliberately returns what is *there* rather than what was expected, so
        that an unlisted record is visible to the caller instead of silently
        skipped.
        """
        found: dict[str, bytes] = {}
        stream = BytesIO(self._objects.get(key))

        for record in ArchiveIterator(stream):
            if record.rec_type != "resource":
                continue
            uri = record.rec_headers.get_header("WARC-Target-URI") or ""
            if not uri.startswith(f"{ARTIFACT_URI_PREFIX}:"):
                continue
            name = uri[len(ARTIFACT_URI_PREFIX) + 1 :]
            found[name] = record.content_stream().read()

        return found
