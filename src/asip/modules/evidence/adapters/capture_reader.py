"""L3 — serving stored capture bytes back to whoever needs to re-read them.

Implements ``CaptureBytes``. Evidence owns the archive, so evidence is what
knows a bundle is a WARC, where it lives, and which record inside it holds the
captured document. Callers get bytes and learn none of that (D-13, D-99).

The bytes come from the archive rather than from any cached copy, which means a
reprocess is reading the same artifact the manifest attests to. If storage has
been tampered with, reprocessing surfaces it as a parse failure rather than
quietly producing content from a corrupted source.
"""

from __future__ import annotations

from uuid import UUID

import psycopg

from asip.contracts.ports.evidence import BundleArchive

#: The artifact holding the captured document. Named here because the mapping
#: from "the capture" to "a record inside the bundle" is evidence's business.
DOCUMENT_ARTIFACTS = ("dom.html", "dom.html.gz")

ARCHIVE_OBJECT_NAME = "bundle.warc.gz"


class WarcCaptureReader:
    """Reads a capture's document out of its sealed bundle."""

    def __init__(self, connection: psycopg.Connection, archive: BundleArchive) -> None:
        self._conn = connection
        self._archive = archive

    def read_capture(self, tenant_id: UUID, capture_id: UUID) -> bytes | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT object_prefix FROM sch_evidence.evidence_bundles "
                " WHERE tenant_id = %s AND capture_id = %s "
                " ORDER BY captured_at DESC LIMIT 1",
                (tenant_id, capture_id),
            )
            row = cur.fetchone()
        if row is None:
            return None

        try:
            artifacts = self._archive.read(f"{row[0]}/{ARCHIVE_OBJECT_NAME}")
        except Exception:
            # Retention may have expired the object while the row survives
            # until its own expiry runs. A missing archive is an ordinary
            # condition during a reprocess of old material, not a crash.
            return None

        for name in DOCUMENT_ARTIFACTS:
            if name in artifacts:
                return artifacts[name]
        return None
