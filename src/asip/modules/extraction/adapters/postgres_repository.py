"""L3 — extraction persistence. Writes only to sch_extraction (D-91)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from psycopg import Connection
from psycopg.types.json import Jsonb

#: Namespace for deterministic account and content identifiers (M-10).
#: The same handle on the same platform always yields the same account_id, so
#: two workers extracting the same page agree without coordinating.
ASIP_NAMESPACE = UUID("6f1d5c40-0000-4000-8000-a51900000002")


def account_id_for(platform: str, handle: str) -> UUID:
    return uuid5(ASIP_NAMESPACE, f"account|{platform}|{handle}")


def content_id_for(platform: str, external_id: str) -> UUID:
    """Stable across reprocessing — the property W-01 question 1 asks about.

    A content id derived from the item's own identity means re-running a newer
    extractor over a stored capture produces the same row, rather than a
    duplicate that would double every count downstream.
    """
    return uuid5(ASIP_NAMESPACE, f"content|{platform}|{external_id}")


class PostgresExtractionRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def upsert_account(
        self,
        account_id: UUID,
        tenant_id: UUID,
        platform: str,
        handle: str,
        display_name: str | None,
        seen_at: datetime,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_extraction.accounts "
                "(account_id, tenant_id, platform, handle, display_name, first_seen, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (account_id) DO UPDATE SET last_seen = EXCLUDED.last_seen",
                (account_id, tenant_id, platform, handle, display_name, seen_at, seen_at),
            )

    def insert_content(
        self,
        content_id: UUID,
        tenant_id: UUID,
        capture_id: UUID,
        source_id: UUID,
        account_id: UUID,
        trace_id: str,
        posted_at: datetime,
        posted_at_raw: str,
        precision: str,
        text: str,
        text_sha256: str,
        lang: str | None,
        extractor_version: int,
        script: str | None = None,
    ) -> None:
        """Insert one item, or record that an existing one was seen again.

        The content_id is deterministic, so a page captured twice re-derives the
        same id and must not duplicate. The first version of this used ON
        CONFLICT DO NOTHING, which achieved that and silently threw away the
        fact of re-observation with it — leaving every item bound forever to the
        first capture that produced it (D-24, and it broke reprocessing).

        Now a repeat updates last_seen and last_capture_id and nothing else.
        `capture_id` stays put: it records where the item was FIRST seen, which
        is the provenance claim, and rewriting it would destroy the record of
        the original observation.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_extraction.content "
                "(content_id, tenant_id, capture_id, source_id, account_id, trace_id, "
                " posted_at_authoritative, posted_at_raw, timestamp_precision, text, "
                " text_sha256, lang, extractor_version, script, last_capture_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (content_id, posted_at_authoritative) DO UPDATE SET "
                "  last_seen = now(), last_capture_id = EXCLUDED.last_capture_id",
                (
                    content_id,
                    tenant_id,
                    capture_id,
                    source_id,
                    account_id,
                    trace_id,
                    posted_at,
                    posted_at_raw,
                    precision,
                    text,
                    text_sha256,
                    lang,
                    extractor_version,
                    script,
                    # last_capture_id starts equal to capture_id and diverges
                    # from it on every re-observation.
                    capture_id,
                ),
            )

    def record_run(
        self,
        run_id: UUID,
        tenant_id: UUID,
        capture_id: UUID,
        extractor_version: int,
        items: int,
        validation_passed: bool,
        problems: list[str],
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_extraction.extraction_runs "
                "(run_id, tenant_id, capture_id, extractor_version, items_extracted, "
                " validation_passed, problems) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    run_id,
                    tenant_id,
                    capture_id,
                    extractor_version,
                    items,
                    validation_passed,
                    Jsonb(problems),
                ),
            )

    def observations_for_detection(self, tenant_id: UUID, source_id: UUID) -> list[dict[str, Any]]:
        """Behavioural columns only — V-2.

        Reads the published view, which does not expose `text`. Detection
        therefore cannot see content even by accident, because the column is
        not in the result set.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT content_id, account_id, capture_id, posted_at_authoritative, "
                "       timestamp_precision "
                "  FROM sch_extraction.v_content_for_detection "
                " WHERE tenant_id = %s AND source_id = %s "
                " ORDER BY posted_at_authoritative",
                (tenant_id, source_id),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def recent_content(self, tenant_id: UUID, limit: int = 100) -> list[dict[str, Any]]:
        """For the console. Includes text, which is fine — this is not the
        authenticity path, it is a human reading what was captured."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT c.content_id, c.capture_id, c.source_id, c.trace_id, "
                "       c.posted_at_authoritative, c.posted_at_raw, c.timestamp_precision, "
                "       c.text, c.text_sha256, c.extractor_version, c.script, "
                "       c.first_seen, c.last_seen, c.last_capture_id, "
                "       a.handle, a.display_name "
                "  FROM sch_extraction.content c "
                "  JOIN sch_extraction.accounts a ON a.account_id = c.account_id "
                " WHERE c.tenant_id = %s AND c.deleted_at IS NULL "
                " ORDER BY c.posted_at_authoritative DESC LIMIT %s",
                (tenant_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    # ── reprocessing (D-13) ─────────────────────────────────────────────────

    def reprocessing_backlog(self, tenant_id: UUID, current_version: int) -> list[dict[str, Any]]:
        """Captures whose content predates the current extractor.

        Read through the published view. Returns captures, not items: a capture
        is re-parsed once and yields all of its items, so batching by capture is
        what keeps a reprocess of a million rows from reading the same archive a
        million times.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT capture_id, oldest_extractor_version, items "
                "  FROM sch_extraction.v_reprocessing_backlog "
                " WHERE tenant_id = %s AND oldest_extractor_version < %s "
                " ORDER BY capture_id",
                (tenant_id, current_version),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def content_for_capture(self, tenant_id: UUID, capture_id: UUID) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT content_id, posted_at_authoritative, text_sha256, script, "
                "       extractor_version "
                "  FROM sch_extraction.content "
                " WHERE tenant_id = %s AND last_capture_id = %s AND deleted_at IS NULL",
                (tenant_id, capture_id),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    @staticmethod
    def content_id_for(platform: str, external_id: str) -> UUID:
        """Exposed so the reprocess use case derives ids the same way."""
        return content_id_for(platform, external_id)

    def update_extracted(
        self,
        tenant_id: UUID,
        content_id: UUID,
        posted_at: datetime,
        text: str,
        text_sha256: str,
        script: str | None,
        precision: str,
        extractor_version: int,
    ) -> bool:
        """Write a newer extractor's reading over an older one.

        Returns whether anything actually changed. The version guard is what
        makes a reprocess safe to run twice and safe to run out of order: an
        older extractor can never overwrite a newer one's output, so a stale
        worker rejoining after a deploy corrupts nothing.

        Identity columns are untouched — which capture it came from and when it
        was posted are not the extractor's to revise.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_extraction.content "
                "   SET text = %s, text_sha256 = %s, script = %s, "
                "       timestamp_precision = %s, extractor_version = %s "
                " WHERE tenant_id = %s AND content_id = %s "
                "   AND posted_at_authoritative = %s "
                "   AND extractor_version < %s",
                (
                    text,
                    text_sha256,
                    script,
                    precision,
                    extractor_version,
                    tenant_id,
                    content_id,
                    posted_at,
                    extractor_version,
                ),
            )
            return cur.rowcount > 0

    def counts(self, tenant_id: UUID) -> dict[str, int]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT (SELECT count(*) FROM sch_extraction.content WHERE tenant_id = %s), "
                "       (SELECT count(*) FROM sch_extraction.accounts WHERE tenant_id = %s)",
                (tenant_id, tenant_id),
            )
            row = cur.fetchone() or (0, 0)
        return {"content": row[0], "accounts": row[1]}
