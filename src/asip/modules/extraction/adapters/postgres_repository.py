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
    ) -> None:
        """Insert one item, ignoring a repeat.

        ON CONFLICT DO NOTHING is what makes reprocessing safe: running a newer
        extractor over the same capture re-derives the same content_id and the
        row is left alone rather than duplicated (D-13).
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_extraction.content "
                "(content_id, tenant_id, capture_id, source_id, account_id, trace_id, "
                " posted_at_authoritative, posted_at_raw, timestamp_precision, text, "
                " text_sha256, lang, extractor_version) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (content_id, posted_at_authoritative) DO NOTHING",
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
                "       c.text, c.text_sha256, c.extractor_version, a.handle, a.display_name "
                "  FROM sch_extraction.content c "
                "  JOIN sch_extraction.accounts a ON a.account_id = c.account_id "
                " WHERE c.tenant_id = %s AND c.deleted_at IS NULL "
                " ORDER BY c.posted_at_authoritative DESC LIMIT %s",
                (tenant_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def counts(self, tenant_id: UUID) -> dict[str, int]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT (SELECT count(*) FROM sch_extraction.content WHERE tenant_id = %s), "
                "       (SELECT count(*) FROM sch_extraction.accounts WHERE tenant_id = %s)",
                (tenant_id, tenant_id),
            )
            row = cur.fetchone() or (0, 0)
        return {"content": row[0], "accounts": row[1]}
