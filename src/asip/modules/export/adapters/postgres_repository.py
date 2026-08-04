"""L3 — export persistence. Writes only to sch_export (D-91)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from psycopg import Connection


class PostgresExportRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def record_export(
        self,
        export_id: UUID,
        tenant_id: UUID,
        finding_id: UUID,
        trace_id: str,
        bundle_json: str,
        bundle_sha256: str,
        object_count: int,
    ) -> None:
        """Store the exported bundle verbatim.

        The bytes are kept as written, not re-serialised, for the same reason
        the evidence manifest is: a recipient may hash the copy we handed them,
        and a stored version that differs by key order would not match.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_export.export_jobs "
                "(export_id, tenant_id, finding_id, trace_id, bundle_json, "
                " bundle_sha256, object_count) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    export_id,
                    tenant_id,
                    finding_id,
                    trace_id,
                    bundle_json,
                    bundle_sha256,
                    object_count,
                ),
            )

    def list_exports(self, tenant_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT export_id, finding_id, trace_id, bundle_sha256, object_count, "
                "       stix_version, created_at "
                "  FROM sch_export.export_jobs WHERE tenant_id = %s "
                " ORDER BY created_at DESC LIMIT %s",
                (tenant_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def get_bundle(self, tenant_id: UUID, export_id: UUID) -> str | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT bundle_json FROM sch_export.export_jobs "
                " WHERE tenant_id = %s AND export_id = %s",
                (tenant_id, export_id),
            )
            row = cur.fetchone()
        return None if row is None else str(row[0])
