"""L3 — detection persistence. Writes only to sch_detection (D-91)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb


class PostgresDetectionRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def ensure_rule(
        self,
        rule_id: UUID,
        tenant_id: UUID,
        name: str,
        description: str,
        params: dict[str, Any],
    ) -> None:
        """Register a rule in shadow mode.

        `shadow_mode=true, enabled=false` is not a default to be tidied up
        later — it is the only state a rule with no measured precision may
        occupy, and the database refuses anything else (V-4).
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_detection.rules "
                "(rule_id, tenant_id, name, description, params, shadow_mode, enabled) "
                "VALUES (%s, %s, %s, %s, %s, true, false) "
                "ON CONFLICT (rule_id) DO NOTHING",
                (rule_id, tenant_id, name, description, Jsonb(params)),
            )

    def list_rules(self, tenant_id: UUID) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT rule_id, name, description, params, shadow_mode, enabled, "
                "       measured_precision, measured_at, created_at "
                "  FROM sch_detection.rules WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def record_finding(
        self,
        finding_id: UUID,
        tenant_id: UUID,
        rule_id: UUID,
        source_id: UUID,
        project_id: UUID,
        trace_id: str,
        window_start: datetime,
        window_end: datetime,
        item_count: int,
        account_count: int,
        signals: list[dict[str, Any]],
        evidence_refs: list[UUID],
        shadow: bool,
        accounts: list[UUID],
    ) -> None:
        """Write a finding and its cluster membership atomically.

        Both or neither: a finding whose cluster is missing would show an
        account count with nothing behind it, which is exactly the kind of
        unfalsifiable number the product exists not to produce.
        """
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_detection.findings "
                "(finding_id, tenant_id, rule_id, source_id, project_id, trace_id, "
                " window_start, window_end, item_count, account_count, signals, "
                " evidence_refs, shadow) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    finding_id,
                    tenant_id,
                    rule_id,
                    source_id,
                    project_id,
                    trace_id,
                    window_start,
                    window_end,
                    item_count,
                    account_count,
                    Jsonb(signals),
                    evidence_refs,
                    shadow,
                ),
            )
            for account_id in accounts:
                cur.execute(
                    "INSERT INTO sch_detection.finding_accounts "
                    "(finding_id, tenant_id, account_id) VALUES (%s, %s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (finding_id, tenant_id, account_id),
                )

    def list_findings(
        self, tenant_id: UUID, project_id: UUID, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Findings in one project (D-49).

        `project_id` is required, not optional. An optional filter defaults to
        "all projects" the moment a caller omits it, which is the tenant-wide
        read that must not exist — and the omission would be invisible.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT finding_id, rule_id, rule_name, source_id, project_id, "
                "       trace_id, window_start, window_end, item_count, account_count, "
                "       signals, evidence_refs, shadow, detected_at "
                "  FROM sch_detection.v_findings_for_review "
                " WHERE tenant_id = %s AND project_id = %s "
                " ORDER BY detected_at DESC LIMIT %s",
                (tenant_id, project_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def get_finding(self, tenant_id: UUID, finding_id: UUID) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT finding_id, rule_id, rule_name, source_id, trace_id, "
                "       window_start, window_end, item_count, account_count, signals, "
                "       evidence_refs, shadow, detected_at "
                "  FROM sch_detection.v_findings_for_review "
                " WHERE tenant_id = %s AND finding_id = %s",
                (tenant_id, finding_id),
            )
            row = cur.fetchone()
            if row is None:
                return None
            columns = [d[0] for d in cur.description or ()]
            finding = dict(zip(columns, row, strict=True))

            cur.execute(
                "SELECT account_id, item_count FROM sch_detection.finding_accounts "
                " WHERE tenant_id = %s AND finding_id = %s ORDER BY account_id",
                (tenant_id, finding_id),
            )
            finding["cluster"] = [
                {"account_id": str(a), "item_count": n} for a, n in cur.fetchall()
            ]
        return finding

    def counts(self, tenant_id: UUID) -> dict[str, int]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FILTER (WHERE shadow), count(*) "
                "  FROM sch_detection.findings WHERE tenant_id = %s",
                (tenant_id,),
            )
            row = cur.fetchone() or (0, 0)
        return {"shadow": row[0], "total": row[1]}
