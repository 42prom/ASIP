"""L3 — review persistence. Writes only to sch_review (D-91)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from psycopg import Connection

#: Four states (D-32). "Insufficient evidence" is a legitimate outcome, not a
#: failure to decide — and a tool that confirms everything is one nobody trusts.
VERDICTS = (
    "confirmed_coordination",
    "likely_coordination",
    "insufficient_evidence",
    "no_coordination",
)


class PostgresReviewRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def record_verdict(
        self,
        verdict_id: UUID,
        tenant_id: UUID,
        finding_id: UUID,
        verdict: str,
        analyst: str,
        rationale: str,
        rule_version: str,
    ) -> None:
        """Append a verdict.

        A changed mind is a second verdict, never an edit of the first. The
        sequence is the record — and D-115 makes every one of these a labelled
        example, which is the cheapest path to measured precision there is.
        """
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}; expected one of {VERDICTS}")
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_review.verdicts "
                "(verdict_id, tenant_id, finding_id, verdict, rationale, analyst, "
                " rule_version) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (verdict_id, tenant_id, finding_id, verdict, rationale, analyst, rule_version),
            )

    def current_verdicts(self, tenant_id: UUID) -> dict[str, dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT finding_id, verdict, rationale, analyst, decided_at "
                "  FROM sch_review.v_current_verdicts WHERE tenant_id = %s",
                (tenant_id,),
            )
            columns = [d[0] for d in cur.description or ()]
            rows = [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]
        return {str(row["finding_id"]): row for row in rows}

    def history(self, tenant_id: UUID, finding_id: UUID) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT verdict_id, verdict, rationale, analyst, decided_at "
                "  FROM sch_review.verdicts WHERE tenant_id = %s AND finding_id = %s "
                " ORDER BY decided_at DESC",
                (tenant_id, finding_id),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]
