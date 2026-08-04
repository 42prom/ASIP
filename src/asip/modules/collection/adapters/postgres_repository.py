"""L3 — collection persistence. Writes only to sch_collection (D-91)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg


class PostgresCollectionRepository:
    def __init__(self, connection: psycopg.Connection) -> None:
        self._conn = connection

    # ── sources ─────────────────────────────────────────────────────────────

    def add_source(
        self,
        source_id: UUID,
        tenant_id: UUID,
        name: str,
        url: str,
        platform: str,
        priority: int = 5,
        is_canary: bool = False,
        interval_seconds: int = 3600,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_collection.sources "
                "(source_id, tenant_id, name, url, platform, priority, is_canary, "
                " interval_seconds) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (source_id) DO NOTHING",
                (source_id, tenant_id, name, url, platform, priority, is_canary, interval_seconds),
            )
            cur.execute(
                "INSERT INTO sch_collection.source_health (source_id, tenant_id) "
                "VALUES (%s, %s) ON CONFLICT (source_id) DO NOTHING",
                (source_id, tenant_id),
            )

    def list_sources(self, tenant_id: UUID) -> list[dict[str, Any]]:
        """Read through the published view, not the tables (D-92)."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT source_id, name, url, platform, priority, enabled, is_canary, "
                "       interval_seconds, last_attempt_at, last_success_at, "
                "       consecutive_failures, last_failure_reason "
                "  FROM sch_collection.v_sources_for_display "
                " WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def due_sources(self, tenant_id: UUID, now: datetime) -> list[dict[str, Any]]:
        """Sources whose interval has elapsed.

        The naive scheduler the skeleton calls for: fixed interval, no priority
        scoring, no budget allocation. Those land with the real scheduler.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT source_id, name, url, platform, is_canary "
                "  FROM sch_collection.v_sources_for_display "
                " WHERE tenant_id = %s AND enabled "
                "   AND (last_attempt_at IS NULL "
                "        OR last_attempt_at < %s - make_interval(secs => interval_seconds)) "
                " ORDER BY priority, name",
                (tenant_id, now),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    # ── jobs ────────────────────────────────────────────────────────────────

    def open_job(
        self, job_id: UUID, tenant_id: UUID, source_id: UUID, trace_id: str, now: datetime
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_collection.fetch_jobs "
                "(job_id, tenant_id, source_id, trace_id, scheduled_for, started_at, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'running')",
                (job_id, tenant_id, source_id, trace_id, now, now),
            )

    def close_job(
        self,
        job_id: UUID,
        status: str,
        bytes_fetched: int,
        finished_at: datetime,
        capture_id: UUID | None = None,
        failure_reason: str | None = None,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_collection.fetch_jobs "
                "   SET status = %s, bytes_fetched = %s, finished_at = %s, "
                "       capture_id = %s, failure_reason = %s "
                " WHERE job_id = %s",
                (status, bytes_fetched, finished_at, capture_id, failure_reason, job_id),
            )

    def record_health(
        self,
        source_id: UUID,
        succeeded: bool,
        moment: datetime,
        failure_reason: str | None = None,
    ) -> None:
        """Roll up the last attempt.

        Health is a summary, not evidence, so it is the one thing here that is
        legitimately overwritten. The underlying attempts stay in fetch_jobs.
        """
        with self._conn.cursor() as cur:
            if succeeded:
                cur.execute(
                    "UPDATE sch_collection.source_health "
                    "   SET last_attempt_at = %s, last_success_at = %s, "
                    "       consecutive_failures = 0, last_failure_reason = NULL "
                    " WHERE source_id = %s",
                    (moment, moment, source_id),
                )
            else:
                cur.execute(
                    "UPDATE sch_collection.source_health "
                    "   SET last_attempt_at = %s, "
                    "       consecutive_failures = consecutive_failures + 1, "
                    "       last_failure_reason = %s "
                    " WHERE source_id = %s",
                    (moment, failure_reason, source_id),
                )

    def recent_jobs(self, tenant_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT j.job_id, j.source_id, s.name AS source_name, j.trace_id, "
                "       j.scheduled_for, j.started_at, j.finished_at, j.status, "
                "       j.bytes_fetched, j.capture_id, j.failure_reason "
                "  FROM sch_collection.fetch_jobs j "
                "  JOIN sch_collection.sources s ON s.source_id = j.source_id "
                " WHERE j.tenant_id = %s ORDER BY j.scheduled_for DESC LIMIT %s",
                (tenant_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]
