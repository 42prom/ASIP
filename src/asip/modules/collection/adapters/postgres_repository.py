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
        project_id: UUID,
        name: str,
        url: str,
        platform: str,
        priority: int = 5,
        is_canary: bool = False,
        interval_seconds: int = 3600,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                # Re-seeding must be able to REPAIR a source, not just skip it.
                # DO NOTHING meant a wrong URL — say, one pointing at a host the
                # fetcher cannot resolve — survived every attempt to fix it, and
                # the only remedy was hand-editing the database. Configuration
                # rows are not evidence; correcting one is the intended path.
                "INSERT INTO sch_collection.sources "
                "(source_id, tenant_id, project_id, name, url, platform, priority, "
                " is_canary, interval_seconds) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (source_id) DO UPDATE SET "
                "  name = EXCLUDED.name, url = EXCLUDED.url, "
                "  platform = EXCLUDED.platform, priority = EXCLUDED.priority, "
                "  is_canary = EXCLUDED.is_canary, "
                "  interval_seconds = EXCLUDED.interval_seconds, "
                # A source moving between projects is a legitimate
                # reorganisation, not a data correction — but it changes who can
                # see its findings, so it is an audited admin action upstream.
                "  project_id = EXCLUDED.project_id",
                (
                    source_id,
                    tenant_id,
                    project_id,
                    name,
                    url,
                    platform,
                    priority,
                    is_canary,
                    interval_seconds,
                ),
            )
            cur.execute(
                "INSERT INTO sch_collection.source_health (source_id, tenant_id) "
                "VALUES (%s, %s) ON CONFLICT (source_id) DO NOTHING",
                (source_id, tenant_id),
            )

    def source_id_for_url(self, tenant_id: UUID, url: str) -> UUID | None:
        """The source already watching this page, if any.

        Used before inserting so "you already watch this" is an answer rather
        than a constraint violation. The constraint stays as the guarantee —
        this is the courtesy in front of it.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT source_id FROM sch_collection.sources  WHERE tenant_id = %s AND url = %s",
                (tenant_id, url),
            )
            row = cur.fetchone()
        return None if row is None else UUID(str(row[0]))

    def begin_observing(self, tenant_id: UUID, source_id: UUID) -> None:
        """Start the baseline clock, once (D-31, D-80).

        Deliberately only sets it when NULL. Re-adding a source — which happens
        every time someone re-pastes a watchlist — must not restart the clock,
        because the history is still there and D-80 gates every rule on how
        much of it exists. Silently resetting it would push `baseline_ready`
        thirty days further out with no visible cause.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_collection.sources SET observing_since = now() "
                " WHERE tenant_id = %s AND source_id = %s AND observing_since IS NULL",
                (tenant_id, source_id),
            )

    def set_enabled(self, tenant_id: UUID, source_id: UUID, enabled: bool) -> bool:
        """The kill switch (D-111). Returns False if there is no such source.

        Distinct from deleting: stopping collection must never mean losing what
        was already collected. An operator reaching for "stop" during an
        incident should not have to think about that difference.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_collection.sources SET enabled = %s "
                " WHERE tenant_id = %s AND source_id = %s",
                (enabled, tenant_id, source_id),
            )
            return cur.rowcount > 0

    def list_sources(self, tenant_id: UUID) -> list[dict[str, Any]]:
        """Read through the published view, not the tables (D-92)."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT source_id, project_id, name, url, platform, priority, enabled, "
                "       is_canary, interval_seconds, baseline_status, observing_since, "
                "       observed_days, last_attempt_at, last_success_at, "
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
                "SELECT source_id, project_id, name, url, platform, is_canary "
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

    # ── scheduler runs ──────────────────────────────────────────────────────

    def open_run(self, run_id: UUID, tenant_id: UUID, trace_id: str, started: datetime) -> None:
        """Record that the scheduler woke up, before anything can go wrong.

        Written and committed up front so a run that crashes mid-way still
        leaves a row. A record only written on success cannot tell anyone about
        the failures, which is the one thing it most needs to do.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_collection.scheduler_runs "
                "(run_id, tenant_id, trace_id, started_at, outcome, detail) "
                "VALUES (%s, %s, %s, %s, 'failed', 'run did not complete')",
                (run_id, tenant_id, trace_id, started),
            )

    def close_run(
        self,
        run_id: UUID,
        tenant_id: UUID,
        finished: datetime,
        outcome: str,
        detail: str,
        counts: dict[str, int],
        stages: str,
    ) -> None:
        """Close a run with what it actually did.

        The row starts as 'failed'; this is what promotes it. A process killed
        between open and close therefore leaves a failed run rather than a
        missing one, and a missing row is the thing nobody notices.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_collection.scheduler_runs "
                "   SET finished_at = %s, outcome = %s, detail = %s, "
                "       sources_due = %s, captures = %s, items = %s, findings = %s, "
                "       exports = %s, held_for_review = %s, stages = %s::jsonb "
                " WHERE run_id = %s AND tenant_id = %s",
                (
                    finished,
                    outcome,
                    detail,
                    counts.get("sources_due", 0),
                    counts.get("captures", 0),
                    counts.get("items", 0),
                    counts.get("findings", 0),
                    counts.get("exports", 0),
                    counts.get("held_for_review", 0),
                    stages,
                    run_id,
                    tenant_id,
                ),
            )

    def recent_runs(self, tenant_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT run_id, trace_id, started_at, finished_at, outcome, detail, "
                "       sources_due, captures, items, findings, exports, "
                "       held_for_review, duration_seconds "
                "  FROM sch_collection.v_scheduler_runs WHERE tenant_id = %s "
                " ORDER BY started_at DESC LIMIT %s",
                (tenant_id, limit),
            )
            columns = [d[0] for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def last_run(self, tenant_id: UUID) -> dict[str, Any] | None:
        """The single fact a health check needs: when did this last work."""
        runs = self.recent_runs(tenant_id, limit=1)
        return runs[0] if runs else None

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
