-- DROP then CREATE: a replace can neither insert nor remove a column, and this
-- restores a narrower view than the one it is replacing.
DROP VIEW IF EXISTS sch_collection.v_sources_for_display;

CREATE VIEW sch_collection.v_sources_for_display
    WITH (security_invoker = true) AS
    SELECT s.source_id, s.tenant_id, s.name, s.url, s.platform, s.priority,
           s.enabled, s.is_canary, s.interval_seconds,
           h.last_attempt_at, h.last_success_at, h.consecutive_failures,
           h.last_failure_reason
      FROM sch_collection.sources s
      LEFT JOIN sch_collection.source_health h ON h.source_id = s.source_id;

DROP INDEX IF EXISTS sch_collection.sources_project_idx;
ALTER TABLE sch_collection.sources DROP COLUMN IF EXISTS project_id;
