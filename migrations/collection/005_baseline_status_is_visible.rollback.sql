DROP VIEW IF EXISTS sch_collection.v_sources_for_display;

CREATE VIEW sch_collection.v_sources_for_display
    WITH (security_invoker = true) AS
    SELECT s.source_id, s.tenant_id, s.project_id, s.name, s.url, s.platform,
           s.priority, s.enabled, s.is_canary, s.interval_seconds,
           h.last_attempt_at, h.last_success_at, h.consecutive_failures,
           h.last_failure_reason
      FROM sch_collection.sources s
      LEFT JOIN sch_collection.source_health h ON h.source_id = s.source_id;

GRANT SELECT ON sch_collection.v_sources_for_display TO asip_app;

ALTER TABLE sch_collection.sources
    DROP CONSTRAINT IF EXISTS sources_baseline_status_known;

-- Drops observing_since, which cannot be reconstructed for any source whose
-- history predates its first recorded success. Export before rolling back.
ALTER TABLE sch_collection.sources
    DROP COLUMN IF EXISTS baseline_status,
    DROP COLUMN IF EXISTS observing_since;
