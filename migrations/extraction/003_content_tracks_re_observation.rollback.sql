DROP VIEW IF EXISTS sch_extraction.v_reprocessing_backlog;
CREATE VIEW sch_extraction.v_reprocessing_backlog WITH (security_invoker = true) AS
    SELECT tenant_id, capture_id, min(extractor_version) AS oldest_extractor_version,
           count(*) AS items
      FROM sch_extraction.content WHERE deleted_at IS NULL
     GROUP BY tenant_id, capture_id;
GRANT SELECT ON sch_extraction.v_reprocessing_backlog TO asip_app;
DROP INDEX IF EXISTS sch_extraction.content_last_capture_idx;
ALTER TABLE sch_extraction.content DROP COLUMN IF EXISTS last_capture_id;
ALTER TABLE sch_extraction.content DROP COLUMN IF EXISTS last_seen;
