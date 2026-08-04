DROP VIEW IF EXISTS sch_extraction.v_reprocessing_backlog;
REVOKE UPDATE ON sch_extraction.content FROM asip_app;
ALTER TABLE sch_extraction.content DROP CONSTRAINT IF EXISTS content_script_known;
ALTER TABLE sch_extraction.content DROP COLUMN IF EXISTS script;
DROP VIEW IF EXISTS sch_extraction.v_content_for_detection;
CREATE VIEW sch_extraction.v_content_for_detection WITH (security_invoker = true) AS
    SELECT content_id, tenant_id, source_id, account_id, capture_id, trace_id,
           posted_at_authoritative, timestamp_precision, text_sha256, lang, first_seen
      FROM sch_extraction.content WHERE deleted_at IS NULL;
GRANT SELECT ON sch_extraction.v_content_for_detection TO asip_app;
