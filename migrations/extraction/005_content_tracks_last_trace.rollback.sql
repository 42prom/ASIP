DROP VIEW IF EXISTS sch_extraction.v_content_provenance;
DROP INDEX IF EXISTS sch_extraction.content_last_trace_idx;
ALTER TABLE sch_extraction.content DROP COLUMN IF EXISTS last_trace_id;
GRANT UPDATE (last_seen, last_capture_id) ON sch_extraction.content TO asip_app;
