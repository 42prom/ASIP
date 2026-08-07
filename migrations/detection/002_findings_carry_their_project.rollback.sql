-- DROP then CREATE: a replace cannot remove a column from a view.
DROP VIEW IF EXISTS sch_detection.v_findings_for_review;

CREATE VIEW sch_detection.v_findings_for_review
    WITH (security_invoker = true) AS
    SELECT f.finding_id, f.tenant_id, f.rule_id, r.name AS rule_name,
           f.source_id, f.trace_id, f.window_start, f.window_end,
           f.item_count, f.account_count, f.signals, f.evidence_refs,
           f.shadow, f.detected_at
      FROM sch_detection.findings f
      JOIN sch_detection.rules r ON r.rule_id = f.rule_id;

DROP INDEX IF EXISTS sch_detection.findings_project_idx;
ALTER TABLE sch_detection.findings DROP COLUMN IF EXISTS project_id;
