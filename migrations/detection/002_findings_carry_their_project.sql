-- A finding carries the project of the source it came from (D-49).
--
-- Denormalised from sch_collection.sources rather than joined at read time, for
-- the same reason tenant_id is denormalised onto every table: an authorization
-- check that needs a cross-schema join is an authorization check that gets
-- skipped for performance, and the one that gets skipped is the one that
-- mattered.
--
-- It also makes the check independent of collection's availability. Deciding
-- whether an analyst may read a finding must not require another module's
-- tables to be reachable.
--
-- No FK, for the same reason as sources.project_id: D-93 forbids cross-schema
-- references and identity stays independently removable (D-99). Same
-- compensating control — the health check counts findings whose project does
-- not resolve.

ALTER TABLE sch_detection.findings
    ADD COLUMN IF NOT EXISTS project_id uuid;

-- Existing findings predate projects. They belong to the development tenant's
-- default project — see collection/004 for where this literal comes from.
UPDATE sch_detection.findings
   SET project_id = '88e6d502-7751-5da5-a72f-4733f8a726c2'
 WHERE project_id IS NULL;

ALTER TABLE sch_detection.findings ALTER COLUMN project_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS findings_project_idx
    ON sch_detection.findings (tenant_id, project_id, detected_at DESC);

COMMENT ON COLUMN sch_detection.findings.project_id IS
    'D-49 compartmentalisation, denormalised from the source. Unenforced '
    'reference to sch_identity.projects (D-93 forbids the FK).';

-- Published so the review path can compartmentalise without joining across
-- schemas (D-92).
-- Same shape as migration 001 plus project_id. rule_name comes from the join,
-- not from the findings table — reproducing this view from memory rather than
-- from the original is how a column silently changes meaning.
--
-- DROP then CREATE: a replace cannot insert a column mid-list, only append.
DROP VIEW IF EXISTS sch_detection.v_findings_for_review;

CREATE VIEW sch_detection.v_findings_for_review
    WITH (security_invoker = true) AS
    SELECT f.finding_id, f.tenant_id, f.project_id, f.rule_id, r.name AS rule_name,
           f.source_id, f.trace_id, f.window_start, f.window_end,
           f.item_count, f.account_count, f.signals, f.evidence_refs,
           f.shadow, f.detected_at
      FROM sch_detection.findings f
      JOIN sch_detection.rules r ON r.rule_id = f.rule_id;

GRANT SELECT ON sch_detection.v_findings_for_review TO asip_app;
