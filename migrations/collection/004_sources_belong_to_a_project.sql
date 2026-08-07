-- A source belongs to a project (D-49).
--
-- WHY THE PROJECT ATTACHES HERE AND NOT TO THE FINDING
--
-- D-49 compartmentalises by project: an analyst sees assigned projects only,
-- and "see everything" does not exist. That requires every piece of tenant data
-- to answer "which project is this". The cheapest honest answer is that a
-- project is a set of sources being monitored — the decision is made once, when
-- someone configures what to watch, rather than per finding by a rule that has
-- no idea what a project is.
--
-- Findings then inherit it (see detection/002). Denormalised rather than
-- joined, for the same reason tenant_id is denormalised onto every table: an
-- authorization check that needs a join is an authorization check that gets
-- skipped for performance.
--
-- NO FOREIGN KEY TO sch_identity.projects
--
-- D-93 forbids cross-schema references, and identity must stay independently
-- removable (D-99). So this is an unenforced reference, exactly like
-- findings.evidence_refs pointing into sch_evidence — and it gets the same
-- compensating control: a health check that counts sources whose project does
-- not resolve. An invariant a database cannot enforce needs a periodic check
-- and a visible result.

ALTER TABLE sch_collection.sources
    ADD COLUMN IF NOT EXISTS project_id uuid;

-- Backfill before the NOT NULL. Existing dev rows predate projects entirely;
-- they go to the tenant's default project, which the seed creates with this
-- same deterministic id.
--
-- uuid5 of the tenant under identity's namespace, so the default project's id
-- is a function of the tenant rather than something that must be looked up
-- (M-10). The literal below is what
-- identity.domain.ids.default_project_id() returns for the development tenant
-- aaaaaaaa-0000-4000-8000-0000000000d1; a test asserts the two agree, because a
-- literal copied into SQL by hand is a literal that will drift.
--
-- Any other tenant's rows are backfilled by the seed that creates them.
UPDATE sch_collection.sources
   SET project_id = '88e6d502-7751-5da5-a72f-4733f8a726c2'
 WHERE project_id IS NULL;

ALTER TABLE sch_collection.sources ALTER COLUMN project_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS sources_project_idx
    ON sch_collection.sources (tenant_id, project_id);

-- The upsert in add_source needs UPDATE on every column it writes, and the
-- grant is column-scoped (migration 002), so a new column is invisible to it
-- until named here. Moving a source between projects changes who can see its
-- findings, which is why it is a grant rather than a blanket UPDATE.
GRANT UPDATE (project_id) ON sch_collection.sources TO asip_app;

COMMENT ON COLUMN sch_collection.sources.project_id IS
    'D-49 compartmentalisation. Unenforced reference to sch_identity.projects '
    '(D-93 forbids the FK); dangling refs are reported by the health check.';

-- The published view carries it, so callers can compartmentalise without
-- reaching into the table (D-92).
--
-- DROP then CREATE, not CREATE OR REPLACE: replacing a view cannot insert a
-- column into the middle of the list, only append to the end. Appending would
-- work and would put project_id after last_failure_reason, which reads as an
-- afterthought in every future SELECT — and the column list of a published view
-- is the contract other modules read.
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
