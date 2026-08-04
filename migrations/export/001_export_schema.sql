-- sch_export — STIX 2.1 objects and export jobs (D-91).
--
-- The boundary between Tier 1 (millions of observations, ours) and Tier 2 (a
-- few hundred curated objects, exchangeable). Only findings at
-- LIKELY_COORDINATION and above cross it.

CREATE SCHEMA IF NOT EXISTS sch_export;
GRANT USAGE ON SCHEMA sch_export TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_export.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';

CREATE TABLE sch_export.export_jobs (
    export_id    uuid        PRIMARY KEY,
    tenant_id    uuid        NOT NULL,
    finding_id   uuid        NOT NULL,
    trace_id     text        NOT NULL,
    -- The serialised bundle, stored as TEXT for the same reason the evidence
    -- manifest is: JSONB reorders keys and rewrites numbers, and an exported
    -- bundle is a document someone else will hash and compare.
    bundle_json  text        NOT NULL,
    bundle_sha256 char(64)   NOT NULL,
    object_count integer     NOT NULL,
    stix_version text        NOT NULL DEFAULT '2.1',
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT export_bundle_is_json CHECK ((bundle_json::jsonb) ? 'objects'),
    CONSTRAINT export_hash_is_lower_hex CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT export_has_objects CHECK (object_count > 0)
);

CREATE INDEX export_jobs_finding_idx ON sch_export.export_jobs (tenant_id, finding_id);
CREATE INDEX export_jobs_tenant_created_idx
    ON sch_export.export_jobs (tenant_id, created_at DESC);

ALTER TABLE sch_export.export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_export.export_jobs FORCE  ROW LEVEL SECURITY;

CREATE POLICY export_jobs_tenant_isolation ON sch_export.export_jobs
    USING (tenant_id = sch_export.current_tenant())
    WITH CHECK (tenant_id = sch_export.current_tenant());

REVOKE ALL ON ALL TABLES IN SCHEMA sch_export FROM PUBLIC;

-- Append-only: an export is a record of what was handed to someone else, and
-- rewriting it would mean the copy they hold no longer matches ours.
GRANT SELECT, INSERT ON sch_export.export_jobs TO asip_app;
GRANT SELECT, DELETE ON sch_export.export_jobs TO asip_retention;
