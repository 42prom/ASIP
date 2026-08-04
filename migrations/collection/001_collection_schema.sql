-- sch_collection — watchlists, scheduling, fetch outcomes, source health (D-91).
--
-- Owned by modules/collection. Nothing here holds page content: the fetch zone
-- writes bundles to object storage and this schema records only *that* a fetch
-- happened and how it went (D-11, V-3).

CREATE SCHEMA IF NOT EXISTS sch_collection;
GRANT USAGE ON SCHEMA sch_collection TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_collection.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';

-- A monitored entity. `enabled` is the kill switch at source level (D-111).
CREATE TABLE sch_collection.sources (
    source_id        uuid        PRIMARY KEY,
    tenant_id        uuid        NOT NULL,
    name             text        NOT NULL,
    url              text        NOT NULL,
    platform         text        NOT NULL,
    priority         smallint    NOT NULL DEFAULT 5,
    enabled          boolean     NOT NULL DEFAULT true,
    -- A canary is a page we control, fetched on the same path as everything
    -- else. It separates "we broke it" from "they changed it" instantly (C-08).
    is_canary        boolean     NOT NULL DEFAULT false,
    interval_seconds integer     NOT NULL DEFAULT 3600,
    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sources_priority_range CHECK (priority BETWEEN 1 AND 10),
    CONSTRAINT sources_interval_sane CHECK (interval_seconds >= 60),
    CONSTRAINT sources_url_is_http CHECK (url ~ '^https?://')
);

CREATE INDEX sources_tenant_idx ON sch_collection.sources (tenant_id, enabled);

-- One scheduled or completed fetch attempt.
CREATE TABLE sch_collection.fetch_jobs (
    job_id         uuid        PRIMARY KEY,
    tenant_id      uuid        NOT NULL,
    source_id      uuid        NOT NULL REFERENCES sch_collection.sources (source_id),
    trace_id       text        NOT NULL,
    scheduled_for  timestamptz NOT NULL,
    started_at     timestamptz,
    finished_at    timestamptz,
    -- D-113: not three values. A failure we caused and a failure the platform
    -- caused need different responses, and collapsing them hides a broken
    -- fetcher behind "the site was down".
    status         text        NOT NULL DEFAULT 'pending',
    bytes_fetched  bigint      NOT NULL DEFAULT 0,
    capture_id     uuid,
    failure_reason text,

    CONSTRAINT fetch_jobs_status_taxonomy CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed_network',
                   'failed_timeout', 'failed_blocked', 'failed_not_found',
                   'failed_parse', 'failed_internal')
    ),
    CONSTRAINT fetch_jobs_bytes_non_negative CHECK (bytes_fetched >= 0)
);

CREATE INDEX fetch_jobs_tenant_scheduled_idx
    ON sch_collection.fetch_jobs (tenant_id, scheduled_for DESC);
CREATE INDEX fetch_jobs_source_idx ON sch_collection.fetch_jobs (tenant_id, source_id);

-- Source health. Every screen shows when each source was last read, so an empty
-- dashboard never silently means "nothing happened" (D-68).
CREATE TABLE sch_collection.source_health (
    source_id            uuid        PRIMARY KEY REFERENCES sch_collection.sources (source_id),
    tenant_id            uuid        NOT NULL,
    last_attempt_at      timestamptz,
    last_success_at      timestamptz,
    consecutive_failures integer     NOT NULL DEFAULT 0,
    last_failure_reason  text,

    CONSTRAINT health_failures_non_negative CHECK (consecutive_failures >= 0)
);

-- RLS (D-82, V-7). FORCE so the owner is subject to the policy too.
ALTER TABLE sch_collection.sources       ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_collection.sources       FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_collection.fetch_jobs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_collection.fetch_jobs    FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_collection.source_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_collection.source_health FORCE  ROW LEVEL SECURITY;

CREATE POLICY sources_tenant_isolation ON sch_collection.sources
    USING (tenant_id = sch_collection.current_tenant())
    WITH CHECK (tenant_id = sch_collection.current_tenant());

CREATE POLICY fetch_jobs_tenant_isolation ON sch_collection.fetch_jobs
    USING (tenant_id = sch_collection.current_tenant())
    WITH CHECK (tenant_id = sch_collection.current_tenant());

CREATE POLICY source_health_tenant_isolation ON sch_collection.source_health
    USING (tenant_id = sch_collection.current_tenant())
    WITH CHECK (tenant_id = sch_collection.current_tenant());

REVOKE ALL ON ALL TABLES IN SCHEMA sch_collection FROM PUBLIC;

GRANT SELECT, INSERT ON sch_collection.sources, sch_collection.fetch_jobs,
                        sch_collection.source_health TO asip_app;

-- source_health is a rolling summary and fetch_jobs record a lifecycle, so both
-- are legitimately updated in place. Evidence tables never are — that asymmetry
-- is the point, and it is why these grants are column-scoped rather than blanket.
GRANT UPDATE ON sch_collection.source_health TO asip_app;
GRANT UPDATE (status, started_at, finished_at, bytes_fetched, capture_id, failure_reason)
    ON sch_collection.fetch_jobs TO asip_app;

GRANT SELECT, DELETE ON sch_collection.sources, sch_collection.fetch_jobs,
                        sch_collection.source_health TO asip_retention;

-- Published read view (D-92). security_invoker or RLS does not apply to callers.
CREATE VIEW sch_collection.v_sources_for_display WITH (security_invoker = true) AS
    SELECT s.source_id, s.tenant_id, s.name, s.url, s.platform, s.priority,
           s.enabled, s.is_canary, s.interval_seconds,
           h.last_attempt_at, h.last_success_at, h.consecutive_failures,
           h.last_failure_reason
      FROM sch_collection.sources s
      LEFT JOIN sch_collection.source_health h ON h.source_id = s.source_id;

GRANT SELECT ON sch_collection.v_sources_for_display TO asip_app;
