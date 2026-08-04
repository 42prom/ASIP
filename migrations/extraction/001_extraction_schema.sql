-- sch_extraction — captures turned into structured content (D-91).
--
-- Reprocessing, never refetching (D-13): content rows carry the
-- extractor_version that produced them, so bumping the version and re-running
-- over stored captures costs CPU and nothing else.

CREATE SCHEMA IF NOT EXISTS sch_extraction;
GRANT USAGE ON SCHEMA sch_extraction TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_extraction.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';

-- An observed account.
--
-- Note what is absent: no score, no label, no verdict, no risk column — and
-- none may be added. V-1 is enforced here by the *shape of the table*. The
-- data model contains no object capable of representing a judgement about a
-- named natural person, which is why the product cannot produce one.
CREATE TABLE sch_extraction.accounts (
    account_id         uuid        PRIMARY KEY,
    tenant_id          uuid        NOT NULL,
    platform           text        NOT NULL,
    handle             text        NOT NULL,
    display_name       text,
    account_created_at timestamptz,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT accounts_unique_per_platform UNIQUE (tenant_id, platform, handle)
);

CREATE INDEX accounts_tenant_idx ON sch_extraction.accounts (tenant_id, platform);

CREATE TABLE sch_extraction.content (
    content_id        uuid        NOT NULL,
    tenant_id         uuid        NOT NULL,
    capture_id        uuid        NOT NULL,
    source_id         uuid        NOT NULL,
    account_id        uuid        NOT NULL REFERENCES sch_extraction.accounts (account_id),
    trace_id          text        NOT NULL,
    -- D-101: clustering runs on the derived authoritative time, never on the
    -- raw platform value. D-102: precision is recorded per platform, because a
    -- rule whose window is narrower than the source's precision is worthless.
    posted_at_authoritative timestamptz NOT NULL,
    posted_at_raw     text,
    timestamp_precision text      NOT NULL DEFAULT 'second',
    text              text        NOT NULL,
    text_sha256       char(64)    NOT NULL,
    lang              text,
    extractor_version integer     NOT NULL,
    first_seen        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz,

    PRIMARY KEY (content_id, posted_at_authoritative),

    CONSTRAINT content_precision_known CHECK (
        timestamp_precision IN ('second', 'minute', 'hour', 'day')
    ),
    CONSTRAINT content_hash_is_lower_hex CHECK (text_sha256 ~ '^[0-9a-f]{64}$')
) PARTITION BY RANGE (posted_at_authoritative);

CREATE TABLE sch_extraction.content_2026_08 PARTITION OF sch_extraction.content
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE sch_extraction.content_2026_09 PARTITION OF sch_extraction.content
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE sch_extraction.content_2026_10 PARTITION OF sch_extraction.content
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE sch_extraction.content_2026_11 PARTITION OF sch_extraction.content
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

CREATE INDEX content_tenant_posted_idx
    ON sch_extraction.content (tenant_id, posted_at_authoritative DESC);
CREATE INDEX content_capture_idx ON sch_extraction.content (tenant_id, capture_id);

CREATE TABLE sch_extraction.extraction_runs (
    run_id            uuid        PRIMARY KEY,
    tenant_id         uuid        NOT NULL,
    capture_id        uuid        NOT NULL,
    extractor_version integer     NOT NULL,
    items_extracted   integer     NOT NULL DEFAULT 0,
    validation_passed boolean     NOT NULL,
    problems          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    ran_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX extraction_runs_capture_idx
    ON sch_extraction.extraction_runs (tenant_id, capture_id);

ALTER TABLE sch_extraction.accounts        ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_extraction.accounts        FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_extraction.content         ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_extraction.content         FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_extraction.extraction_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_extraction.extraction_runs FORCE  ROW LEVEL SECURITY;

CREATE POLICY accounts_tenant_isolation ON sch_extraction.accounts
    USING (tenant_id = sch_extraction.current_tenant())
    WITH CHECK (tenant_id = sch_extraction.current_tenant());

CREATE POLICY content_tenant_isolation ON sch_extraction.content
    USING (tenant_id = sch_extraction.current_tenant())
    WITH CHECK (tenant_id = sch_extraction.current_tenant());

CREATE POLICY extraction_runs_tenant_isolation ON sch_extraction.extraction_runs
    USING (tenant_id = sch_extraction.current_tenant())
    WITH CHECK (tenant_id = sch_extraction.current_tenant());

REVOKE ALL ON ALL TABLES IN SCHEMA sch_extraction FROM PUBLIC;

GRANT SELECT, INSERT ON sch_extraction.accounts, sch_extraction.content,
                        sch_extraction.extraction_runs TO asip_app;
GRANT UPDATE (last_seen) ON sch_extraction.accounts TO asip_app;
GRANT SELECT, DELETE ON sch_extraction.accounts, sch_extraction.content,
                        sch_extraction.extraction_runs TO asip_retention;

-- ─────────────────────────────────────────────────────────────────────────────
-- What detection is allowed to read (D-92) — and V-2 enforced structurally.
--
-- The authenticity path physically cannot reach `text`, because this view does
-- not publish it. That is the whole mechanism: V-2 says the isolation is a
-- module boundary rather than a convention, and a column list is a boundary.
-- Adding `text` here would be a veto violation, not a schema change.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE VIEW sch_extraction.v_content_for_detection WITH (security_invoker = true) AS
    SELECT content_id, tenant_id, source_id, account_id, capture_id, trace_id,
           posted_at_authoritative, timestamp_precision, text_sha256, lang, first_seen
      FROM sch_extraction.content
     WHERE deleted_at IS NULL;

GRANT SELECT ON sch_extraction.v_content_for_detection TO asip_app;
