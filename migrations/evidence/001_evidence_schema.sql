-- sch_evidence — the evidence module's schema (D-91).
--
-- Owned exclusively by modules/evidence. No other module writes here, and
-- cross-schema reads go through the v_* views at the bottom of this file
-- (D-92). A module that needs evidence state emits an event (D-93).
--
-- Append-only. There is no UPDATE path and no DELETE path on the four tables
-- below, and this migration must never introduce one. That is enforced by
-- grant rather than by convention: the application role holds SELECT and
-- INSERT and nothing else. Retention expiry (D-54) is a separate audited job
-- running as a separate role, and it cascades to the object store and backups.
--
-- Partitioning: captures and evidence_bundles are range-partitioned by month
-- from day one (D-83). Retroactively partitioning a billion-row table is a
-- multi-day outage, and these are the two tables that grow without bound.
--
-- RLS: every table carries tenant_id and every table has a FORCE'd policy in
-- this same migration (D-82). FORCE matters — without it the table owner
-- bypasses the policy, which is the "see everything" path V-7 forbids.

CREATE SCHEMA IF NOT EXISTS sch_evidence;

-- ─────────────────────────────────────────────────────────────────────────────
-- Roles
--
-- Two roles, deliberately unequal. asip_app can add evidence and read it back;
-- it cannot alter or remove any of it. There is no third role that can see
-- across tenants (V-7).
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'asip_app') THEN
        CREATE ROLE asip_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'asip_retention') THEN
        CREATE ROLE asip_retention NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA sch_evidence TO asip_app, asip_retention;

-- ─────────────────────────────────────────────────────────────────────────────
-- captures — one fetch attempt, successful or not
--
-- A failed capture is as much a record as a successful one: "we looked and the
-- page was gone" is evidence, and D-25 makes deletion a first-class alert.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.captures (
    capture_id          uuid        NOT NULL,
    tenant_id           uuid        NOT NULL,
    source_id           uuid        NOT NULL,
    trace_id            text        NOT NULL,
    url                 text        NOT NULL,
    requested_at        timestamptz NOT NULL,
    completed_at        timestamptz,
    status              text        NOT NULL,
    http_status         integer,
    bytes_transferred   bigint      NOT NULL DEFAULT 0,
    failure_reason      text,

    PRIMARY KEY (capture_id, requested_at),

    -- D-113: status is not three values. The taxonomy distinguishes failures
    -- we caused from failures the platform caused, because the response to
    -- each is different and collapsing them hides a broken fetcher behind
    -- "the site was down".
    CONSTRAINT captures_status_taxonomy CHECK (
        status IN (
            'pending',
            'succeeded',
            'failed_network',
            'failed_timeout',
            'failed_blocked',
            'failed_not_found',
            'failed_parse',
            'failed_internal'
        )
    ),
    CONSTRAINT captures_bytes_non_negative CHECK (bytes_transferred >= 0),
    CONSTRAINT captures_completed_after_requested CHECK (
        completed_at IS NULL OR completed_at >= requested_at
    )
) PARTITION BY RANGE (requested_at);

CREATE INDEX captures_tenant_requested_idx
    ON sch_evidence.captures (tenant_id, requested_at DESC);

-- D-112: any finding must be traceable to its originating capture in one query.
CREATE INDEX captures_trace_idx ON sch_evidence.captures (tenant_id, trace_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- evidence_bundles — a sealed, hashed, manifest-covered capture
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.evidence_bundles (
    bundle_id           uuid        NOT NULL,
    captured_at         timestamptz NOT NULL,
    capture_id          uuid        NOT NULL,
    tenant_id           uuid        NOT NULL,
    trace_id            text        NOT NULL,
    source_url          text        NOT NULL,
    manifest            jsonb       NOT NULL,
    manifest_sha256     char(64)    NOT NULL,
    object_prefix       text        NOT NULL,
    render_params       jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (bundle_id, captured_at),

    -- The manifest covers everything (invariant 1). A bundle attesting to no
    -- artifacts attests to nothing.
    CONSTRAINT bundles_manifest_not_empty CHECK (
        jsonb_array_length(manifest -> 'artifacts') >= 1
    ),
    CONSTRAINT bundles_digest_is_lower_hex CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$')
) PARTITION BY RANGE (captured_at);

CREATE INDEX bundles_tenant_captured_idx
    ON sch_evidence.evidence_bundles (tenant_id, captured_at DESC);
CREATE INDEX bundles_capture_idx ON sch_evidence.evidence_bundles (tenant_id, capture_id);
CREATE INDEX bundles_trace_idx ON sch_evidence.evidence_bundles (tenant_id, trace_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- hash_chain — the append-only tamper-evident log (D-21)
--
-- Not partitioned, on purpose. The chain is read as a sequence and its head is
-- looked up on every write; partitioning would spread a hot, strictly ordered
-- structure across relations for no benefit. It grows one row per bundle,
-- which is an order of magnitude smaller than the tables above.
--
-- chain_index is per-tenant, so one tenant's indices never reveal another's
-- capture volume (V-7).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.hash_chain (
    tenant_id           uuid        NOT NULL,
    chain_index         bigint      NOT NULL,
    prev_hash           char(64)    NOT NULL,
    manifest_sha256     char(64)    NOT NULL,
    bundle_id           uuid        NOT NULL,
    bundle_captured_at  timestamptz NOT NULL,
    entry_hash          char(64)    NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, chain_index),

    -- One bundle, one entry. Re-attesting a bundle under a second index would
    -- make the chain ambiguous about what it is proving.
    CONSTRAINT chain_one_entry_per_bundle UNIQUE (tenant_id, bundle_id),

    -- The chain entry must point at a bundle that exists. This FK is why
    -- bundle_captured_at is carried here: a foreign key into a partitioned
    -- table must reference its full primary key.
    CONSTRAINT chain_bundle_fk FOREIGN KEY (bundle_id, bundle_captured_at)
        REFERENCES sch_evidence.evidence_bundles (bundle_id, captured_at),

    CONSTRAINT chain_index_non_negative CHECK (chain_index >= 0),
    CONSTRAINT chain_hashes_are_lower_hex CHECK (
        prev_hash ~ '^[0-9a-f]{64}$'
        AND manifest_sha256 ~ '^[0-9a-f]{64}$'
        AND entry_hash ~ '^[0-9a-f]{64}$'
    ),

    -- Only the genesis entry may carry the all-zero predecessor, and it must.
    CONSTRAINT chain_genesis_is_index_zero CHECK (
        (chain_index = 0) = (prev_hash = repeat('0', 64))
    )
);

CREATE INDEX chain_bundle_idx ON sch_evidence.hash_chain (tenant_id, bundle_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- tsa_tokens — RFC 3161 tokens, appended (D-22)
--
-- A separate table rather than a column on evidence_bundles. The token arrives
-- after the bundle is committed, so a column would mean an UPDATE against an
-- append-only table — and a mutable tsa_status is exactly how a bundle would
-- come to read "verified" without a token behind it.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.tsa_tokens (
    tenant_id           uuid        NOT NULL,
    bundle_id           uuid        NOT NULL,
    bundle_captured_at  timestamptz NOT NULL,
    manifest_sha256     char(64)    NOT NULL,
    authority_url       text        NOT NULL,
    token               bytea       NOT NULL,
    obtained_at         timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, bundle_id, authority_url, obtained_at),

    CONSTRAINT tsa_bundle_fk FOREIGN KEY (bundle_id, bundle_captured_at)
        REFERENCES sch_evidence.evidence_bundles (bundle_id, captured_at),
    CONSTRAINT tsa_token_not_empty CHECK (octet_length(token) > 0),
    CONSTRAINT tsa_digest_is_lower_hex CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX tsa_bundle_idx ON sch_evidence.tsa_tokens (tenant_id, bundle_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Initial partitions
--
-- A missing future partition is an outage, not a warning: an INSERT with no
-- matching partition fails outright. These cover the walking skeleton; the
-- partition-creation job that runs ahead of time lands with the scheduler.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.captures_2026_08 PARTITION OF sch_evidence.captures
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE sch_evidence.captures_2026_09 PARTITION OF sch_evidence.captures
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE sch_evidence.captures_2026_10 PARTITION OF sch_evidence.captures
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE sch_evidence.evidence_bundles_2026_08 PARTITION OF sch_evidence.evidence_bundles
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE sch_evidence.evidence_bundles_2026_09 PARTITION OF sch_evidence.evidence_bundles
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE sch_evidence.evidence_bundles_2026_10 PARTITION OF sch_evidence.evidence_bundles
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

-- ─────────────────────────────────────────────────────────────────────────────
-- Row-Level Security (D-82, V-7)
--
-- FORCE is not optional. Without it the table owner is exempt from the policy,
-- and "the owner can see everything" is the permission V-7 forbids. The tenant
-- comes from a session GUC set by the connection pool per request; an unset
-- GUC yields NULL, which matches no row — closed by default rather than open.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION sch_evidence.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('asip.tenant_id', true), '')::uuid $$;

ALTER TABLE sch_evidence.captures          ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.captures          FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.evidence_bundles  ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.evidence_bundles  FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.hash_chain        ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.hash_chain        FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.tsa_tokens        ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.tsa_tokens        FORCE  ROW LEVEL SECURITY;

CREATE POLICY captures_tenant_isolation ON sch_evidence.captures
    USING (tenant_id = sch_evidence.current_tenant())
    WITH CHECK (tenant_id = sch_evidence.current_tenant());

CREATE POLICY bundles_tenant_isolation ON sch_evidence.evidence_bundles
    USING (tenant_id = sch_evidence.current_tenant())
    WITH CHECK (tenant_id = sch_evidence.current_tenant());

CREATE POLICY chain_tenant_isolation ON sch_evidence.hash_chain
    USING (tenant_id = sch_evidence.current_tenant())
    WITH CHECK (tenant_id = sch_evidence.current_tenant());

CREATE POLICY tsa_tenant_isolation ON sch_evidence.tsa_tokens
    USING (tenant_id = sch_evidence.current_tenant())
    WITH CHECK (tenant_id = sch_evidence.current_tenant());

-- ─────────────────────────────────────────────────────────────────────────────
-- Grants — append-only enforced mechanically
--
-- No UPDATE. No DELETE. Not for the application role, not for anyone reachable
-- from application code. If a future migration needs to hand out UPDATE on one
-- of these tables, the change is wrong, not the grant.
-- ─────────────────────────────────────────────────────────────────────────────

-- Nothing reaches these tables by default. PUBLIC is revoked explicitly rather
-- than relied upon to be empty.
REVOKE ALL ON ALL TABLES IN SCHEMA sch_evidence FROM PUBLIC;

GRANT SELECT, INSERT ON
    sch_evidence.captures,
    sch_evidence.evidence_bundles,
    sch_evidence.hash_chain,
    sch_evidence.tsa_tokens
TO asip_app;

-- OPERATIONAL REQUIREMENT — the application must never connect as the role
-- that owns this schema.
--
-- A table's owner keeps every privilege on it and can re-grant at will, so the
-- append-only guarantee above is a property of *which role the application
-- connects as*, not something the grants can enforce on their own. The owner
-- role is for migrations only. FORCE ROW LEVEL SECURITY limits which rows the
-- owner sees; it does not stop the owner rewriting them.

-- Retention expiry (D-54) is the single audited exception, and it deletes
-- only — it can no more rewrite a record than the application can.
GRANT SELECT, DELETE ON
    sch_evidence.captures,
    sch_evidence.evidence_bundles,
    sch_evidence.hash_chain,
    sch_evidence.tsa_tokens
TO asip_retention;

-- ─────────────────────────────────────────────────────────────────────────────
-- Published read views (D-92)
--
-- The contract with other modules. Columns may be added; never removed, never
-- retyped, without a version bump. Note what is absent: object_prefix and the
-- manifest itself are not published, because no other module has any business
-- reaching into the object store directly.
-- ─────────────────────────────────────────────────────────────────────────────

-- security_invoker is load-bearing, not a detail. A PostgreSQL view executes
-- with its *owner's* privileges by default, so a view owned by the migration
-- role runs as that role and RLS on the underlying tables never applies to the
-- caller. Without this setting the view returns every tenant's rows to any
-- caller — verified: the isolation suite caught exactly that. Since D-92
-- routes all cross-module reads through published views, every future view in
-- this system needs this option or it is a cross-tenant leak by construction.
CREATE VIEW sch_evidence.v_bundles_for_review WITH (security_invoker = true) AS
    SELECT b.bundle_id,
           b.tenant_id,
           b.capture_id,
           b.trace_id,
           b.source_url,
           b.captured_at,
           b.manifest_sha256,
           c.chain_index,
           EXISTS (
               SELECT 1 FROM sch_evidence.tsa_tokens t
               WHERE t.tenant_id = b.tenant_id AND t.bundle_id = b.bundle_id
           ) AS has_timestamp
    FROM sch_evidence.evidence_bundles b
    JOIN sch_evidence.hash_chain c
      ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id;

GRANT SELECT ON sch_evidence.v_bundles_for_review TO asip_app;
