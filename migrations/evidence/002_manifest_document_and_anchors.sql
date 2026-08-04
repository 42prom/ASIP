-- Evidence, second migration. Three changes, all aimed at the twenty-year case.
--
-- 1. The manifest is stored as TEXT, not JSONB.
-- 2. The hash chain records its own digest algorithm.
-- 3. Chain anchors: periodic external attestation of the chain head.
--
-- Backfill: none. sch_evidence is empty — the walking skeleton has produced no
-- retained bundles, and evidence written before this migration would in any
-- case have used the pre-v1 preimage. Applying to a populated database would
-- require a rewrite of manifest storage, which is why this lands now.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Manifest as TEXT
--
-- JSONB normalises: it reorders keys, collapses whitespace, and rewrites number
-- formatting. Those are useful properties for a document you query and fatal
-- ones for a document you hash. A manifest stored as JSONB and read back would
-- not necessarily hash to the digest that was attested and timestamped.
--
-- TEXT preserves the bytes exactly as written, so the database copy and the
-- archive copy agree and either can be used to verify the other. Querying into
-- the manifest is still possible via manifest::jsonb where needed; what is not
-- possible is the database silently changing evidence.
-- ─────────────────────────────────────────────────────────────────────────────

-- The old constraint uses the jsonb -> operator, so it has to go before the
-- column stops being jsonb. Dropping it after would fail with "operator does
-- not exist: text -> text" — PostgreSQL re-checks constraint expressions
-- against the new type as part of the ALTER.
ALTER TABLE sch_evidence.evidence_bundles
    DROP CONSTRAINT IF EXISTS bundles_manifest_not_empty;

-- The published view reads this column, so it must be dropped first too.
DROP VIEW IF EXISTS sch_evidence.v_bundles_for_review;

ALTER TABLE sch_evidence.evidence_bundles
    ALTER COLUMN manifest TYPE text USING manifest::text;

-- The manifest must still be a JSON document and must still list at least one
-- artifact. Checked by casting at read time rather than by storing as JSONB,
-- which keeps validation without giving up byte fidelity.

ALTER TABLE sch_evidence.evidence_bundles
    ADD CONSTRAINT bundles_manifest_is_json_with_artifacts CHECK (
        jsonb_array_length((manifest::jsonb) -> 'artifacts') >= 1
    );

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Algorithm agility on the chain
--
-- SHA-256 will not be the right answer for the whole life of this evidence. An
-- entry that names its own algorithm can be succeeded by one using a stronger
-- algorithm without invalidating anything, because a predecessor's hash is an
-- opaque string to its successor. A chain that hard-codes its algorithm can
-- only be migrated by rewriting history, which append-only forbids.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE sch_evidence.hash_chain
    ADD COLUMN algorithm text NOT NULL DEFAULT 'sha256';

ALTER TABLE sch_evidence.hash_chain
    ADD CONSTRAINT chain_algorithm_known CHECK (algorithm IN ('sha256', 'sha384', 'sha512'));

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Chain anchors
--
-- The gap this closes: a hash chain proves nobody edited *one* record, because
-- editing one breaks the links after it. It does not stop someone with write
-- access rebuilding the chain from genesis — every entry recomputed, every link
-- consistent, the whole history quietly replaced. Nothing inside the chain can
-- detect that, because the forged chain is internally perfect.
--
-- An anchor is an RFC 3161 token over the chain head at a moment in time. Once
-- an anchor exists, history before it cannot be rewritten without producing a
-- chain whose head disagrees with a third party's signed record of what that
-- head was. Anchors are cheap — one token per tenant per interval, regardless
-- of how many bundles were sealed — and they are what turns the chain from
-- tamper-evident-against-edits into tamper-evident-against-replacement.
--
-- Append-only like everything else here: an anchor is never updated, and a
-- disagreement between two anchors is itself the finding.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sch_evidence.chain_anchors (
    tenant_id           uuid        NOT NULL,
    anchored_at         timestamptz NOT NULL,
    chain_index         bigint      NOT NULL,
    entry_hash          char(64)    NOT NULL,
    algorithm           text        NOT NULL DEFAULT 'sha256',
    authority_url       text        NOT NULL,
    token               bytea       NOT NULL,

    PRIMARY KEY (tenant_id, anchored_at, authority_url),

    CONSTRAINT anchor_hash_is_lower_hex CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT anchor_index_non_negative CHECK (chain_index >= 0),
    CONSTRAINT anchor_token_not_empty CHECK (octet_length(token) > 0)
);

CREATE INDEX chain_anchors_tenant_idx
    ON sch_evidence.chain_anchors (tenant_id, chain_index DESC);

ALTER TABLE sch_evidence.chain_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_evidence.chain_anchors FORCE  ROW LEVEL SECURITY;

CREATE POLICY anchors_tenant_isolation ON sch_evidence.chain_anchors
    USING (tenant_id = sch_evidence.current_tenant())
    WITH CHECK (tenant_id = sch_evidence.current_tenant());

GRANT SELECT, INSERT ON sch_evidence.chain_anchors TO asip_app;
GRANT SELECT, DELETE ON sch_evidence.chain_anchors TO asip_retention;

-- ─────────────────────────────────────────────────────────────────────────────
-- Published view — recreated because its underlying column changed type.
-- security_invoker stays set: without it the view runs as its owner and RLS on
-- the tables below it never applies to the caller (see migration 001).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE VIEW sch_evidence.v_bundles_for_review WITH (security_invoker = true) AS
    SELECT b.bundle_id,
           b.tenant_id,
           b.capture_id,
           b.trace_id,
           b.source_url,
           b.captured_at,
           b.manifest_sha256,
           c.chain_index,
           c.algorithm AS chain_algorithm,
           EXISTS (
               SELECT 1 FROM sch_evidence.tsa_tokens t
               WHERE t.tenant_id = b.tenant_id AND t.bundle_id = b.bundle_id
           ) AS has_timestamp
    FROM sch_evidence.evidence_bundles b
    JOIN sch_evidence.hash_chain c
      ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id;

GRANT SELECT ON sch_evidence.v_bundles_for_review TO asip_app;
