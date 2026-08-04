-- Rollback of 002_manifest_document_and_anchors.
--
-- Tested by tests/isolation/test_migration_rollback.py, which applies every
-- migration, rolls each back, and applies again.
--
-- Reverting manifest storage to JSONB is lossy: JSONB reorders keys and
-- rewrites whitespace, so a manifest that survives this round trip may no
-- longer hash to its attested digest. Harmless while the table is empty, which
-- it is; on a populated database this rollback destroys verifiability and the
-- correct response to a problem with 002 is a forward migration instead.

DROP VIEW IF EXISTS sch_evidence.v_bundles_for_review;

DROP TABLE IF EXISTS sch_evidence.chain_anchors;

ALTER TABLE sch_evidence.hash_chain
    DROP CONSTRAINT IF EXISTS chain_algorithm_known;
ALTER TABLE sch_evidence.hash_chain
    DROP COLUMN IF EXISTS algorithm;

ALTER TABLE sch_evidence.evidence_bundles
    DROP CONSTRAINT IF EXISTS bundles_manifest_is_json_with_artifacts;

ALTER TABLE sch_evidence.evidence_bundles
    ALTER COLUMN manifest TYPE jsonb USING manifest::jsonb;

ALTER TABLE sch_evidence.evidence_bundles
    ADD CONSTRAINT bundles_manifest_not_empty CHECK (
        jsonb_array_length(manifest -> 'artifacts') >= 1
    );

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
