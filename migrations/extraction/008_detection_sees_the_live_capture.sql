-- Detection needs a capture that still exists, not only the first one.
--
-- WHAT HAPPENED
--
-- A finding was refused by its own V-5 constraint:
--
--     new row for relation "findings" violates check constraint
--     "findings_evidence_required"
--
-- The cluster resolved to zero evidence bundles. Its items' `capture_id` is the
-- capture that FIRST saw them — the provenance claim, deliberately frozen by
-- migration 003 — and that capture's bundle no longer existed.
--
-- The constraint was right and the pipeline was wrong. A finding must rest on
-- evidence; one that cannot name a surviving bundle must not be written. But
-- the situation is ordinary, not exceptional:
--
--   * retention expires old captures while content rows outlive them (D-54)
--   * a per-module rollback can drop sch_evidence and orphan every reference
--   * a long-running item is re-observed for months after its first capture
--
-- In all three the item is still evidenced — by the capture that saw it MOST
-- RECENTLY, which migration 003 already tracks as last_capture_id. Detection
-- simply could not see that column.
--
-- WHY BOTH, AND WHY capture_id STAYS FIRST
--
-- first-seen is the provenance claim and answers "when did this appear".
-- last-seen answers "which surviving capture proves it". They are different
-- questions and the evidence path wants the second. Publishing only the second
-- would lose the first; publishing only the first is what broke.
--
-- V-2 is untouched: both are identifiers of a capture, neither is derived from
-- text. The test for V-2 is not "is this text" but "is this derived from text".

DROP VIEW IF EXISTS sch_extraction.v_content_for_detection;

CREATE VIEW sch_extraction.v_content_for_detection WITH (security_invoker = true) AS
    SELECT content_id, tenant_id, source_id, account_id,
           capture_id,
           last_capture_id,
           trace_id, posted_at_authoritative, timestamp_precision, text_sha256,
           first_seen, last_seen
      FROM sch_extraction.content
     WHERE deleted_at IS NULL;

COMMENT ON VIEW sch_extraction.v_content_for_detection IS
    'D-92 published contract, and the physical enforcement of V-2: no text, no '
    'lang, no script. capture_id is where an item was first seen (provenance); '
    'last_capture_id is the most recent capture containing it, which is what '
    'the evidence path should cite because it is the one likely to still exist.';

GRANT SELECT ON sch_extraction.v_content_for_detection TO asip_app;
