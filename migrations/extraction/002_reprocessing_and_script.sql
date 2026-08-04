-- Reprocessing (D-13), and a V-2 tightening found while enabling it.
--
-- Three changes:
--   1. a `script` column, produced by extractor v2
--   2. UPDATE on the derived columns, so a reprocess can correct them
--   3. `lang` removed from the detection read view
--
-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Script
--
-- Which alphabet an item is written in. Georgian is first-class in this product
-- (D-63) and knowing which items use it matters for display, font selection and
-- eventually for choosing an embedding model. A property of the characters, not
-- of the opinion.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE sch_extraction.content ADD COLUMN script text;

ALTER TABLE sch_extraction.content
    ADD CONSTRAINT content_script_known CHECK (
        script IS NULL OR script IN ('georgian', 'latin', 'cyrillic', 'arabic', 'mixed')
    );

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Derived content is correctable. Captures are not.
--
-- D-13's whole premise is that a capture is fetched once and parsed many times.
-- That is only true if a newer extractor can WRITE its improved output over the
-- old, which needs UPDATE — and the original grants gave INSERT only, by
-- analogy with the evidence tables.
--
-- The analogy is wrong in the same way it was wrong for sources. A capture is
-- evidence and is immutable because rewriting it destroys what makes it
-- evidence. Extracted content is a *derivation* from that evidence: it can be
-- recomputed at any time from something that has not changed, so correcting it
-- loses nothing and refusing to correct it forces a refetch — the exact cost
-- D-13 exists to avoid.
--
-- Note what stays ungranted: capture_id, source_id, account_id, trace_id and
-- posted_at_authoritative. A reprocess may improve how an item was read; it may
-- not change which capture it came from or when it was posted. Those are the
-- item's identity, and a reprocess that rewrote them would be inventing a
-- different observation rather than re-reading the same one.
-- ─────────────────────────────────────────────────────────────────────────────

GRANT UPDATE (text, text_sha256, lang, script, timestamp_precision, extractor_version)
    ON sch_extraction.content TO asip_app;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. V-2 — `lang` leaves the detection view
--
-- The view was already correct about the important thing: it does not publish
-- `text`. But it published `lang`, which is derived from the text, and V-2 says
-- the authenticity path must not read content or stance. A language label is a
-- content-derived attribute, and a rule that could see it could learn to treat
-- one language's activity as more suspicious than another's. That is precisely
-- the failure the veto exists to prevent, arriving through a column nobody
-- thought of as content.
--
-- `script` is not published here either, for the same reason.
--
-- Detection keeps what is behavioural: who acted, when, from which capture.
-- ─────────────────────────────────────────────────────────────────────────────

DROP VIEW IF EXISTS sch_extraction.v_content_for_detection;

CREATE VIEW sch_extraction.v_content_for_detection WITH (security_invoker = true) AS
    SELECT content_id, tenant_id, source_id, account_id, capture_id, trace_id,
           posted_at_authoritative, timestamp_precision, text_sha256, first_seen
      FROM sch_extraction.content
     WHERE deleted_at IS NULL;

GRANT SELECT ON sch_extraction.v_content_for_detection TO asip_app;

-- What reprocessing needs to find work: captures whose content was produced by
-- an older extractor. Published so the console can show how much is pending.
CREATE VIEW sch_extraction.v_reprocessing_backlog WITH (security_invoker = true) AS
    SELECT tenant_id,
           capture_id,
           min(extractor_version) AS oldest_extractor_version,
           count(*)               AS items
      FROM sch_extraction.content
     WHERE deleted_at IS NULL
     GROUP BY tenant_id, capture_id;

GRANT SELECT ON sch_extraction.v_reprocessing_backlog TO asip_app;
