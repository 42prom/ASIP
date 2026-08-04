-- Content must record that it was seen again (D-24), and reprocessing needs a
-- capture whose bytes still exist (D-13).
--
-- THE BUG THIS FIXES
--
-- Content ids are deterministic UUIDv5 over (platform, external_id), which is
-- correct and is what makes reprocessing idempotent (M-10). But `insert_content`
-- used ON CONFLICT DO NOTHING, so every re-observation of an item already seen
-- was silently discarded — including its capture_id.
--
-- The result: an item stayed bound forever to the FIRST capture that produced
-- it, while later captures and bundles accumulated with no content pointing at
-- them. Three things broke, all quietly:
--
--   * D-24 — last_seen was never updated, so "when did we last observe this"
--     had no answer and deletion detection had nothing to compare against.
--   * D-13 — reprocessing looked up the original capture, which retention will
--     eventually expire, after which the item can never be re-parsed even
--     though a perfectly good later capture of the same page exists.
--   * D-112 — a finding traced back to a capture that may predate it by weeks.
--
-- Found by the walking skeleton doing exactly what it is for: the reprocess
-- reported "capture unavailable" for an item whose page had been captured
-- minutes earlier.
--
-- first_seen keeps its meaning: the first time this item was observed, which is
-- the provenance claim. last_capture_id is the most recent capture containing
-- it, which is what re-parsing should read.

-- D-24 requires first_seen AND last_seen on every object. The table shipped
-- with only first_seen, which was survivable while nothing was ever observed
-- twice and became wrong the moment re-observation was recorded at all.
-- Deletion detection (D-25) compares against last_seen, so its absence would
-- have surfaced later as a feature that could not be built.
ALTER TABLE sch_extraction.content
    ADD COLUMN last_seen timestamptz NOT NULL DEFAULT now();

ALTER TABLE sch_extraction.content
    ADD COLUMN last_capture_id uuid;

-- Existing rows have only ever been seen once, so their first capture is also
-- their last. No backfill cost — the table is small and this is a single pass.
UPDATE sch_extraction.content
   SET last_capture_id = capture_id, last_seen = first_seen
 WHERE last_capture_id IS NULL;

ALTER TABLE sch_extraction.content
    ALTER COLUMN last_capture_id SET NOT NULL;

CREATE INDEX content_last_capture_idx
    ON sch_extraction.content (tenant_id, last_capture_id);

-- Re-observation updates these three and nothing else. capture_id stays put:
-- it records where the item was FIRST seen, and rewriting it would destroy the
-- provenance of the original observation.
GRANT UPDATE (last_seen, last_capture_id, deleted_at)
    ON sch_extraction.content TO asip_app;

-- Reprocessing reads the most recent capture, not the original, so an item
-- stays re-parseable for as long as ANY capture containing it survives.
DROP VIEW IF EXISTS sch_extraction.v_reprocessing_backlog;

CREATE VIEW sch_extraction.v_reprocessing_backlog WITH (security_invoker = true) AS
    SELECT tenant_id,
           last_capture_id        AS capture_id,
           min(extractor_version) AS oldest_extractor_version,
           count(*)               AS items
      FROM sch_extraction.content
     WHERE deleted_at IS NULL
     GROUP BY tenant_id, last_capture_id;

GRANT SELECT ON sch_extraction.v_reprocessing_backlog TO asip_app;
