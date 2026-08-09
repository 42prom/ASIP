-- Reprocessing must re-parse a capture with the reader that produced it.
--
-- THE BUG THIS PREVENTS
--
-- `ReprocessCaptures.execute` took a `platform` argument, defaulted it to
-- "canary", and never used it. With one platform that was invisible. With a
-- second, re-parsing a Telegram capture would run the canary reader over it,
-- find nothing, and report "page yielded fewer items than expected" — which
-- reads as the site changing shape rather than as us using the wrong reader.
--
-- Worse than a plain failure: D-13 exists so a newer extractor can re-read old
-- captures, and a reprocess that silently blanks them would destroy extracted
-- content that was previously correct.
--
-- The platform is a property of the account the item came from, and accounts
-- live in this same schema — so the backlog can answer it without crossing a
-- module boundary (D-93).
--
-- Grouped per capture AND platform rather than assuming one platform per
-- capture. A capture is one page from one source today; asserting that in a
-- GROUP BY would bake in an assumption nobody has promised to keep.

DROP VIEW IF EXISTS sch_extraction.v_reprocessing_backlog;

CREATE VIEW sch_extraction.v_reprocessing_backlog WITH (security_invoker = true) AS
    SELECT c.tenant_id,
           c.last_capture_id        AS capture_id,
           a.platform,
           min(c.extractor_version) AS oldest_extractor_version,
           count(*)                 AS items
      FROM sch_extraction.content c
      JOIN sch_extraction.accounts a ON a.account_id = c.account_id
     WHERE c.deleted_at IS NULL
     GROUP BY c.tenant_id, c.last_capture_id, a.platform;

COMMENT ON VIEW sch_extraction.v_reprocessing_backlog IS
    'D-92 published contract: captures whose content predates the current '
    'extractor, with the platform whose reader must re-parse them (D-13).';

GRANT SELECT ON sch_extraction.v_reprocessing_backlog TO asip_app;
