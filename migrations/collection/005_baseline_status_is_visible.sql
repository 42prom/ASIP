-- The 30-day clock, made visible (D-31, D-80).
--
-- WHY THIS IS THE FIRST THING THE COLLECTION PHASE NEEDS
--
-- MASTER_PLAN §5.4: "collection must start one month before you intend to
-- demonstrate any analytics. baseline_status (collecting / ready / stale) is
-- visible in the UI."
--
-- D-80 makes `baseline_ready` an implicit condition on EVERY rule: a rule may
-- not fire against a source whose baseline is still collecting. So during the
-- first month the honest state of the product is "we are watching and cannot
-- yet tell you anything", and that has to be legible. Otherwise a month of
-- empty Findings screens reads as "no coordinated activity here" — which is
-- the D-68 failure at its most expensive, because it is sustained and
-- confident and wrong.
--
-- WHAT THIS IS AND IS NOT
--
-- This is the STATUS, not the baseline. The baseline itself — volume by hour,
-- commenter overlap, reply-latency distributions — is modules/baseline/, which
-- does not exist yet. Recording when observation began costs nothing now and
-- cannot be reconstructed later: if collection runs for three weeks before
-- anyone adds this column, those three weeks are unattributable.
--
-- Start the clock first. Build the model while it ticks.

ALTER TABLE sch_collection.sources
    ADD COLUMN IF NOT EXISTS baseline_status text NOT NULL DEFAULT 'collecting',
    -- When continuous observation of THIS source began. Distinct from
    -- created_at: a source disabled for a fortnight and resumed has a gap, and
    -- a baseline computed across a gap describes a period that did not happen.
    ADD COLUMN IF NOT EXISTS observing_since timestamptz;

ALTER TABLE sch_collection.sources
    ADD CONSTRAINT sources_baseline_status_known
    CHECK (baseline_status IN ('collecting', 'ready', 'stale'));

COMMENT ON COLUMN sch_collection.sources.baseline_status IS
    'D-80: a rule cannot fire against a source that is not ready. '
    'collecting = too little history yet; ready = usable; stale = observation '
    'lapsed and the baseline no longer describes the present.';

COMMENT ON COLUMN sch_collection.sources.observing_since IS
    'Start of the CURRENT unbroken observation run, reset when collection '
    'resumes after a gap. A baseline computed across a gap describes a period '
    'that did not happen.';

-- Existing sources have been observed since their first successful fetch, if
-- there was one. Derived rather than defaulted to now(): claiming today would
-- reset a clock that has genuinely been running.
UPDATE sch_collection.sources s
   SET observing_since = h.last_success_at
  FROM sch_collection.source_health h
 WHERE h.source_id = s.source_id
   AND s.observing_since IS NULL
   AND h.last_success_at IS NOT NULL;

GRANT UPDATE (baseline_status, observing_since) ON sch_collection.sources TO asip_app;

-- ─────────────────────────────────────────────────────────────────────────────
-- Published so the console can show the clock without reaching into the table.
--
-- `observed_days` is computed here rather than in the application: it is the
-- number the whole first month is judged by, and two callers computing it
-- slightly differently would disagree about whether a rule may fire.
-- ─────────────────────────────────────────────────────────────────────────────
DROP VIEW IF EXISTS sch_collection.v_sources_for_display;

CREATE VIEW sch_collection.v_sources_for_display
    WITH (security_invoker = true) AS
    SELECT s.source_id, s.tenant_id, s.project_id, s.name, s.url, s.platform,
           s.priority, s.enabled, s.is_canary, s.interval_seconds,
           s.baseline_status, s.observing_since,
           CASE
               WHEN s.observing_since IS NULL THEN 0
               ELSE floor(EXTRACT(EPOCH FROM (now() - s.observing_since)) / 86400)::int
           END AS observed_days,
           h.last_attempt_at, h.last_success_at, h.consecutive_failures,
           h.last_failure_reason
      FROM sch_collection.sources s
      LEFT JOIN sch_collection.source_health h ON h.source_id = s.source_id;

GRANT SELECT ON sch_collection.v_sources_for_display TO asip_app;
