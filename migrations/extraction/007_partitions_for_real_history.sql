-- Real platform data has a past. The canary never did.
--
-- WHAT HAPPENED
--
-- The first fetch of a real Telegram channel died with
--
--     CheckViolation: no partition of relation "content" found for row
--
-- `content` is range-partitioned on posted_at_authoritative and covered
-- 2026-08 through 2026-11. Every canary item is posted "just now", so four
-- months forward looked like plenty. The first real channel returned posts from
-- April, and the entire extraction batch aborted.
--
-- This could not have been found with synthetic data, and it would have been
-- found on the first day of the first client. A source's history is the most
-- valuable thing about it — a coordination network is visible in what it did
-- last month, not only in what it does while we watch.
--
-- TWO FIXES, BECAUSE ONE IS NOT ENOUGH
--
-- 1. Cover a real range: monthly from 2024-01 to 2027-12. Backwards because
--    platforms serve history; forwards because nobody should have to run a
--    migration to keep collecting next year.
--
-- 2. A DEFAULT partition, so an item outside every range is STORED rather than
--    aborting the batch that contained it. Losing forty extracted posts because
--    one of them is from 2019 is the wrong trade: the row is evidence, and
--    evidence is the thing this system exists not to drop.
--
-- WHY A DEFAULT PARTITION IS NORMALLY A MISTAKE, AND WHY IT IS RIGHT HERE
--
-- It defeats pruning for queries that could otherwise skip it, and attaching a
-- new partition later must scan it for conflicting rows. Both real costs. They
-- are worth paying because the alternative failure is data loss during
-- ingestion, and because rows arriving there are a SIGNAL: the default filling
-- up means partition maintenance is behind, which is exactly the kind of slow
-- rot that is invisible until it is urgent (D-87).
--
-- So the default is not a silent catch-all. The health check counts it, and a
-- non-zero count is reported as something to act on.

DO $$
DECLARE
    start_month date := date '2024-01-01';
    last_month  date := date '2027-12-01';
    m           date;
    part        text;
BEGIN
    m := start_month;
    WHILE m <= last_month LOOP
        part := format('content_%s', to_char(m, 'YYYY_MM'));
        IF to_regclass(format('sch_extraction.%I', part)) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE sch_extraction.%I PARTITION OF sch_extraction.content '
                'FOR VALUES FROM (%L) TO (%L)',
                part, m, m + interval '1 month'
            );
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
END $$;

-- The floor. Anything outside every range above lands here rather than
-- aborting the insert that carried it.
CREATE TABLE IF NOT EXISTS sch_extraction.content_unpartitioned
    PARTITION OF sch_extraction.content DEFAULT;

COMMENT ON TABLE sch_extraction.content_unpartitioned IS
    'Items whose posted_at falls outside every monthly partition. Not an error '
    'state — the row is kept rather than lost — but a non-zero count means '
    'partition maintenance is behind. Reported by /api/health/tenant.';

-- RLS is not inherited by a partition created after the parent was configured
-- in some Postgres versions, and getting this wrong on one partition would be a
-- cross-tenant leak on exactly the rows nobody is watching (V-7). Applied
-- explicitly to every partition, existing and new.
DO $$
DECLARE
    part record;
BEGIN
    FOR part IN
        SELECT c.oid::regclass AS name
          FROM pg_class c
          JOIN pg_inherits i ON i.inhrelid = c.oid
          JOIN pg_class p ON p.oid = i.inhparent
          JOIN pg_namespace n ON n.oid = p.relnamespace
         WHERE p.relname = 'content' AND n.nspname = 'sch_extraction'
    LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', part.name);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', part.name);
    END LOOP;
END $$;
