-- Drops the partitions this migration added, INCLUDING ANY ROWS IN THEM.
--
-- Rolling this back after real collection has run destroys every item posted
-- outside 2026-08..2026-11. That is the honest consequence of un-widening a
-- partition range and there is no version of it that keeps the data: the parent
-- has nowhere to put those rows once these partitions are gone.
--
-- Export before running this against anything that has collected.

DROP TABLE IF EXISTS sch_extraction.content_unpartitioned;

DO $$
DECLARE
    start_month date := date '2024-01-01';
    last_month  date := date '2027-12-01';
    m           date;
    part        text;
BEGIN
    m := start_month;
    WHILE m <= last_month LOOP
        -- The four this migration did not create stay: they belong to 001.
        IF to_char(m, 'YYYY_MM') NOT IN ('2026_08', '2026_09', '2026_10', '2026_11') THEN
            part := format('content_%s', to_char(m, 'YYYY_MM'));
            EXECUTE format('DROP TABLE IF EXISTS sch_extraction.%I', part);
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
END $$;
