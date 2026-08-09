-- Drops the constraint. The rows deleted when it was applied are not restored:
-- they were duplicates of surviving rows and their captures still exist.
ALTER TABLE sch_collection.sources
    DROP CONSTRAINT IF EXISTS sources_url_unique_per_tenant;
