-- Rolling back rejects any job already recorded as failed_not_configured, so
-- those are moved to failed_internal first. Less accurate, and the alternative
-- is a constraint that cannot be applied.
UPDATE sch_collection.fetch_jobs
   SET status = 'failed_internal'
 WHERE status = 'failed_not_configured';

ALTER TABLE sch_collection.fetch_jobs
    DROP CONSTRAINT IF EXISTS fetch_jobs_status_taxonomy;

ALTER TABLE sch_collection.fetch_jobs
    ADD CONSTRAINT fetch_jobs_status_taxonomy CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed_network',
                   'failed_timeout', 'failed_blocked', 'failed_not_found',
                   'failed_parse', 'failed_internal')
    );
