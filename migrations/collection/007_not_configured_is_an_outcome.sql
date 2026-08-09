-- "No acquisition route is configured" is a fetch outcome, and the taxonomy
-- had nowhere to put it.
--
-- D-113 is why the status column is a taxonomy rather than a boolean: a
-- failure we caused and a failure the platform caused need different
-- responses, and collapsing them hides a broken fetcher behind "the site was
-- down". This is a third kind again — nothing was attempted at all.
--
-- The distinction is operational, not pedantic:
--
--   failed_network          transient. Retry.
--   failed_blocked          they refused us. Back off, review the source.
--   failed_not_configured   we never tried. Retrying forever changes nothing;
--                           somebody has to make a decision (O-03).
--
-- Without this row the constraint would have rejected the job update and the
-- pipeline would have died on the first Facebook source — a CHECK doing its
-- job, on a value the application had no business inventing.
--
-- Found by a unit test asserting the status differs from failed_network, which
-- prompted checking whether the database agreed it existed. It did not.

ALTER TABLE sch_collection.fetch_jobs
    DROP CONSTRAINT IF EXISTS fetch_jobs_status_taxonomy;

ALTER TABLE sch_collection.fetch_jobs
    ADD CONSTRAINT fetch_jobs_status_taxonomy CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed_network',
                   'failed_timeout', 'failed_blocked', 'failed_not_found',
                   'failed_parse', 'failed_internal', 'failed_not_configured')
    );

COMMENT ON CONSTRAINT fetch_jobs_status_taxonomy ON sch_collection.fetch_jobs IS
    'D-113. Distinct causes get distinct statuses so an operator can tell a '
    'transient failure from a refusal from a missing decision.';
