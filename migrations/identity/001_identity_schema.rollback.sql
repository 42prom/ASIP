-- Drops the schema, including the audit log.
--
-- Note what this means: rolling back identity destroys the record of who did
-- what. In development that is fine. In any environment holding real audit
-- history, exporting the chain first is not optional — an audit log that can be
-- rolled away is not an audit log (D-51).
DROP SCHEMA IF EXISTS sch_identity CASCADE;
