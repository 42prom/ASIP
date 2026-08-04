-- Rollback of 001_evidence_schema.
--
-- Tested, not merely written: tests/isolation/test_evidence_migration.py applies
-- this migration, rolls it back, and applies it again against a live database.
--
-- DROP SCHEMA CASCADE takes the tables, their partitions, the policies, the
-- views and the grants with it. The roles are left in place deliberately —
-- they are shared across modules, and dropping a role that another schema's
-- grants still reference would fail and leave the rollback half-applied.
--
-- Backfill: none. This migration creates empty tables, so there is nothing to
-- rewrite and nothing to estimate. Rolling it back on a populated database
-- destroys evidence, which is why it is the retention job (D-54) and not this
-- file that removes data in production.

DROP SCHEMA IF EXISTS sch_evidence CASCADE;
