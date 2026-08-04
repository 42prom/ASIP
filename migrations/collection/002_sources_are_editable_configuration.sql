-- Sources are configuration, and configuration is meant to be corrected.
--
-- The original grants gave asip_app INSERT only, by analogy with the evidence
-- tables. That analogy is wrong. Evidence is append-only because rewriting it
-- destroys the thing that makes it evidence; a watchlist entry has no such
-- property. Making sources immutable did not protect anything — it just meant
-- a source seeded with a wrong URL could never be repaired through the
-- application, and the only remedy was hand-editing the database, which is
-- exactly the habit this schema exists to make unnecessary.
--
-- Found the hard way: the canary was repointed at a hostname only resolvable
-- from inside a container, and `make seed-dev` could not put it back.
--
-- Note what is still NOT granted: DELETE. Removing a source would orphan the
-- captures and findings that reference it, and retiring one is what `enabled`
-- is for. Retention (D-54) remains the only path that removes rows.

GRANT UPDATE (name, url, platform, priority, enabled, is_canary, interval_seconds)
    ON sch_collection.sources TO asip_app;
