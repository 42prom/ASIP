-- One URL, one source, per tenant.
--
-- WHAT WENT WRONG
--
-- A channel added through the form got a random source_id; the same channel
-- pasted into the bulk list got a deterministic one derived from its URL. Two
-- rows, same page. Both fetched on every tick.
--
-- WHY THAT MATTERS MORE THAN IT LOOKS
--
--   * Every duplicate doubles the fetch cost of that source forever, and D-13
--     is in this codebase because fetching is the expensive operation.
--   * It doubles the captures and therefore the storage, for bytes that are
--     identical.
--   * It is impolite to the source, which sees twice the traffic it should
--     (V-6 — honest rate limiting is the boundary this project accepts).
--   * The two rows have independent observing_since values, so a tenant can
--     have one copy "ready" and another "collecting" for the same channel, and
--     D-80 would give different answers depending on which was queried.
--
-- The constraint is the fix rather than a deduplication script, because the
-- second row is not a data error to clean up — it is a shape the table should
-- never have allowed.
--
-- Scoped per tenant, not global: two clients legitimately watching the same
-- public channel is normal, and merging them would be a cross-tenant leak of
-- the most basic kind (V-7).

-- Keep the oldest row per (tenant, url) — it has the longest observation
-- history, which is the thing that cannot be recreated. Health rows go first
-- because they reference the source.
DELETE FROM sch_collection.source_health h
 USING sch_collection.sources s, sch_collection.sources keep
 WHERE h.source_id = s.source_id
   AND keep.tenant_id = s.tenant_id
   AND keep.url = s.url
   AND keep.created_at < s.created_at;

DELETE FROM sch_collection.sources s
 USING sch_collection.sources keep
 WHERE keep.tenant_id = s.tenant_id
   AND keep.url = s.url
   AND keep.created_at < s.created_at;

ALTER TABLE sch_collection.sources
    ADD CONSTRAINT sources_url_unique_per_tenant UNIQUE (tenant_id, url);

COMMENT ON CONSTRAINT sources_url_unique_per_tenant ON sch_collection.sources IS
    'A page is watched once. A duplicate doubles fetch cost and storage '
    'forever, and gives two independent baseline clocks for one channel (D-80).';
