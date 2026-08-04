-- D-112: the trace context breaks at the content row on the second run.
--
-- WHAT THE SKELETON SHOWED
--
-- D-112 says trace_id is generated at fetch dispatch and carried through
-- capture, bundle, extraction, content rows, and findings. It is — on the first
-- run. On every run after that, `content.trace_id` still holds the trace of the
-- run that FIRST extracted the item, because migration 003 correctly refuses to
-- rewrite provenance on re-observation.
--
-- Measured on the canary: all six content rows carried trace-45ca953d7e25 while
-- three findings carried three different traces. Joining a finding to its
-- content on trace_id returned nothing for every run but the first.
--
-- Both facts are worth keeping and they are different facts:
--
--   trace_id       the run that first observed this item — provenance, frozen
--   last_trace_id  the run that most recently observed it — the live trace
--
-- Same shape as capture_id / last_capture_id in migration 003, and for the same
-- reason: an append-only provenance claim and a moving pointer are not one
-- column, and the version that tried to be both silently lost one of them.
--
-- NOTE FOR PHASE 1 — this does not make trace_id a general traceability join.
-- It works here because the skeleton extracts and detects inside one run. A
-- real detection rule spans a time window over content observed across many
-- runs, and then finding.trace_id will not equal content.last_trace_id for
-- most of the cluster. The path that survives that is structural:
--
--   finding -> evidence_refs[] -> evidence_bundle -> capture
--
-- which M-15 already guarantees exists, since a finding without an evidence
-- reference cannot be written. That join lives in the composition root
-- (entrypoints/provenance.py), not in a view here: a view in one module's
-- schema that reads two others' would make dropping either module break this
-- one, which is the coupling D-99 exists to prevent.
--
-- D-112 should be read as "traceable in one query", which holds, and not as
-- "joined by trace_id", which does not once detection spans runs.

ALTER TABLE sch_extraction.content
    ADD COLUMN IF NOT EXISTS last_trace_id text;

-- Backfill: an item observed once has been observed most recently by the run
-- that first saw it.
UPDATE sch_extraction.content SET last_trace_id = trace_id WHERE last_trace_id IS NULL;

ALTER TABLE sch_extraction.content ALTER COLUMN last_trace_id SET NOT NULL;

-- The lookup this exists to serve: "what did run X touch".
CREATE INDEX IF NOT EXISTS content_last_trace_idx
    ON sch_extraction.content (tenant_id, last_trace_id);

COMMENT ON COLUMN sch_extraction.content.trace_id IS
    'The run that FIRST observed this item. Provenance — never rewritten.';
COMMENT ON COLUMN sch_extraction.content.last_trace_id IS
    'The run that most recently observed this item (D-112). Moves on re-observation.';

-- The application updates it on re-observation; it may not rewrite trace_id.
GRANT UPDATE (last_seen, last_capture_id, last_trace_id)
    ON sch_extraction.content TO asip_app;

-- ─────────────────────────────────────────────────────────────────────────────
-- What the traceability query is allowed to read (D-92).
--
-- Separate from v_content_for_detection on purpose. That view is the physical
-- enforcement of V-2 and its value comes from being exactly as narrow as
-- detection needs; adding columns to it for an unrelated caller is how a
-- boundary erodes one reasonable-looking column at a time.
--
-- Nothing here is derived from text. These are observation facts: which capture
-- an item came from, which run saw it, and when. The test for V-2 is not "is
-- this text" but "is this derived from text".
-- ─────────────────────────────────────────────────────────────────────────────
CREATE VIEW sch_extraction.v_content_provenance WITH (security_invoker = true) AS
    SELECT content_id, tenant_id, source_id, capture_id, last_capture_id,
           trace_id, last_trace_id, extractor_version, first_seen, last_seen,
           posted_at_authoritative
      FROM sch_extraction.content
     WHERE deleted_at IS NULL;

COMMENT ON VIEW sch_extraction.v_content_provenance IS
    'D-92 published contract: where an item came from and which run saw it. '
    'No text, no lang, no script — nothing content-derived (V-2).';

GRANT SELECT ON sch_extraction.v_content_provenance TO asip_app;
