-- Every scheduler tick is recorded, including the ones that did nothing.
--
-- WHY AN IDLE TICK IS A ROW
--
-- D-68: an empty screen never means "no activity". Without this table an
-- operator opening the console sees nothing and cannot distinguish
--
--     the scheduler ran and nothing was due          (fine)
--     the scheduler died six hours ago               (an incident)
--
-- D-87 calls silent degradation the primary failure mode of this class of
-- system. A scheduler that stops quietly is the purest example: everything
-- looks healthy because nothing is complaining, and the reason nothing is
-- complaining is that nothing is running.
--
-- WHY IT LIVES IN sch_collection
--
-- D-17 puts scheduling in the collection domain — budget allocation, source
-- priority, interval. This schema already owns due_sources, fetch_jobs and
-- source_health. A record of "the scheduler woke, and here is what it decided"
-- belongs with them.
--
-- The `stages` payload is opaque JSON that collection never interprets. It is a
-- log, not a foreign key: collection learns nothing about detection's schema by
-- storing a line of text detection produced. If a second orchestrator ever
-- exists, this moves.
--
-- NOT IN SCOPE — D-17's priority_score allocator and D-18's budget hard stop
-- are Phase 1. The skeleton schedules on interval_seconds alone, which is what
-- due_sources already implements. Building the optimizer now would be exactly
-- the over-building CLAUDE.md §10 forbids.

CREATE TABLE sch_collection.scheduler_runs (
    run_id        uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL,
    trace_id      text        NOT NULL,
    started_at    timestamptz NOT NULL,
    finished_at   timestamptz,

    -- Three outcomes, not two. "idle" is a successful run that found nothing
    -- due — collapsing it into "ok" would lose the distinction D-68 is about,
    -- and collapsing it into "failed" would page someone at 3am for silence.
    outcome       text        NOT NULL,
    detail        text        NOT NULL DEFAULT '',

    sources_due   integer     NOT NULL DEFAULT 0,
    captures      integer     NOT NULL DEFAULT 0,
    items         integer     NOT NULL DEFAULT 0,
    findings      integer     NOT NULL DEFAULT 0,
    exports       integer     NOT NULL DEFAULT 0,
    held_for_review integer   NOT NULL DEFAULT 0,

    -- Opaque to this module. See the header.
    stages        jsonb       NOT NULL DEFAULT '[]'::jsonb,

    CONSTRAINT scheduler_runs_outcome CHECK (outcome IN ('ok', 'idle', 'failed')),
    CONSTRAINT scheduler_runs_counts_non_negative CHECK (
        sources_due >= 0 AND captures >= 0 AND items >= 0
        AND findings >= 0 AND exports >= 0 AND held_for_review >= 0
    ),
    -- A run that finished cannot have finished before it started. Cheap, and it
    -- catches a clock going backwards, which is the kind of thing that silently
    -- corrupts every duration measurement downstream (D-86 measures p95).
    CONSTRAINT scheduler_runs_ordered CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE INDEX scheduler_runs_tenant_started_idx
    ON sch_collection.scheduler_runs (tenant_id, started_at DESC);

ALTER TABLE sch_collection.scheduler_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_collection.scheduler_runs FORCE  ROW LEVEL SECURITY;

CREATE POLICY scheduler_runs_tenant_isolation ON sch_collection.scheduler_runs
    USING (tenant_id = sch_collection.current_tenant())
    WITH CHECK (tenant_id = sch_collection.current_tenant());

GRANT SELECT, INSERT ON sch_collection.scheduler_runs TO asip_app;

-- A run is opened when it starts and closed when it ends, so these columns are
-- legitimately updated in place. The rest are not: a run's identity and its
-- start time are facts, and a scheduler that could rewrite when it ran is a
-- scheduler whose history cannot be trusted.
GRANT UPDATE (finished_at, outcome, detail, sources_due, captures, items,
              findings, exports, held_for_review, stages)
    ON sch_collection.scheduler_runs TO asip_app;

GRANT SELECT, DELETE ON sch_collection.scheduler_runs TO asip_retention;

-- Published read view (D-92).
CREATE VIEW sch_collection.v_scheduler_runs WITH (security_invoker = true) AS
    SELECT run_id, tenant_id, trace_id, started_at, finished_at, outcome, detail,
           sources_due, captures, items, findings, exports, held_for_review,
           EXTRACT(EPOCH FROM (finished_at - started_at)) AS duration_seconds
      FROM sch_collection.scheduler_runs;

COMMENT ON VIEW sch_collection.v_scheduler_runs IS
    'D-92 published contract: unattended run history. Excludes the opaque '
    'stages payload, which is for the console detail view only.';

GRANT SELECT ON sch_collection.v_scheduler_runs TO asip_app;
