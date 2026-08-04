-- sch_review — the triage queue and analyst verdicts (D-91).
--
-- The system never decides alone. A finding is a candidate until a human has
-- looked at it, and this schema is where that human's judgement lands.

CREATE SCHEMA IF NOT EXISTS sch_review;
GRANT USAGE ON SCHEMA sch_review TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_review.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';

-- Verdicts are append-only. A changed mind is a second verdict, not an edit of
-- the first: the sequence of judgements about a finding is itself the record,
-- and D-115 makes every one of them a training label.
CREATE TABLE sch_review.verdicts (
    verdict_id   uuid        PRIMARY KEY,
    tenant_id    uuid        NOT NULL,
    finding_id   uuid        NOT NULL,
    -- Four states (D-32). "Insufficient evidence" is a legitimate outcome and
    -- not a failure to decide — a tool that confirms everything is a tool
    -- nobody can rely on.
    verdict      text        NOT NULL,
    rationale    text        NOT NULL DEFAULT '',
    analyst      text        NOT NULL,
    rule_version text        NOT NULL,
    decided_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT verdicts_known_state CHECK (
        verdict IN ('confirmed_coordination', 'likely_coordination',
                    'insufficient_evidence', 'no_coordination')
    ),
    CONSTRAINT verdicts_analyst_named CHECK (length(analyst) > 0)
);

CREATE INDEX verdicts_finding_idx ON sch_review.verdicts (tenant_id, finding_id, decided_at DESC);
CREATE INDEX verdicts_tenant_decided_idx ON sch_review.verdicts (tenant_id, decided_at DESC);

ALTER TABLE sch_review.verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_review.verdicts FORCE  ROW LEVEL SECURITY;

CREATE POLICY verdicts_tenant_isolation ON sch_review.verdicts
    USING (tenant_id = sch_review.current_tenant())
    WITH CHECK (tenant_id = sch_review.current_tenant());

REVOKE ALL ON ALL TABLES IN SCHEMA sch_review FROM PUBLIC;

-- No UPDATE. A verdict is a record of what someone concluded at a moment, and
-- rewriting it would destroy the audit trail that makes the conclusion
-- defensible.
GRANT SELECT, INSERT ON sch_review.verdicts TO asip_app;
GRANT SELECT, DELETE ON sch_review.verdicts TO asip_retention;

-- The current verdict for each finding: the most recent one. Earlier verdicts
-- stay readable in the table, which is the point of appending.
CREATE VIEW sch_review.v_current_verdicts WITH (security_invoker = true) AS
    SELECT DISTINCT ON (finding_id)
           finding_id, tenant_id, verdict, rationale, analyst, decided_at
      FROM sch_review.verdicts
     ORDER BY finding_id, decided_at DESC;

GRANT SELECT ON sch_review.v_current_verdicts TO asip_app;
