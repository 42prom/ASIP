-- sch_detection — rules, findings, clusters (D-91).
--
-- This schema carries three vetoes as database constraints. They are here
-- rather than in application code because application code can be bypassed by
-- the next person in a hurry, and a CHECK cannot.

CREATE SCHEMA IF NOT EXISTS sch_detection;
GRANT USAGE ON SCHEMA sch_detection TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_detection.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';

CREATE TABLE sch_detection.rules (
    rule_id            uuid        PRIMARY KEY,
    tenant_id          uuid        NOT NULL,
    name               text        NOT NULL,
    description        text        NOT NULL,
    params             jsonb       NOT NULL,
    -- A rule in shadow mode produces findings that are recorded and shown, but
    -- are explicitly not verdicts. Everything starts here.
    shadow_mode        boolean     NOT NULL DEFAULT true,
    enabled            boolean     NOT NULL DEFAULT false,
    -- NULL until measured against a hand-labelled sample. Synthetic precision
    -- is a filter, never a gate (D-109), so it does not go in this column.
    measured_precision numeric(4, 3),
    measured_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),

    -- V-4. A rule with no measured precision cannot be enabled. This is the
    -- veto, expressed the only way that cannot be argued with at 2am.
    CONSTRAINT rules_precision_required_to_enable CHECK (
        NOT enabled OR measured_precision IS NOT NULL
    ),
    CONSTRAINT rules_precision_is_a_proportion CHECK (
        measured_precision IS NULL OR measured_precision BETWEEN 0 AND 1
    ),
    -- An enabled rule cannot also be in shadow mode: that combination has no
    -- meaning and would make "is this finding a verdict?" unanswerable.
    CONSTRAINT rules_enabled_is_not_shadow CHECK (NOT (enabled AND shadow_mode))
);

CREATE INDEX rules_tenant_idx ON sch_detection.rules (tenant_id, enabled);

-- A finding is about a CLUSTER. There is no column here for a subject, a
-- person, or an author — the unit of analysis is the group's behaviour, and
-- V-1 is again enforced by what the table cannot express.
CREATE TABLE sch_detection.findings (
    finding_id     uuid        PRIMARY KEY,
    tenant_id      uuid        NOT NULL,
    rule_id        uuid        NOT NULL REFERENCES sch_detection.rules (rule_id),
    source_id      uuid        NOT NULL,
    trace_id       text        NOT NULL,
    window_start   timestamptz NOT NULL,
    window_end     timestamptz NOT NULL,
    item_count     integer     NOT NULL,
    account_count  integer     NOT NULL,
    -- Every measurement that contributed, with its threshold and observed
    -- value, so the analyst sees the reasoning rather than a number (D-30).
    signals        jsonb       NOT NULL,
    -- V-5: no finding without evidence. Every finding points at the bundles it
    -- rests on, and the array cannot be empty.
    evidence_refs  uuid[]      NOT NULL,
    -- Recorded on the finding, not derived at read time: a finding produced by
    -- a shadow rule stays a shadow finding even if the rule is later enabled.
    shadow         boolean     NOT NULL,
    detected_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT findings_evidence_required CHECK (cardinality(evidence_refs) >= 1),
    -- D-29: a finding resting on fewer than three independent signals is a
    -- coincidence with formatting.
    CONSTRAINT findings_signals_minimum CHECK (jsonb_array_length(signals) >= 3),
    CONSTRAINT findings_window_ordered CHECK (window_end >= window_start),
    CONSTRAINT findings_counts_positive CHECK (item_count > 0 AND account_count > 0)
);

CREATE INDEX findings_tenant_detected_idx
    ON sch_detection.findings (tenant_id, detected_at DESC);
CREATE INDEX findings_trace_idx ON sch_detection.findings (tenant_id, trace_id);

-- Cluster membership. Which accounts acted together — a property of the group,
-- carrying no judgement about any member.
CREATE TABLE sch_detection.finding_accounts (
    finding_id  uuid NOT NULL REFERENCES sch_detection.findings (finding_id),
    tenant_id   uuid NOT NULL,
    account_id  uuid NOT NULL,
    item_count  integer NOT NULL DEFAULT 1,

    PRIMARY KEY (finding_id, account_id),
    CONSTRAINT finding_accounts_items_positive CHECK (item_count > 0)
);

ALTER TABLE sch_detection.rules            ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_detection.rules            FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_detection.findings         ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_detection.findings         FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_detection.finding_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_detection.finding_accounts FORCE  ROW LEVEL SECURITY;

CREATE POLICY rules_tenant_isolation ON sch_detection.rules
    USING (tenant_id = sch_detection.current_tenant())
    WITH CHECK (tenant_id = sch_detection.current_tenant());

CREATE POLICY findings_tenant_isolation ON sch_detection.findings
    USING (tenant_id = sch_detection.current_tenant())
    WITH CHECK (tenant_id = sch_detection.current_tenant());

CREATE POLICY finding_accounts_tenant_isolation ON sch_detection.finding_accounts
    USING (tenant_id = sch_detection.current_tenant())
    WITH CHECK (tenant_id = sch_detection.current_tenant());

REVOKE ALL ON ALL TABLES IN SCHEMA sch_detection FROM PUBLIC;

GRANT SELECT, INSERT ON sch_detection.rules, sch_detection.findings,
                        sch_detection.finding_accounts TO asip_app;
GRANT UPDATE (shadow_mode, enabled, measured_precision, measured_at)
    ON sch_detection.rules TO asip_app;
GRANT SELECT, DELETE ON sch_detection.rules, sch_detection.findings,
                        sch_detection.finding_accounts TO asip_retention;

CREATE VIEW sch_detection.v_findings_for_review WITH (security_invoker = true) AS
    SELECT f.finding_id, f.tenant_id, f.rule_id, r.name AS rule_name,
           f.source_id, f.trace_id, f.window_start, f.window_end,
           f.item_count, f.account_count, f.signals, f.evidence_refs,
           f.shadow, f.detected_at
      FROM sch_detection.findings f
      JOIN sch_detection.rules r ON r.rule_id = f.rule_id;

GRANT SELECT ON sch_detection.v_findings_for_review TO asip_app;
