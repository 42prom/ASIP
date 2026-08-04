-- Export needs the handles of the accounts in a cluster; it must not reach into
-- sch_extraction.accounts to get them (D-99, D-92).
--
-- WHY A VIEW AND NOT A JOIN
--
-- The console's graph endpoint already joins sch_detection.finding_accounts to
-- sch_extraction.accounts directly. That works, and it is exactly the coupling
-- D-99 exists to prevent: extraction can no longer rename a column, add a
-- retention rule, or change how an account is identified without breaking two
-- other modules that were never told they were customers.
--
-- A published view is the contract. Extraction may reshape the table underneath
-- it; what it may not do is change what it promised to publish.
--
-- WHAT IS DELIBERATELY NOT HERE
--
--   display_name  — a person's chosen name, not needed to serialise an
--                   observable. M-03: the cluster is the unit of analysis.
--   text, lang    — V-2. Nothing content-derived crosses this boundary either.
--
-- The handle stays, because M-01 models a monitored account as an SCO and an
-- account SCO with no identifier is useless to a recipient. It carries no
-- judgement: the assessment attaches to the grouping (M-03).

CREATE VIEW sch_extraction.v_accounts_for_export WITH (security_invoker = true) AS
    SELECT account_id, tenant_id, platform, handle, first_seen, last_seen
      FROM sch_extraction.accounts;

COMMENT ON VIEW sch_extraction.v_accounts_for_export IS
    'D-92 published contract: account identity for STIX serialisation. '
    'No display_name (M-03), nothing content-derived (V-2).';

GRANT SELECT ON sch_extraction.v_accounts_for_export TO asip_app;
