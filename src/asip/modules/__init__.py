"""The nine modules of the monolith (D-10).

One deployment and one database, with strict internal boundaries. Nine
services would deliver every distributed-systems cost and the single
benefit - independent team velocity - that a one-person team cannot use.

Each module owns exactly one PostgreSQL schema and writes to no other
(D-91). Cross-schema reads go through the producer's published v_* view
(D-92); cross-schema writes go through an event (D-93). Cross-module
Python imports resolve through modules/<name>/__init__.py only, never
into another module's domain/, application/ or adapters/ (L-05).

Every module must be removable without breaking the others' imports.
That is not an aspiration - tests/independence/ asserts it for each of
the nine in turn (D-99).

    collection   sch_collection    fetch_jobs, budgets, source_health
    evidence     sch_evidence      captures, evidence_bundles, hash_chain
    extraction   sch_extraction    content, accounts, extraction_runs
    baseline     sch_baseline      source_baselines, metrics
    detection    sch_detection     rules, findings, clusters
    review       sch_review        queue, verdicts, assignments
    identity     sch_identity      tenants, users, roles, audit
    export       sch_export        stix_objects, export_jobs
    reporting    sch_reporting     reports, templates
"""
