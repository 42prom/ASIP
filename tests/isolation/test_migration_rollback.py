"""The rollback is tested, not merely written (asip-migration skill).

A rollback file that has never been executed is a guess. This applies the
migration, rolls it back, and applies it again — the sequence a real recovery
performs, and the one that catches a rollback which leaves the schema in a
state the migration cannot be reapplied onto.
"""

from __future__ import annotations

import psycopg
import pytest

from asip.entrypoints.migrate import (
    BOOTSTRAP,
    applied_versions,
    apply,
    discover,
    rollback,
)

from .conftest import scalar


@pytest.mark.isolation
def test_every_migration_has_a_rollback_file() -> None:
    """Checked without a database, so it fails fast and everywhere."""
    missing = [str(m) for m in discover() if not m.rollback_path.is_file()]
    assert not missing, f"migrations with no rollback: {missing}"


@pytest.mark.isolation
def test_apply_rollback_reapply_leaves_a_working_schema(migrated_db: str) -> None:
    """Every migration down in reverse order, then every one back up."""
    evidence = [m for m in discover() if m.module == "evidence"]

    with psycopg.connect(migrated_db) as conn:
        with conn.cursor() as cur:
            cur.execute(BOOTSTRAP)
        conn.commit()

        for migration in reversed(evidence):
            rollback(conn, migration)
            conn.commit()

        assert not [v for m, v in applied_versions(conn) if m == "evidence"]
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('sch_evidence.evidence_bundles')")
            assert scalar(cur) is None

        # Up again — the part that catches a rollback leaving debris behind.
        for migration in evidence:
            apply(conn, migration)
            conn.commit()

        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('sch_evidence.chain_anchors')")
            assert scalar(cur) is not None


@pytest.mark.isolation
def test_rolling_back_out_of_order_is_refused(migrated_db: str) -> None:
    """001's rollback is DROP SCHEMA CASCADE — it would silently remove 002.

    Found the hard way: the schema was destroyed while 002 stayed recorded as
    applied, so the next run skipped it and every query hit a missing column.
    """
    first = next(m for m in discover() if m.module == "evidence" and m.version == "001")

    with psycopg.connect(migrated_db) as conn:
        with conn.cursor() as cur:
            cur.execute(BOOTSTRAP)
        conn.commit()
        with pytest.raises(RuntimeError, match="reverse order"):
            rollback(conn, first)


@pytest.mark.isolation
def test_rls_is_enabled_and_forced_on_every_evidence_table(migrated_db: str) -> None:
    """FORCE is the part that matters and the part that is easy to omit.

    Without it the table owner bypasses the policy, which is exactly the
    "see everything" capability V-7 forbids.
    """
    with psycopg.connect(migrated_db) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'sch_evidence' AND c.relkind = 'p' "
            "   OR (n.nspname = 'sch_evidence' AND c.relkind = 'r' "
            "       AND c.relname IN ('hash_chain', 'tsa_tokens'))"
        )
        rows = cur.fetchall()

    assert rows, "no evidence tables found"
    unprotected = [name for name, enabled, forced in rows if not (enabled and forced)]
    assert not unprotected, f"RLS not enabled+forced on: {unprotected}"


@pytest.mark.isolation
def test_partitions_exist_for_the_tables_that_grow(migrated_db: str) -> None:
    """A missing future partition is an outage: the INSERT simply fails."""
    with psycopg.connect(migrated_db) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname, count(i.inhrelid) "
            "FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "LEFT JOIN pg_inherits i ON i.inhparent = c.oid "
            "WHERE n.nspname = 'sch_evidence' AND c.relkind = 'p' "
            "GROUP BY c.relname"
        )
        partition_counts: dict[str, int] = dict(cur.fetchall())

    assert set(partition_counts) == {"captures", "evidence_bundles"}
    for table, count in partition_counts.items():
        assert count >= 3, f"{table} has only {count} partitions"


@pytest.mark.isolation
def test_the_application_role_holds_no_update_or_delete_grant(migrated_db: str) -> None:
    """Append-only, checked against the catalogue as well as by behaviour.

    Scoped to the roles application code can actually connect as. The schema
    owner necessarily keeps every privilege and can re-grant at will, so the
    guarantee is "the application does not connect as the owner", which is
    stated as an operational requirement in the migration itself. Asserting
    that *nobody* holds UPDATE would be asserting something PostgreSQL cannot
    provide, and a test that cannot pass teaches people to delete tests.
    """
    with psycopg.connect(migrated_db) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT table_name, grantee, privilege_type "
            "FROM information_schema.table_privileges "
            "WHERE table_schema = 'sch_evidence' "
            "  AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE') "
            "  AND grantee IN ('asip_app', 'PUBLIC')"
        )
        grants = cur.fetchall()

    assert not grants, f"application role can mutate evidence: {grants}"


@pytest.mark.isolation
def test_every_published_view_uses_security_invoker(migrated_db: str) -> None:
    """D-92 routes cross-module reads through views — each is an RLS bypass by default.

    A PostgreSQL view runs with its owner's privileges unless told otherwise,
    so a published view owned by the migration role serves every tenant's rows
    to any caller. This asserts the option is set on all of them, not just the
    one that happened to be caught.
    """
    with psycopg.connect(migrated_db) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname, c.reloptions "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname LIKE 'sch\\_%' AND c.relkind = 'v'"
        )
        views = cur.fetchall()

    assert views, "no published views found"
    leaking = [
        name
        for name, options in views
        if not options or "security_invoker=true" not in [o.replace(" ", "") for o in options]
    ]
    assert not leaking, f"views without security_invoker (cross-tenant leak): {leaking}"
