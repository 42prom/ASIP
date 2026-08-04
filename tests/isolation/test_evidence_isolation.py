"""D-88.4 / V-7 — cross-tenant reads must be refused by the database.

Every test here is an attempt to see another tenant's evidence. They run
against real PostgreSQL with real RLS, because the claim being tested is about
the database's behaviour, not the application's intentions.

Also covers the append-only guarantee: the application role must have no way to
alter or remove a sealed bundle. That is checked by attempting it, not by
reading the grant table.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import psycopg
import pytest

from .conftest import TENANT_A, TENANT_B, as_tenant, scalar

CAPTURED_AT = "2026-08-15T10:00:00+00:00"
GENESIS = "0" * 64


def digest(seed: str) -> str:
    """A well-formed lowercase hex digest, distinct per seed."""
    import hashlib

    return hashlib.sha256(seed.encode()).hexdigest()


def seed_bundle(connection: psycopg.Connection, tenant_id: UUID, seed: str) -> UUID:
    """Insert a capture, a bundle and its chain entry as the given tenant."""
    bundle_id = uuid4()
    capture_id = uuid4()
    manifest = {
        "algorithm": "sha256",
        "artifacts": [
            {
                "name": "dom.html.gz",
                "kind": "dom",
                "media_type": "application/gzip",
                "size_bytes": 10,
                "sha256": digest(seed + "dom"),
            }
        ],
    }
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO sch_evidence.captures "
            "(capture_id, tenant_id, source_id, trace_id, url, requested_at, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'succeeded')",
            (capture_id, tenant_id, uuid4(), f"trace-{seed}", "https://e.org/1", CAPTURED_AT),
        )
        cur.execute(
            "INSERT INTO sch_evidence.evidence_bundles "
            "(bundle_id, captured_at, capture_id, tenant_id, trace_id, source_url, "
            " manifest, manifest_sha256, object_prefix) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                bundle_id,
                CAPTURED_AT,
                capture_id,
                tenant_id,
                f"trace-{seed}",
                "https://e.org/1",
                json.dumps(manifest),
                digest(seed),
                f"{tenant_id}/{bundle_id}",
            ),
        )
        cur.execute(
            "INSERT INTO sch_evidence.hash_chain "
            "(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id, "
            " bundle_captured_at, entry_hash) "
            "VALUES (%s, 0, %s, %s, %s, %s, %s)",
            (tenant_id, GENESIS, digest(seed), bundle_id, CAPTURED_AT, digest(seed + "entry")),
        )
    return bundle_id


# ─────────────────────────────────────────────────────────────────────────────
# Cross-tenant reads
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.isolation
def test_a_connection_with_no_tenant_set_sees_nothing(conn: psycopg.Connection) -> None:
    """Closed by default. An unset GUC must not mean "everything"."""
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur:
        cur.execute("SET LOCAL ROLE asip_app")
        cur.execute("SELECT set_config('asip.tenant_id', '', true)")
        cur.execute("SELECT count(*) FROM sch_evidence.evidence_bundles")
        assert scalar(cur) == 0


@pytest.mark.isolation
@pytest.mark.parametrize(
    "table",
    ["captures", "evidence_bundles", "hash_chain"],
)
def test_one_tenant_cannot_read_anothers_rows(conn: psycopg.Connection, table: str) -> None:
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur:
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(TENANT_B),))
        cur.execute(f"SELECT count(*) FROM sch_evidence.{table}")
        assert scalar(cur) == 0

        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(TENANT_A),))
        cur.execute(f"SELECT count(*) FROM sch_evidence.{table}")
        assert scalar(cur) == 1


@pytest.mark.isolation
def test_the_published_view_is_also_tenant_scoped(conn: psycopg.Connection) -> None:
    """A view is a common way to accidentally route around RLS."""
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur:
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(TENANT_B),))
        cur.execute("SELECT count(*) FROM sch_evidence.v_bundles_for_review")
        assert scalar(cur) == 0


@pytest.mark.isolation
def test_a_tenant_cannot_insert_a_row_belonging_to_another(conn: psycopg.Connection) -> None:
    """WITH CHECK, not only USING. Writing across tenants is as bad as reading."""
    as_tenant(conn, TENANT_A)

    with conn.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(
            "INSERT INTO sch_evidence.captures "
            "(capture_id, tenant_id, source_id, trace_id, url, requested_at, status) "
            "VALUES (%s, %s, %s, 'trace-x', 'https://e.org/1', %s, 'succeeded')",
            (uuid4(), TENANT_B, uuid4(), CAPTURED_AT),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Append-only
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.isolation
@pytest.mark.parametrize("table", ["evidence_bundles", "hash_chain", "captures"])
def test_the_application_role_cannot_update_evidence(conn: psycopg.Connection, table: str) -> None:
    """No UPDATE path exists. Verified by attempting one."""
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(f"UPDATE sch_evidence.{table} SET tenant_id = tenant_id")


@pytest.mark.isolation
@pytest.mark.parametrize("table", ["evidence_bundles", "hash_chain", "captures"])
def test_the_application_role_cannot_delete_evidence(conn: psycopg.Connection, table: str) -> None:
    """Retention expiry is a separate audited role (D-54), not this one."""
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(f"DELETE FROM sch_evidence.{table}")


# ─────────────────────────────────────────────────────────────────────────────
# Constraints that encode invariants
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.isolation
def test_a_bundle_with_an_empty_manifest_is_refused(conn: psycopg.Connection) -> None:
    """Invariant 1 at the database level: attesting to nothing is not a bundle."""
    as_tenant(conn, TENANT_A)

    with conn.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        cur.execute(
            "INSERT INTO sch_evidence.evidence_bundles "
            "(bundle_id, captured_at, capture_id, tenant_id, trace_id, source_url, "
            " manifest, manifest_sha256, object_prefix) "
            "VALUES (%s, %s, %s, %s, 't', 'https://e.org/1', %s, %s, 'p')",
            (
                uuid4(),
                CAPTURED_AT,
                uuid4(),
                TENANT_A,
                json.dumps({"algorithm": "sha256", "artifacts": []}),
                digest("empty"),
            ),
        )


@pytest.mark.isolation
def test_a_chain_entry_without_its_bundle_is_refused(conn: psycopg.Connection) -> None:
    """The chain cannot attest to a bundle that does not exist."""
    as_tenant(conn, TENANT_A)

    with conn.cursor() as cur, pytest.raises(psycopg.errors.ForeignKeyViolation):
        cur.execute(
            "INSERT INTO sch_evidence.hash_chain "
            "(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id, "
            " bundle_captured_at, entry_hash) "
            "VALUES (%s, 0, %s, %s, %s, %s, %s)",
            (TENANT_A, GENESIS, digest("x"), uuid4(), CAPTURED_AT, digest("y")),
        )


@pytest.mark.isolation
def test_only_index_zero_may_carry_the_genesis_hash(conn: psycopg.Connection) -> None:
    as_tenant(conn, TENANT_A)
    bundle_id = seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        cur.execute(
            "INSERT INTO sch_evidence.hash_chain "
            "(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id, "
            " bundle_captured_at, entry_hash) "
            "VALUES (%s, 5, %s, %s, %s, %s, %s)",
            (TENANT_A, GENESIS, digest("x"), bundle_id, CAPTURED_AT, digest("z")),
        )


@pytest.mark.isolation
def test_one_bundle_cannot_hold_two_chain_positions(conn: psycopg.Connection) -> None:
    as_tenant(conn, TENANT_A)
    bundle_id = seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur, pytest.raises(psycopg.errors.UniqueViolation):
        cur.execute(
            "INSERT INTO sch_evidence.hash_chain "
            "(tenant_id, chain_index, prev_hash, manifest_sha256, bundle_id, "
            " bundle_captured_at, entry_hash) "
            "VALUES (%s, 1, %s, %s, %s, %s, %s)",
            (TENANT_A, digest("prev"), digest("x"), bundle_id, CAPTURED_AT, digest("w")),
        )


@pytest.mark.isolation
def test_two_tenants_may_both_hold_chain_index_zero(conn: psycopg.Connection) -> None:
    """Chains are per-tenant, so indices do not leak another tenant's volume."""
    as_tenant(conn, TENANT_A)
    seed_bundle(conn, TENANT_A, "a")

    with conn.cursor() as cur:
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(TENANT_B),))
    seed_bundle(conn, TENANT_B, "b")

    with conn.cursor() as cur:
        cur.execute("SELECT chain_index FROM sch_evidence.hash_chain")
        assert [row[0] for row in cur.fetchall()] == [0]
