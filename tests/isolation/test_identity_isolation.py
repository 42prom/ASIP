"""What the database refuses, proved against a real database.

The domain tests in tests/unit/identity assert that the *decision* is right.
These assert that the decision cannot be bypassed by going around it — a
forgotten WHERE clause, a compromised application role, a well-meaning UPDATE.
That distinction is the whole reason D-47 puts isolation in RLS rather than in
application code (T-002).

Two claims here are load-bearing enough that the register marks them
non-tradeable: cross-tenant isolation (T-002) and the super-admin boundary
(T-003). A third — the audit log being append-only (T-008) — is enforced by the
absence of a GRANT, which is the only way to enforce it against the application
that owns the connection.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from uuid import UUID

import psycopg
import pytest

from .conftest import TENANT_A, TENANT_B, as_tenant, scalar

USER_A = UUID("11111111-0000-4000-8000-00000000000a")
USER_B = UUID("22222222-0000-4000-8000-00000000000b")


def seed_tenant(conn: psycopg.Connection, tenant_id: UUID, user_id: UUID, email: str) -> None:
    """Insert a tenant and a user as the owner, bypassing nothing.

    The owner is subject to FORCE RLS too, so even seeding sets the tenant GUC.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(tenant_id),))
        cur.execute(
            "INSERT INTO sch_identity.tenants (tenant_id, name) VALUES (%s, %s) "
            "ON CONFLICT (tenant_id) DO NOTHING",
            (tenant_id, f"tenant-{tenant_id.hex[:6]}"),
        )
        cur.execute(
            "INSERT INTO sch_identity.users (user_id, tenant_id, email, password_hash) "
            "VALUES (%s, %s, %s, 'scrypt$n=1024,r=8,p=1$c2FsdA==$ZGlnZXN0') "
            "ON CONFLICT (user_id) DO NOTHING",
            (user_id, tenant_id, email),
        )


@pytest.fixture
def two_tenants(conn: psycopg.Connection) -> psycopg.Connection:
    seed_tenant(conn, TENANT_A, USER_A, "analyst@tenant-a.example")
    seed_tenant(conn, TENANT_B, USER_B, "analyst@tenant-b.example")
    conn.commit()
    return conn


# ── T-002: the tenant boundary ──────────────────────────────────────────────


def test_a_connection_with_no_tenant_sees_no_users(two_tenants: psycopg.Connection) -> None:
    """The first thing worth proving: forgetting to identify yourself yields
    nothing, not everything."""
    with two_tenants.cursor() as cur:
        cur.execute("SET LOCAL ROLE asip_app")
        cur.execute("SELECT count(*) FROM sch_identity.users")
        assert scalar(cur) == 0


def test_one_tenant_cannot_see_another_tenants_users(two_tenants: psycopg.Connection) -> None:
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur:
        cur.execute("SELECT count(*) FROM sch_identity.users WHERE tenant_id = %s", (TENANT_B,))
        assert scalar(cur) == 0

        cur.execute("SELECT count(*) FROM sch_identity.users")
        assert scalar(cur) == 1, "tenant A should see exactly its own user"


def test_a_deliberate_cross_tenant_query_returns_nothing(two_tenants: psycopg.Connection) -> None:
    """Not a forgotten filter — an explicit attempt, which is what an attacker
    with SQL access would write."""
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur:
        cur.execute("SELECT count(*) FROM sch_identity.users WHERE user_id = %s", (USER_B,))
        assert scalar(cur) == 0


def test_a_tenant_cannot_insert_a_user_into_another_tenant(
    two_tenants: psycopg.Connection,
) -> None:
    """WITH CHECK, not just USING. Without it a tenant could write rows it
    could not then read — a one-way channel into someone else's data."""
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.Error):
        cur.execute(
            "INSERT INTO sch_identity.users (user_id, tenant_id, email, password_hash) "
            "VALUES (%s, %s, 'intruder@example.com', 'x')",
            (uuid.uuid4(), TENANT_B),
        )
    two_tenants.rollback()


def test_the_published_user_view_is_tenant_scoped(two_tenants: psycopg.Connection) -> None:
    """D-92 views run as their owner unless told otherwise — every one of them
    is an RLS bypass by default."""
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur:
        cur.execute("SELECT count(*) FROM sch_identity.v_active_users")
        assert scalar(cur) == 1


def test_every_identity_table_carries_a_policy(two_tenants: psycopg.Connection) -> None:
    """Enumerated from the catalogue, so a table added later is covered the day
    it is added rather than the day someone remembers."""
    with two_tenants.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            " WHERE n.nspname = 'sch_identity' AND c.relkind = 'r' "
            "   AND NOT (c.relrowsecurity AND c.relforcerowsecurity)"
        )
        unprotected = [r[0] for r in cur.fetchall()]

    assert not unprotected, f"tables without FORCEd RLS in sch_identity: {unprotected} (V-7)"


# ── T-008: the audit log is append-only, by GRANT ───────────────────────────


def audit_row(conn: psycopg.Connection, tenant_id: UUID) -> tuple[UUID, int]:
    """Append one audit entry and commit it.

    The index is derived from what is already stored rather than fixed at 0.
    These rows are committed — an append-only table cannot be cleaned up between
    tests, which is the point of it — so they accumulate across the session and
    a hardcoded index collides with the previous test's row.
    """
    entry_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(tenant_id),))
        cur.execute(
            "SELECT coalesce(max(chain_index) + 1, 0) FROM sch_identity.audit_log "
            " WHERE tenant_id = %s",
            (tenant_id,),
        )
        index = scalar(cur)
        cur.execute(
            "INSERT INTO sch_identity.audit_log "
            "(entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
            " resource_type, resource_id, outcome, occurred_at, entry_hash) "
            "VALUES (%s, %s, %s, %s, %s, 'read_findings', 'finding', 'f-1', 'allowed', %s, %s)",
            (
                entry_id,
                tenant_id,
                index,
                "0" * 64,
                USER_A,
                datetime.now(UTC),
                hashlib.sha256(entry_id.bytes).hexdigest(),
            ),
        )
    conn.commit()
    return entry_id, index


def test_the_application_cannot_update_an_audit_entry(two_tenants: psycopg.Connection) -> None:
    """The single most important grant in the schema.

    A system that can edit its own audit trail does not have an audit trail; it
    has a log. Note this is not RLS — it is the absence of a GRANT, which is
    the only thing that stops the role that legitimately owns the connection.
    """
    entry_id, _ = audit_row(two_tenants, TENANT_A)
    as_tenant(two_tenants, TENANT_A)

    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(
            "UPDATE sch_identity.audit_log SET outcome = 'denied' WHERE entry_id = %s",
            (entry_id,),
        )
    two_tenants.rollback()


def test_the_application_cannot_delete_an_audit_entry(two_tenants: psycopg.Connection) -> None:
    entry_id, _ = audit_row(two_tenants, TENANT_A)
    as_tenant(two_tenants, TENANT_A)

    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute("DELETE FROM sch_identity.audit_log WHERE entry_id = %s", (entry_id,))
    two_tenants.rollback()


def test_even_retention_cannot_delete_an_audit_entry(two_tenants: psycopg.Connection) -> None:
    """D-51: never truncated, never rotated destructively.

    Retention expires evidence and content. It never expires the record of who
    looked at them — otherwise "delete the data, then delete the trail" is a
    supported workflow.
    """
    audit_row(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur:
        cur.execute("SET LOCAL ROLE asip_retention")
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(TENANT_A),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM sch_identity.audit_log")
    two_tenants.rollback()


def test_an_audit_chain_index_cannot_be_reused(two_tenants: psycopg.Connection) -> None:
    """Reusing an index is how a forged entry would be slipped in beside a real
    one rather than after it."""
    _, taken = audit_row(two_tenants, TENANT_A)
    as_tenant(two_tenants, TENANT_A)

    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.UniqueViolation):
        cur.execute(
            "INSERT INTO sch_identity.audit_log "
            "(entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
            " resource_type, resource_id, outcome, occurred_at, entry_hash) "
            "VALUES (%s, %s, %s, %s, %s, 'x', 'y', 'z', 'allowed', now(), %s)",
            (uuid.uuid4(), TENANT_A, taken, "0" * 64, USER_A, "a" * 64),
        )
    two_tenants.rollback()


def test_one_tenant_cannot_read_another_tenants_audit_log(
    two_tenants: psycopg.Connection,
) -> None:
    entry_id, _ = audit_row(two_tenants, TENANT_B)
    as_tenant(two_tenants, TENANT_A)

    with two_tenants.cursor() as cur:
        cur.execute("SELECT count(*) FROM sch_identity.audit_log WHERE entry_id = %s", (entry_id,))
        assert scalar(cur) == 0, "tenant A read an entry from tenant B's audit chain"

        cur.execute("SELECT count(*) FROM sch_identity.audit_log WHERE tenant_id = %s", (TENANT_B,))
        assert scalar(cur) == 0


# ── T-003 / D-50: grants are temporary, justified, and not self-issued ──────


def insert_grant(conn: psycopg.Connection, **overrides: object) -> None:
    fields: dict[str, object] = {
        "grant_id": uuid.uuid4(),
        "tenant_id": TENANT_A,
        "granted_to": USER_A,
        "granted_by": USER_A,
        "permissions": ["manage_users"],
        "justification": "incident 4412: tenant admin locked out of their account",
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
    }
    fields.update(overrides)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sch_identity.elevated_grants "
            "(grant_id, tenant_id, granted_to, granted_by, permissions, justification, expires_at) "
            "VALUES (%(grant_id)s, %(tenant_id)s, %(granted_to)s, %(granted_by)s, "
            "        %(permissions)s, %(justification)s, %(expires_at)s)",
            fields,
        )


def test_a_grant_cannot_be_issued_without_an_expiry(two_tenants: psycopg.Connection) -> None:
    """NOT NULL with no default. The failure prevented is the 2am emergency
    grant nobody revokes, which is indistinguishable from a standing privilege
    a year later."""
    as_tenant(two_tenants, TENANT_A)
    with pytest.raises(psycopg.errors.NotNullViolation):
        insert_grant(two_tenants, granted_by=USER_B, expires_at=None)
    two_tenants.rollback()


def test_a_grant_cannot_outlast_twelve_hours(two_tenants: psycopg.Connection) -> None:
    as_tenant(two_tenants, TENANT_A)
    with pytest.raises(psycopg.errors.CheckViolation):
        insert_grant(
            two_tenants,
            granted_by=USER_B,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
    two_tenants.rollback()


def test_a_grant_cannot_be_issued_to_yourself(two_tenants: psycopg.Connection) -> None:
    """Self-granting defeats the control entirely."""
    as_tenant(two_tenants, TENANT_A)
    with pytest.raises(psycopg.errors.CheckViolation):
        insert_grant(two_tenants, granted_to=USER_A, granted_by=USER_A)
    two_tenants.rollback()


def test_a_grant_needs_a_real_justification(two_tenants: psycopg.Connection) -> None:
    """ "ok" is not a justification. The length floor is crude and it works:
    it forces someone to type a sentence that will be read back later."""
    as_tenant(two_tenants, TENANT_A)
    with pytest.raises(psycopg.errors.CheckViolation):
        insert_grant(two_tenants, granted_by=USER_B, justification="ok")
    two_tenants.rollback()


def test_a_valid_grant_is_accepted(two_tenants: psycopg.Connection) -> None:
    """The constraints must not be so strict that the legitimate path fails —
    a control nobody can satisfy gets removed."""
    as_tenant(two_tenants, TENANT_A)
    insert_grant(two_tenants, granted_by=USER_B)
    with two_tenants.cursor() as cur:
        cur.execute("SELECT count(*) FROM sch_identity.elevated_grants")
        assert scalar(cur) == 1
    two_tenants.rollback()


# ── column-scoped grants ────────────────────────────────────────────────────


def test_the_application_cannot_move_a_user_between_tenants(
    two_tenants: psycopg.Connection,
) -> None:
    """A blanket UPDATE on users would allow changing tenant_id, which is a
    cross-tenant move disguised as an edit. The grant is column-scoped so the
    column simply is not writable."""
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(
            "UPDATE sch_identity.users SET tenant_id = %s WHERE user_id = %s",
            (TENANT_B, USER_A),
        )
    two_tenants.rollback()


def test_the_application_can_still_change_a_password(two_tenants: psycopg.Connection) -> None:
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur:
        cur.execute(
            "UPDATE sch_identity.users SET password_hash = %s WHERE user_id = %s",
            ("scrypt$n=16384,r=8,p=1$c2FsdA==$bmV3", USER_A),
        )
        assert cur.rowcount == 1
    two_tenants.rollback()


def test_a_session_token_is_stored_only_as_a_digest(two_tenants: psycopg.Connection) -> None:
    """A leaked dump must not yield usable sessions. The column is char(64)
    constrained to hex, so a raw token does not fit in it."""
    as_tenant(two_tenants, TENANT_A)
    with two_tenants.cursor() as cur, pytest.raises(psycopg.errors.Error):
        cur.execute(
            "INSERT INTO sch_identity.sessions "
            "(session_id, tenant_id, user_id, token_sha256, expires_at) "
            "VALUES (%s, %s, %s, %s, now() + interval '1 hour')",
            (uuid.uuid4(), TENANT_A, USER_A, "a-raw-looking-session-token-not-a-digest"),
        )
    two_tenants.rollback()
