"""Database fixtures for the isolation suite.

These tests need a real PostgreSQL. RLS cannot be tested against a fake — the
whole point is that the *database* refuses the read, not that application code
remembers to filter. A fake that filtered correctly would prove nothing about
production.

`make test` stays infrastructure-free: without ASIP_TEST_DB_URL these skip.
`make test-isolation` fails loudly when it is unset, because a security suite
that silently skips is worse than no suite at all.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any
from uuid import UUID

import psycopg
import pytest

from asip.entrypoints.migrate import migrate_up

TENANT_A = UUID("aaaaaaaa-0000-0000-0000-000000000001")
TENANT_B = UUID("bbbbbbbb-0000-0000-0000-000000000002")


def _dsn() -> str:
    dsn = os.environ.get("ASIP_TEST_DB_URL")
    if not dsn:
        pytest.skip("ASIP_TEST_DB_URL not set — isolation suite needs a real database")
    return dsn


@pytest.fixture(scope="session")
def migrated_db() -> Iterator[str]:
    """A database with every migration applied."""
    dsn = _dsn()
    with psycopg.connect(dsn) as conn:
        migrate_up(conn)
        conn.commit()
    yield dsn


@pytest.fixture
def conn(migrated_db: str) -> Iterator[psycopg.Connection]:
    """A connection with no tenant set.

    Deliberately unset rather than defaulted: the first thing worth proving is
    that a connection which forgot to identify its tenant sees nothing, rather
    than seeing everything.
    """
    with psycopg.connect(migrated_db) as connection:
        yield connection
        connection.rollback()


def scalar(cur: psycopg.Cursor) -> Any:
    """First column of the next row, asserting there is one.

    `fetchone()` is legitimately Optional, and these tests always expect a row —
    aggregate queries and catalogue lookups. Failing the assertion is the right
    outcome if one is ever missing; silencing the type with an ignore would hide
    a query that returned nothing.
    """
    row = cur.fetchone()
    assert row is not None, "expected a row, got none"
    return row[0]


def as_tenant(connection: psycopg.Connection, tenant_id: UUID) -> None:
    """Adopt a tenant for the rest of the transaction.

    Mirrors what the connection pool does per request. SET LOCAL so the setting
    cannot leak into the next user of a pooled connection — a leaked tenant GUC
    would be a cross-tenant read that no policy could catch.
    """
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE asip_app")
        cur.execute("SELECT set_config('asip.tenant_id', %s, true)", (str(tenant_id),))
